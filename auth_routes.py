import random
from bson import ObjectId
from fastapi import APIRouter, HTTPException, Request, status, Depends, Header
from fastapi.responses import RedirectResponse
from models import UserCreate, LoginRequest, ResetPasswordRequest
from database import users_collection
from auth_utils import generate_access_token, hash_password, generate_temp_password, send_email, generate_oauth_state, get_current_user
import config
import requests
import httpx
from urllib.parse import quote, urlencode
from typing import Optional, Dict, Union

router = APIRouter()

# Basic authentication routes
@router.post("/register", response_model=Dict[str, Union[str, Dict[str, str]]])
async def register_user(user: UserCreate):
    existing_user = await users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed_password = hash_password(user.password)
    user_data = {
        "email": user.email,
        "password": hashed_password,
        "first_name": user.first_name,
        "last_name": user.last_name
    }

    result = await users_collection.insert_one(user_data)
    user_id = str(result.inserted_id)

    # Generate access token
    access_token = generate_access_token({
        "sub": user_id,
        "email": user.email
    })

    return {
        "access_token": access_token,
        "user": {
            "id": user_id,
            "first_name": user.first_name,
            "last_name": user.last_name,
            "email": user.email
        }
    }
    
@router.put("/profiles", response_model=Dict[str, Union[str, Dict[str, str]]])
async def update_profile(
    update_data: UserCreate,
    current_user: dict = Depends(get_current_user)
):
    try:
        # Extract user ID from the current user
        user_id = current_user['id']
        
        # Prepare update fields dynamically
        update_fields = {}
        
        # Only add fields that are not None to the update
        if update_data.first_name is not None:
            update_fields["first_name"] = update_data.first_name
        
        if update_data.last_name is not None:
            update_fields["last_name"] = update_data.last_name
        
        if update_data.email is not None:
            update_fields["email"] = update_data.email
        
        if update_data.mobile_number is not None:
            update_fields["mobile_number"] = update_data.mobile_number
        
        # Check if any fields are being updated
        if not update_fields:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="No update fields provided"
            )
        
        # Update user in database
        result = await users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$set": update_fields}
        )
        
        if result.modified_count == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, 
                detail="No changes made to profile"
            )
        
        # Fetch updated user
        updated_user = await users_collection.find_one(
            {"_id": ObjectId(user_id)}
        )
        
        return {
            "message": "User profile details Updated Successfully",
            "user": {
                "id": str(updated_user["_id"]),
                "first_name": updated_user.get("first_name"),
                "last_name": updated_user.get("last_name"),
                "email": updated_user.get("email"),
                "mobile_number": updated_user.get("mobile_number")
            }
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
            detail=f"An error occurred during profile update: {str(e)}"
        )

@router.post("/login", response_model=Dict[str, Union[str, Dict[str, str]]])
async def login_user(login_data: LoginRequest):
    existing_user = await users_collection.find_one({"email": login_data.email})
    if not existing_user:
        raise HTTPException(status_code=400, detail="Invalid email or password")

    hashed_password = hash_password(login_data.password)
    if hashed_password != existing_user["password"]:
        raise HTTPException(status_code=400, detail="Invalid email or password")

    # Generate access token
    access_token = generate_access_token({
        "sub": str(existing_user["_id"]),
        "email": existing_user["email"]
    })

    return {
        "access_token": access_token,
        "user": {
            "id": str(existing_user["_id"]),
            "first_name": existing_user.get("first_name"),
            "last_name": existing_user.get("last_name"),
            "email": existing_user["email"]
        }
    }

@router.post("/forgot-password")
async def forgot_password(email: str):
    existing_user = await users_collection.find_one({"email": email})
    if not existing_user:
        raise HTTPException(status_code=400, detail="Email not found")
 
    # Generate temporary password (OTP)
    temp_password = generate_temp_password()
    hashed_temp_password = hash_password(temp_password)
    
    # Store hashed temporary password
    await users_collection.update_one(
        {"email": email}, 
        {"$set": {"temp_password": hashed_temp_password}}
    )
 
    # Send temporary password via email
    send_email(email, temp_password)
    
    return {"message": "Temporary password sent to your email"}

@router.post("/reset-password")
async def reset_password(reset_data: ResetPasswordRequest):
    # Verify the passwords match
    if reset_data.new_password != reset_data.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")
    
    # Find user with the OTP
    hashed_otp = hash_password(reset_data.otp)
    existing_user = await users_collection.find_one({"temp_password": hashed_otp})
    
    if not existing_user:
        raise HTTPException(status_code=400, detail="Invalid OTP")
 
    # Hash and update the new password
    hashed_new_password = hash_password(reset_data.new_password)
    await users_collection.update_one(
        {"_id": existing_user["_id"]}, 
        {
            "$set": {"password": hashed_new_password},
            "$unset": {"temp_password": ""}  # Remove temp_password field after use
        }
    )
 
    return {"message": "Password reset successfully"}

# Google OAuth routes
@router.get("/google")
async def auth_google(request: Request):
    # Generate state and store in session
    state = generate_oauth_state()
    request.session["google_oauth_state"] = state
    
    params = {
        "response_type": "code",
        "client_id": config.GOOGLE_CLIENT_ID,
        "redirect_uri": config.GOOGLE_REDIRECT_URI,
        "scope": " ".join(config.GOOGLE_SCOPES),
        "state": state,
        "access_type": "offline",
        "prompt": "consent",
    }
    google_auth_url = f"https://accounts.google.com/o/oauth2/auth?{urlencode(params)}"
    return RedirectResponse(url=google_auth_url)

@router.get("/google/callback")
async def auth_google_callback(request: Request, code: str, state: Optional[str] = None):
    # Verify state to prevent CSRF
    stored_state = request.session.get("google_oauth_state")
    if not stored_state or stored_state != state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid state parameter"
        )

    try:
        token_url = "https://oauth2.googleapis.com/token"
        data = {
            "code": code,
            "client_id": config.GOOGLE_CLIENT_ID,
            "client_secret": config.GOOGLE_CLIENT_SECRET,
            "redirect_uri": config.GOOGLE_REDIRECT_URI,
            "grant_type": "authorization_code",
        }
        response = requests.post(token_url, data=data)
        token_data = response.json()
        access_token = token_data.get("access_token")

        if not access_token:
            raise HTTPException(
                status_code=400, detail="Failed to retrieve access token"
            )

        user_info_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        headers = {"Authorization": f"Bearer {access_token}"}
        user_info_response = requests.get(user_info_url, headers=headers)
        user_info = user_info_response.json()

        email = user_info.get("email")
        first_name = user_info.get("given_name", "")
        last_name = user_info.get("family_name", "")

        if not email:
            raise HTTPException(
                status_code=400, detail="Failed to retrieve user email"
            )

        existing_user = await users_collection.find_one({"email": email})

        if not existing_user:
            # Generate a random password for OAuth users
            hashed_password = hash_password(str(random.randint(100000, 999999)))

            user_data = {
                "email": email,
                "first_name": first_name,
                "last_name": last_name,
                "password": hashed_password,
                "auth_provider": "google"
            }

            result = await users_collection.insert_one(user_data)
            user_id = str(result.inserted_id)
        else:
            # Update existing user with latest info
            await users_collection.update_one(
                {"email": email},
                {"$set": {
                    "first_name": first_name,
                    "last_name": last_name,
                    "auth_provider": "google"
                }}
            )
            user_id = str(existing_user["_id"])

        # Generate access token
        access_token = generate_access_token({
            "sub": user_id,
            "email": email
        })

        # Store user in session
        request.session["user"] = {
            "id": user_id,
            "email": email,
            "first_name": first_name,
            "last_name": last_name,
            "auth_provider": "google"
        }

        return {
            "access_token": access_token,
            "user": {
                "id": user_id,
                "email": email,
                "first_name": first_name,
                "last_name": last_name
            }
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(e)
        )

# LinkedIn OAuth routes
@router.get("/linkedin")
async def auth_linkedin(request: Request):
    # Generate random state for CSRF protection
    state = generate_oauth_state()
    request.session["linkedin_oauth_state"] = state
    
    # URL encode the redirect URI
    redirect_uri = quote(config.LINKEDIN_REDIRECT_URI)
    
    # Use OpenID Connect scopes
    auth_url = f"{config.LINKEDIN_AUTH_URL}?response_type=code&client_id={config.LINKEDIN_CLIENT_ID}&redirect_uri={redirect_uri}&state={state}&scope=openid%20profile%20email"
    
    return RedirectResponse(auth_url)

@router.get("/linkedin/callback")
async def linkedin_callback(request: Request, code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None, error_description: Optional[str] = None):
    # Check if there was an error from LinkedIn
    if error:
        error_msg = f"LinkedIn OAuth error: {error}"
        if error_description:
            error_msg += f" - {error_description}"
            
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg
        )
    
    # Ensure we received all required parameters
    if not code or not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required parameters (code or state)"
        )
    
    # Verify state to prevent CSRF attacks
    stored_state = request.session.get("linkedin_oauth_state")
    if not stored_state or stored_state != state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid state parameter"
        )
    
    # Exchange authorization code for access token
    token_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": config.LINKEDIN_REDIRECT_URI,
        "client_id": config.LINKEDIN_CLIENT_ID,
        "client_secret": config.LINKEDIN_CLIENT_SECRET,
    }
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            # Get access token
            token_response = await client.post(
                config.LINKEDIN_TOKEN_URL,
                data=token_data,
                headers=headers
            )
            
            token_response.raise_for_status()
            token_info = token_response.json()
            oauth_access_token = token_info["access_token"]
            
            # Get user info from OpenID Connect userinfo endpoint
            user_response = await client.get(
                config.LINKEDIN_USER_INFO_URL,
                headers={"Authorization": f"Bearer {oauth_access_token}"}
            )
            
            user_response.raise_for_status()
            user_data = user_response.json()
            
            # Extract user information from OpenID Connect format
            user_id = user_data.get("sub", "")
            email = user_data.get("email", "")
            given_name = user_data.get("given_name", "")
            family_name = user_data.get("family_name", "")
            
            if not email:
                raise HTTPException(
                    status_code=400, detail="Failed to retrieve user email"
                )
                
            # Check if user exists
            existing_user = await users_collection.find_one({"email": email})
            
            if not existing_user:
                # Generate a random password for OAuth users
                hashed_password = hash_password(str(random.randint(100000, 999999)))
                
                # Prepare user data for DB
                linkedin_user_data = {
                    "email": email,
                    "first_name": given_name,
                    "last_name": family_name,
                    "password": hashed_password,
                    "linkedin_id": user_id,
                    "auth_provider": "linkedin"
                }
                
                # Save to MongoDB
                result = await users_collection.insert_one(linkedin_user_data)
                user_id = str(result.inserted_id)
            else:
                # Update user data with LinkedIn info
                await users_collection.update_one(
                    {"email": email},
                    {"$set": {
                        "first_name": given_name,
                        "last_name": family_name,
                        "linkedin_id": user_id,
                        "auth_provider": "linkedin"
                    }}
                )
                user_id = str(existing_user["_id"])
            
            # Generate application access token
            access_token = generate_access_token({
                "sub": user_id,
                "email": email
            })
            
            # Store user in session
            request.session["user"] = {
                "id": user_id,
                "email": email, 
                "first_name": given_name,
                "last_name": family_name,
                "auth_provider": "linkedin"
            }
            
            # Return user data and token
            return {
                "access_token": access_token,
                "user": {
                    "id": user_id,
                    "first_name": given_name,
                    "last_name": family_name,
                    "email": email
                }
            }
    
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"LinkedIn API error: {e.response.text}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred: {str(e)}"
        )
        

@router.get("/facebook")
async def auth_facebook(request: Request):
    # Generate random state for CSRF protection
    state = generate_oauth_state()
    request.session["facebook_oauth_state"] = state
    
    # Construct Facebook OAuth URL
    params = {
        "client_id": config.FACEBOOK_APP_ID,
        "redirect_uri": config.FACEBOOK_REDIRECT_URI,
        "state": state,
        "scope": "email,public_profile"
    }
    facebook_auth_url = f"https://www.facebook.com/v12.0/dialog/oauth?{urlencode(params)}"
    
    return RedirectResponse(url=facebook_auth_url)

@router.get("/facebook/callback")
async def facebook_callback(request: Request, code: Optional[str] = None, state: Optional[str] = None, error: Optional[str] = None, error_description: Optional[str] = None):
    # Check for OAuth errors
    if error:
        error_msg = f"Facebook OAuth error: {error}"
        if error_description:
            error_msg += f" - {error_description}"
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_msg
        )
    
    # Validate required parameters
    if not code or not state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required parameters (code or state)"
        )
    
    # Verify state to prevent CSRF attacks
    stored_state = request.session.get("facebook_oauth_state")
    if not stored_state or stored_state != state:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid state parameter"
        )
    
    try:
        # Exchange authorization code for access token
        token_url = f"https://graph.facebook.com/v12.0/oauth/access_token"
        token_params = {
            "client_id": config.FACEBOOK_APP_ID,
            "client_secret": config.FACEBOOK_APP_SECRET,
            "redirect_uri": config.FACEBOOK_REDIRECT_URI,
            "code": code
        }
        
        async with httpx.AsyncClient() as client:
            # Get access token
            token_response = await client.get(token_url, params=token_params)
            token_response.raise_for_status()
            token_data = token_response.json()
            access_token = token_data["access_token"]
            
            # Get user profile information
            user_info_url = "https://graph.facebook.com/me"
            user_params = {
                "fields": "id,email,first_name,last_name,picture",
                "access_token": access_token
            }
            
            user_response = await client.get(user_info_url, params=user_params)
            user_response.raise_for_status()
            user_data = user_response.json()
            
            # Extract user information
            facebook_id = user_data.get("id", "")
            email = user_data.get("email", "")
            first_name = user_data.get("first_name", "")
            last_name = user_data.get("last_name", "")
            profile_picture = user_data.get("picture", {}).get("data", {}).get("url", "")
            
            if not email:
                raise HTTPException(
                    status_code=400, detail="Failed to retrieve user email"
                )
            
            # Check if user exists
            existing_user = await users_collection.find_one({"email": email})
            
            if not existing_user:
                # Generate a random password for OAuth users
                hashed_password = hash_password(str(random.randint(100000, 999999)))
                
                # Prepare user data for DB
                facebook_user_data = {
                    "email": email,
                    "first_name": first_name,
                    "last_name": last_name,
                    "password": hashed_password,
                    "facebook_id": facebook_id,
                    "profile_picture": profile_picture,
                    "auth_provider": "facebook"
                }
                
                # Save to MongoDB
                result = await users_collection.insert_one(facebook_user_data)
                user_id = str(result.inserted_id)
            else:
                # Update user data with Facebook info
                await users_collection.update_one(
                    {"email": email},
                    {"$set": {
                        "first_name": first_name,
                        "last_name": last_name,
                        "facebook_id": facebook_id,
                        "profile_picture": profile_picture,
                        "auth_provider": "facebook"
                    }}
                )
                user_id = str(existing_user["_id"])
            
            # Store user in session
            request.session["user"] = {
                "id": user_id,
                "email": email, 
                "first_name": first_name,
                "last_name": last_name,
                "profile_picture": profile_picture,
                "auth_provider": "facebook"
            }
            
            # Return user data (updated response)
            return {
                "access_token": access_token,
                "user": {
                    "id": user_id,
                    "first_name": first_name,
                    "last_name": last_name,
                    "email": email,
                    "profile_picture": profile_picture
                }
            }
    
    except httpx.HTTPStatusError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Facebook API error: {e.response.text}"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An error occurred: {str(e)}"
        )