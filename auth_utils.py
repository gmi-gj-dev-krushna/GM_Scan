import hashlib
import random
import smtplib
import os
import secrets
from email.mime.text import MIMEText
from config import SMTP_SERVER, SMTP_PORT, SECRET_KEY
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from fastapi import HTTPException, status, Header

# Updated import for PyJWT
import jwt

# Function to hash passwords
def hash_password(password: str) -> str:
    """
    Hash password using SHA-256 with a salt
    """
    salt = os.getenv("PASSWORD_SALT", "default_salt")
    return hashlib.sha256((password + salt).encode()).hexdigest()

# Function to generate a 4-digit temporary password/OTP
def generate_temp_password() -> str:
    """
    Generate a 4-digit temporary password/OTP
    """
    return str(random.randint(1000, 9999))

# Function to generate random state for OAuth
def generate_oauth_state() -> str:
    """
    Generate a secure random state for OAuth CSRF protection
    """
    return secrets.token_urlsafe(16)

# Function to send email
def send_email(to_email: str, temp_password: str):
    """
    Send email with temporary password
    """
    sender_email = os.getenv("SMTP_EMAIL")
    sender_password = os.getenv("SMTP_PASSWORD")
    
    if not sender_email or not sender_password:
        # Use fallback if environment variables not set
        sender_email = "gmi.tn.dev.akmarimuthu@gmail.com"
        sender_password = "ragmvkoqvlvvzalr"
    
    msg = MIMEText(f"Your temporary password is: {temp_password}")
    msg["Subject"] = "Password Reset Request"
    msg["From"] = sender_email
    msg["To"] = to_email
    
    with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, to_email, msg.as_string())

# Function to generate OTP with expiration
def generate_otp(email: str, users_collection) -> str:
    """
    Generate a time-limited OTP for the given email
    
    :param email: User's email
    :param users_collection: MongoDB collection for users
    :return: Unencrypted OTP
    """
    # Generate 4-digit OTP
    otp = generate_temp_password()
    
    # Hash the OTP
    hashed_otp = hash_password(otp)
    
    # Set OTP expiration (15 minutes from now)
    expiration = datetime.utcnow() + timedelta(minutes=15)
    
    # Update user document with hashed OTP and expiration
    users_collection.update_one(
        {"email": email},
        {
            "$set": {
                "temp_password": hashed_otp,
                "otp_expiration": expiration
            }
        }
    )
    
    return otp

# Function to verify OTP
def verify_otp(email: str, otp: str, users_collection) -> bool:
    """
    Verify the OTP for a given email
    
    :param email: User's email
    :param otp: OTP to verify
    :param users_collection: MongoDB collection for users
    :return: Boolean indicating OTP validity
    """
    # Find user by email
    user = users_collection.find_one({"email": email})
    
    if not user:
        return False
    
    # Check if OTP exists and is not expired
    if (not user.get("temp_password") or 
        not user.get("otp_expiration") or 
        datetime.utcnow() > user.get("otp_expiration")):
        return False
    
    # Hash the provided OTP
    hashed_otp = hash_password(otp)
    
    # Compare hashed OTPs
    return hashed_otp == user.get("temp_password")

# Updated function to generate access tokens
def generate_access_token(user_data: Dict[str, Any], expires_delta: timedelta = None) -> str:
    """
    Generate a JWT access token
    
    :param user_data: Dictionary containing user information
    :param expires_delta: Optional token expiration time
    :return: JWT access token
    """
    # Create a copy of user data to avoid modifying the original
    to_encode = user_data.copy()
    
    # Set default expiration to 1 day if not specified
    if expires_delta is None:
        expires_delta = timedelta(days=1)
    
    # Calculate expiration time
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    
    # Updated generation method for PyJWT
    return jwt.encode(payload=to_encode, key=SECRET_KEY, algorithm="HS256")

# Updated verify function for PyJWT
def verify_access_token(token: str) -> Dict[str, Any]:
    """
    Verify and decode a JWT access token
    
    :param token: JWT access token
    :return: Decoded token payload
    """
    try:
        return jwt.decode(token, key=SECRET_KEY, algorithms=["HS256"])
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError:
        raise ValueError("Invalid token")
    
    
    
def get_current_user(authorization: Optional[str] = Header(None)):
    """
    Extract and verify user from access token

    :param authorization: Authorization header with Bearer token
    :return: Dictionary with user information
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid access token",
        )

    # Extract and verify token
    token = authorization.split(" ")[1]
    try:
        token_data = verify_access_token(token)
        return {"id": token_data.get("sub"), "email": token_data.get("email")}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))