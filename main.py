import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
import secrets
import json
from bson import ObjectId
from fastapi.responses import JSONResponse
from typing import Any
import os
from dotenv import load_dotenv
from auth_routes import router as auth_router
from document_routes import app as document_router

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(title="Authentication and Document API")

# Generate a secure secret key for sessions
SESSION_SECRET_KEY = os.getenv("SESSION_SECRET_KEY", secrets.token_hex(32))

# Add session middleware for OAuth state and user sessions
app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET_KEY,
    max_age=3600  # 1 hour session
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Set this to specific domains in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Custom JSON encoder for MongoDB ObjectId
class MongoJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        return super().default(obj)

# Custom response class for MongoDB ObjectId serialization
class MongoJSONResponse(JSONResponse):
    def render(self, content: Any) -> bytes:
        return json.dumps(
            content,
            ensure_ascii=False,
            allow_nan=False,
            indent=None,
            separators=(",", ":"),
            cls=MongoJSONEncoder,
        ).encode("utf-8")

# Override default JSONResponse with custom response class
app.router.default_response_class = MongoJSONResponse

# Include auth routes
app.include_router(auth_router, prefix="/auth", tags=["authentication"])
app.include_router(document_router, prefix="/api/documents", tags=["documents"])


@app.get("/")
def root():
    return {
        "message": "Authentication and Document API. Use /auth and /api/documents endpoints."
    }


@app.get("/profile")
async def profile(request: Request):
    # Check if user is logged in
    user = request.session.get("user")
    if not user:
        return {"message": "Not logged in", "authenticated": False}
    
    return {
        "message": "You are logged in!",
        "user": user,
        "authenticated": True
    }

@app.get("/logout")
async def logout(request: Request):
    request.session.pop("user", None)
    request.session.pop("google_oauth_state", None)
    request.session.pop("linkedin_oauth_state", None)
    request.session.pop("facebook_oauth_state", None)
    return {"message": "Logged out successfully"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)