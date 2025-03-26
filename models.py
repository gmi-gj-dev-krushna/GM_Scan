from pydantic import BaseModel, EmailStr, Field, validator
from bson import ObjectId
from typing import Optional, Literal, Any, Dict
from datetime import datetime, timedelta

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    email: Optional[str] = None
    password: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    mobile_number: Optional[str] = None

class UserResponse(UserBase):
    id: str
    email: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    auth_provider: Optional[str] = None
    access_token: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int = Field(
        default_factory=lambda: int(timedelta(hours=1).total_seconds())
    )

class ResetPasswordRequest(BaseModel):
    otp: str
    new_password: str
    confirm_password: str

class LoginRequest(BaseModel):
    email: EmailStr
    password: str

# Document Models (rest of the code remains the same)
class Document(BaseModel):
    id: Optional[str] = "_id"
    user_id: Optional[str] = None
    document_name: str
    is_favorite: Optional[bool] = False
    scan_type: Literal["id", "business", "book", "document"]
    is_favorite: Optional[bool] = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    # ID Card fields
    name: Optional[str] = None
    profession: Optional[str] = None
    email: Optional[EmailStr] = None
    mobile_number: Optional[str] = None
    address: Optional[str] = None
    
    # Business Card additional fields
    company_name: Optional[str] = None
    website: Optional[str] = None
    
    # Book fields
    isbn_no: Optional[int] = None
    book_name: Optional[str] = None
    author_name: Optional[str] = None
    publication: Optional[str] = None
    number_of_pages: Optional[int] = None
    subject: Optional[str] = None
    
    # General Document fields
    summary: Optional[str] = None
    
    model_config = {
        "populate_by_name": True,
        "arbitrary_types_allowed": True,
        "json_encoders": {ObjectId: str, datetime: lambda dt: dt.isoformat()},
    }

class DocumentCreate(Document):
    @validator("user_id")
    def user_id_must_not_be_none(cls, v):
        if v is None:
            raise ValueError("user_id is required")
        return v

class DocumentUpdate(BaseModel):
    document_name: Optional[str] = None
    scan_type: Optional[Literal["id", "business", "book", "document"]] = None
    is_favorite: Optional[bool] = None
    # ID Card fields
    name: Optional[str] = None
    profession: Optional[str] = None
    email: Optional[EmailStr] = None
    mobile_number: Optional[str] = None
    address: Optional[str] = None
    
    # Business Card additional fields
    company_name: Optional[str] = None
    website: Optional[str] = None
    
    # Book fields
    isbn_no: Optional[int] = None
    book_name: Optional[str] = None
    author_name: Optional[str] = None
    publication: Optional[str] = None
    number_of_pages: Optional[int] = None
    subject: Optional[str] = None
    
    # General Document fields
    summary: Optional[str] = None

class DocumentResponse(Document):
    @classmethod
    def from_mongo(cls, document: Dict[str, Any]):
        """Convert MongoDB document to Pydantic model"""
        doc_dict = {k: v for k, v in document.items()}
        if "_id" in doc_dict:
            doc_dict["id"] = str(doc_dict.pop("_id"))
        
        # Convert datetime strings to datetime objects if needed
        if "created_at" in doc_dict and isinstance(doc_dict["created_at"], str):
            doc_dict["created_at"] = datetime.fromisoformat(doc_dict["created_at"])
        if "updated_at" in doc_dict and isinstance(doc_dict["updated_at"], str):
            doc_dict["updated_at"] = datetime.fromisoformat(doc_dict["updated_at"])
        
        return cls(**doc_dict)