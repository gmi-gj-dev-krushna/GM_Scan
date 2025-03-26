from fastapi import APIRouter, HTTPException, Depends, status, Header
from motor.motor_asyncio import AsyncIOMotorDatabase
from bson import ObjectId
from typing import List
from models import DocumentCreate, DocumentUpdate, DocumentResponse
from database import get_db
from datetime import datetime
from auth_utils import get_current_user

app = APIRouter(tags=["documents"])


@app.post("/", response_model=DocumentResponse, status_code=status.HTTP_201_CREATED)
async def create_document(
    document: DocumentCreate,
    db: AsyncIOMotorDatabase = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Create a new document"""
    # Ensure user_id matches the authenticated user
    document_data = document.model_dump(exclude_unset=True)
    document_data["user_id"] = current_user["id"]

    # Add timestamp fields
    current_time = datetime.utcnow()
    document_data["created_at"] = current_time
    document_data["updated_at"] = current_time

    # Insert into database
    result = await db.documents.insert_one(document_data)

    # Get the newly created document
    created_document = await db.documents.find_one({"_id": result.inserted_id})

    if created_document is None:
        raise HTTPException(status_code=404, detail="Document creation failed")

    # Convert MongoDB document to Pydantic model
    return DocumentResponse.from_mongo(created_document)


@app.get("/", response_model=List[DocumentResponse])
async def read_documents(
    skip: int = 0,
    limit: int = 10,
    db: AsyncIOMotorDatabase = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get all documents for the authenticated user with pagination"""
    # Find documents for the specific user
    documents = (
        await db.documents.find({"user_id": current_user["id"]})
        .skip(skip)
        .limit(limit)
        .to_list(length=limit)
    )

    return [DocumentResponse.from_mongo(doc) for doc in documents]


@app.get("/{document_id}", response_model=DocumentResponse)
async def read_document(
    document_id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get a single document by ID for the authenticated user"""
    if not ObjectId.is_valid(document_id):
        raise HTTPException(status_code=400, detail="Invalid document ID format")

    document = await db.documents.find_one(
        {"_id": ObjectId(document_id), "user_id": current_user["id"]}
    )

    if document is None:
        raise HTTPException(
            status_code=404, detail="Document not found or unauthorized"
        )

    return DocumentResponse.from_mongo(document)


@app.put("/{document_id}", response_model=DocumentResponse)
async def update_document(
    document_id: str,
    document: DocumentUpdate,
    db: AsyncIOMotorDatabase = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Update a document for the authenticated user"""
    if not ObjectId.is_valid(document_id):
        raise HTTPException(status_code=400, detail="Invalid document ID format")

    # Get only set fields (exclude None values)
    update_data = {k: v for k, v in document.model_dump().items() if v is not None}

    if not update_data:
        raise HTTPException(status_code=400, detail="No fields to update")

    # Add updated_at timestamp
    update_data["updated_at"] = datetime.utcnow()

    # Update the document, ensuring it belongs to the authenticated user
    result = await db.documents.update_one(
        {"_id": ObjectId(document_id), "user_id": current_user["id"]},
        {"$set": update_data},
    )

    if result.matched_count == 0:
        raise HTTPException(
            status_code=404, detail="Document not found or unauthorized"
        )

    # Get the updated document
    updated_document = await db.documents.find_one({"_id": ObjectId(document_id)})

    return DocumentResponse.from_mongo(updated_document)


@app.delete("/{document_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_document(
    document_id: str,
    db: AsyncIOMotorDatabase = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Delete a document for the authenticated user"""
    if not ObjectId.is_valid(document_id):
        raise HTTPException(status_code=400, detail="Invalid document ID format")

    # Delete the document, ensuring it belongs to the authenticated user
    result = await db.documents.delete_one(
        {"_id": ObjectId(document_id), "user_id": current_user["id"]}
    )

    if result.deleted_count == 0:
        raise HTTPException(
            status_code=404, detail="Document not found or unauthorized"
        )

    return None


@app.get("/type/{scan_type}", response_model=List[DocumentResponse])
async def get_documents_by_type(
    scan_type: str,
    skip: int = 0,
    limit: int = 10,
    db: AsyncIOMotorDatabase = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Get documents filtered by scan type for the authenticated user"""
    # Validate scan type
    valid_types = ["id", "business", "book", "document"]
    if scan_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid scan type. Must be one of: {', '.join(valid_types)}",
        )

    documents = (
        await db.documents.find({"scan_type": scan_type, "user_id": current_user["id"]})
        .sort([("created_at", -1)])  # Sort by created_at in descending order
        .skip(skip)
        .limit(limit)
        .to_list(length=limit)
    )

    return [DocumentResponse.from_mongo(doc) for doc in documents]


@app.get("/search/", response_model=List[DocumentResponse])
async def search_documents(
    query: str,
    skip: int = 0,
    limit: int = 10,
    db: AsyncIOMotorDatabase = Depends(get_db),
    current_user: dict = Depends(get_current_user),
):
    """Search documents by name or other fields for the authenticated user"""
    # Text search across multiple fields for the authenticated user
    documents = (
        await db.documents.find(
            {
                "user_id": current_user["id"],
                "$or": [
                    {"document_name": {"$regex": query, "$options": "i"}},
                    {"name": {"$regex": query, "$options": "i"}},
                    {"book_name": {"$regex": query, "$options": "i"}},
                    {"author_name": {"$regex": query, "$options": "i"}},
                    {"company_name": {"$regex": query, "$options": "i"}},
                ],
            }
        )
        .skip(skip)
        .limit(limit)
        .to_list(length=limit)
    )

    return [DocumentResponse.from_mongo(doc) for doc in documents]
