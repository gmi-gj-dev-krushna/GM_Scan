import os
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from dotenv import load_dotenv

load_dotenv()

# Database connection settings
MONGODB_URL = os.getenv("MONGODB_URL")
DB_NAME = os.getenv("DB_NAME")


class Database:
    def __init__(self):
        self.client = AsyncIOMotorClient(MONGODB_URL)
        self.db = self.client[DB_NAME]
        self.users_collection = self.db["users"]
        self.documents_collection = self.db["documents"]

    def get_users_collection(self):
        return self.users_collection

    def get_documents_collection(self):
        return self.documents_collection


# Singleton instance
db_instance = Database()

# Explicitly define collections
users_collection = db_instance.get_users_collection()
documents_collection = db_instance.get_documents_collection()


def get_db() -> AsyncIOMotorDatabase:
    return db_instance.db  # Return the database instance
