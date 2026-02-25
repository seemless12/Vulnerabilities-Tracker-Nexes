from pymongo import MongoClient
from bson import ObjectId
import os

CONNECTION_STRING = os.environ["MONGODB_URI"]
client = MongoClient(CONNECTION_STRING)
db = client['nexes']
users_collection = db["users"]
assets_collection = db["assets"]
vulnerabilities_collection = db["vulnerabilities"]

print("Connected to MongoDB successfully!")