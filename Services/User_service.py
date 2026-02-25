from DB import users_collection
from bson import ObjectId
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# CREATE USER
def create_user(user_data):
    hashed_password = pwd_context.hash(user_data["password"])
    user_data["password"] = hashed_password

    result = users_collection.insert_one(user_data)
    return str(result.inserted_id)


# AUTHENTICATE USER (for login)
def authenticate_user(email, password):
    user = users_collection.find_one({"email": email})

    if not user:
        return None

    if not pwd_context.verify(password, user["password"]):
        return None

    return user


# GET USER BY ID
def get_user_by_id(user_id):
    user = users_collection.find_one({"_id": ObjectId(user_id)})

    if not user:
        return None

    user["_id"] = str(user["_id"])
    user.pop("password", None)

    return user
