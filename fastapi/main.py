from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pymongo import MongoClient
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
import bcrypt
import jwt
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi import File, UploadFile, Form
import os
import csv
import shutil
from bson.objectid import ObjectId
from redis.asyncio import Redis
import uuid 

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = MongoClient("mongodb://localhost:27017/")
db = client["csv_management"]
collection_name = "authorized_user"
collection = db[collection_name]

SECRET_KEY = "abi"
ALGORITHM = "HS256"

redis = Redis(host="localhost", port=6379, db=0)

async def jwt_token(email: str, role: str) -> str:
    token_data = {
        "email": email,
        "role": role,
        "exp": datetime.utcnow() + timedelta(minutes=60)
    }
    token = jwt.encode(token_data, SECRET_KEY, algorithm=ALGORITHM)
    token_key = str(uuid.uuid4())

    await redis.setex(token_key, timedelta(minutes=60), token)

    return token_key  

security = HTTPBearer()

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> dict:
    token_key = credentials.credentials
    try:
        
        token = await redis.get(token_key)
        if token is None:
            raise HTTPException(status_code=401, detail="Invalid token")

        decoded_token = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return decoded_token

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    
@app.get("/get_list")
async def get_list(token_data: str = Depends(verify_token)):
    try:
        role = token_data.get("role")
        email = token_data.get("email")
        COLLECTION_NAME = "fileInfo"
        collection = db[COLLECTION_NAME]

        if role == "admin":
            files = list(collection.find({}))
        else:
            files = list(collection.find({"email": email}))
 
        for file in files:
            file["_id"] = str(file["_id"])
        return files
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))    

@app.post("/get_user_role")
async def get_user_role(token_data: dict = Depends(verify_token)):
   
    return {"role": token_data.get("role")}


class UserLogin(BaseModel):
    email: str
    password: str
@app.post("/login")
async def login_user(user: UserLogin):
    try:
        existing_user = collection.find_one({"email": user.email})
        
        if existing_user and bcrypt.checkpw(user.password.encode('utf-8'), existing_user['password']):
            user_role = existing_user.get('role')
            
            if user_role is None:
                raise HTTPException(status_code=500, detail="Role not found for user")
            
            token = await jwt_token(user.email, user_role)  
            return {"message": "Login successful", "token": token}
        
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Server error: {str(e)}")



@app.get("/usersList")
async def get_users(token_data: str = Depends(verify_token)):
    try:
        COLLECTION_NAME = "authorized_user" 
        collection = db[COLLECTION_NAME]
        users = list(collection.find({}))    
        for user in users:
            user["_id"] = str(user["_id"])

        return {"users": users}
    except Exception as e:
       
        raise HTTPException(status_code=500, detail=str(e))



class UserRegistration(BaseModel):
    email: str
    password: str
    role:str

@app.post("/register")
async def register_user(user: UserRegistration):
    # Check if user already exists
    existing_user = collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=409, detail="User already exists")

    
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
   # encode -to convert byts format & gensalt - generate random sequences
   
    user_data = {
        "email": user.email,
        "password": hashed_password,
        "role":user.role
    }
    result = collection.insert_one(user_data)
    return {"message": "User registered successfully", "result": str(result.inserted_id)}


class ForgotEmail(BaseModel):
    email: str


@app.post("/forgot")
async def check_email(user: ForgotEmail,token_data: str = Depends(verify_token)):
    existing_user = collection.find_one({"email": user.email})
    if existing_user:
        try:
            user_role = existing_user.get('role')
            
            token =await jwt_token(user.email,user_role)
            await send_password_reset_email(user.email,token)
            return {"message": "Password reset email sent.", "email": user.email,"token":token}
        except Exception as e:
            raise HTTPException(status_code=500, detail="Failed to send password reset email")
    else:
        raise HTTPException(status_code=404, detail="Email not found in database")
    
port = 465
smtp_server = "smtp.gmail.com"
username = "abinayait2001@gmail.com"
password = "iblrwkduerbsdqxf"
sender_email = "abinayait2001@gmail.com"


async def send_password_reset_email(email, token):
    reset_link = f"http://localhost:3000/ConfirmPassword?token={token}"
    html = f"""\
        <html>
        <body>
            <p>Hi,<br>
            You requested a password reset for email: {email}. 
            Click <a href="{reset_link}">here</a> to reset your password.</p>
        </body>
        </html>
        """
    try:
        message = MIMEMultipart("alternative")
        message["Subject"] = "Password Reset Request"
        message["From"] = sender_email
        message["To"] = email

        part = MIMEText(html, "html")
        message.attach(part)

        with smtplib.SMTP_SSL(smtp_server, port) as server:
            server.login(username, password)
            server.sendmail(sender_email, email, message.as_string())

        return {"message": "Password reset email sent successfully"}
    except Exception:
        raise HTTPException(status_code=500, detail="Failed to send password reset email")
    


class PasswordChange(BaseModel):
    newPassword: str
    confirmPassword: str
    token: str

@app.post("/confirmPassword")
async def confirm_password(password_change: PasswordChange,token_data: str = Depends(verify_token)):
    try:
        
        # decoded_token = jwt.decode(password_change.token, SECRET_KEY, algorithms=[ALGORITHM])
        email = token_data["email"]  

        existing_user = collection.find_one({"email": email})
        if not existing_user:
            raise HTTPException(status_code=404, detail="User not found")

        if password_change.newPassword != password_change.confirmPassword:
            raise HTTPException(status_code=400, detail="Passwords do not match")
        
        hashed_password = bcrypt.hashpw(password_change.newPassword.encode('utf-8'), bcrypt.gensalt())

        result = collection.update_one({"email": email}, {"$set": {"password": hashed_password}})
        if result.modified_count == 0:
            raise HTTPException(status_code=500, detail="Failed to update password")

        return {"message": "Password changed successfully"}

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")

    except (jwt.DecodeError, jwt.InvalidTokenError):
        raise HTTPException(status_code=401, detail="Invalid token")

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    

@app.get("/dashboard")
async def get_dashboard(token_data: str = Depends(verify_token)):
    email = token_data.get("email")

    collection_name = db["fileInfo"]
    collections_names = list(collection_name.find({"email": email}, {"collection_name": 1, "_id": 0}))
    collections_count = len(collections_names)

    list_names = list(collection_name.find({"email": email}, {"list_name": 1, "_id": 0}))
    lists_count = len(list_names)
    return {"message": "Welcome to the dashboard", "collections_count": collections_count,"lists_count":lists_count}



upload_directory = "./uploads"
os.makedirs(upload_directory, exist_ok=True)

class FileUploadResponse(BaseModel):
    filename: str
    uploaded_time: datetime

@app.post("/upload/")
async def upload_file(token_data: str = Depends(verify_token),file: UploadFile = File(...), list_name: str = Form(...)):

#async def upload_file(file: UploadFile = File(...), list_name: str = Form(...)):
    # File will contain the uploaded file 
    # Form will contain form data sent as part of the request  
    try:
        email = token_data.get("email")
        if file.filename.endswith(".csv"):
            file_location = os.path.join(upload_directory, file.filename)
           
            with open(file_location, "wb") as file_object:
                shutil.copyfileobj(file.file, file_object)
            
            collection_name = os.path.splitext(file.filename)[0]
            if collection_name in db.list_collection_names():
                raise HTTPException(status_code=400, detail="Collection already exists")

            with open(file_location, "r") as csv_file:
                csv_reader = csv.DictReader(csv_file)
                collection = db[collection_name]
                
                for row in csv_reader:
                    result = collection.insert_one(row)
                    

                uploaded_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                metadata = {
                    "file_name": file.filename,
                    "uploaded_time": uploaded_time,
                    "collection_name": collection_name,
                    "list_name": list_name,
                    "email":email
                }
                meta_collection = db["fileInfo"]
                meta_collection.insert_one(metadata)
                # return JSONResponse(status_code=200, content={"message": "File uploaded and processed successfully"})
                return FileUploadResponse(filename=file.filename, uploaded_time=uploaded_time)
                #return {"file":file_location}
        else:
            raise HTTPException(status_code=400, detail="Only CSV files are allowed")
    except Exception as e:
       
        raise HTTPException(status_code=500, detail="Internal server error")
    

@app.delete("/deleteList")
async def delete_collection(collection_name: str,token_data: str = Depends(verify_token)):
    try:   
        email = token_data.get("email")   
        if collection_name in db.list_collection_names():
            db.drop_collection(collection_name)
        else:
            raise HTTPException(status_code=404, detail="Collection not found")

        result = db["fileInfo"].delete_one({"collection_name": collection_name})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Metadata not found")

        file_path = os.path.join(upload_directory, f"{collection_name}.csv")
        if os.path.exists(file_path):
            os.remove(file_path)
        else:
            print("File not found in uploads directory")

        return {"message": "Collection, metadata deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail="some error coming while deleting the collection")




@app.delete("/deleteUser")
async def delete_user(_id: str,token_data: str = Depends(verify_token)):
    try:
        object_id = ObjectId(_id)
        result = db["authorized_user"].delete_one({"_id": object_id})

        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="User not found")
        
        return {"message": "User deleted successfully"}
    except Exception as e: 
        raise HTTPException(status_code=500, detail="An error occurred while deleting the user")


@app.get("/user/{user_id}")
async def get_user(user_id: str, token_data: dict = Depends(verify_token)):
    try:

        role = token_data.get("role")
        if role != "admin":
            raise HTTPException(status_code=403, detail="Forbidden")
        
        object_id = ObjectId(user_id)
        user = collection.find_one({"_id": object_id})
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        
        user["_id"] = str(user["_id"])
        return user
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    


class UserUpdate(BaseModel):
    email: str
    role: str

@app.put("/editUser/{user_id}")
async def edit_user(user_id: str, user_update: UserUpdate, token_data: dict = Depends(verify_token)):
    try:
        role = token_data.get("role")
        if role != "admin":
            raise HTTPException(status_code=403, detail="Forbidden")

        object_id = ObjectId(user_id)
        update_result = collection.update_one(
            {"_id": object_id},
            {"$set": {"email": user_update.email, "role": user_update.role}}
        )

        if update_result.matched_count == 0:
            raise HTTPException(status_code=404, detail="User not found")

        return {"message": "User updated successfully"}
    
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
class PasswordChange(BaseModel):
    email: EmailStr
    newPassword: str
    confirmPassword: str


@app.post("/changePassword")
async def changePassword(password_change: PasswordChange,token_data: str = Depends(verify_token)):
    try:
        if password_change.newPassword != password_change.confirmPassword:
            raise HTTPException(status_code=400, detail="Passwords do not match")

        hashed_password = bcrypt.hashpw(password_change.newPassword.encode('utf-8'), bcrypt.gensalt())

        result = collection.update_one({"email": password_change.email}, {"$set": {"password": hashed_password}})
        if result.modified_count == 0:
            raise HTTPException(status_code=500, detail="Failed to update password")

        return {"message": "Password changed successfully"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))



@app.get("/get_all_collections")
async def get_all_collections(token_data: str = Depends(verify_token)):
    try:
        file_info_collection = db["fileInfo"]
        collections_info = list(file_info_collection.find({}, {"_id": 0, "collection_name": 1, "list_name": 1}))

        all_data = []
        for collection in collections_info:
            collection_name = collection["collection_name"]
            list_name = collection["list_name"]
            collection_data = list(db[collection_name].find({}))
            for item in collection_data:
                item["_id"] = str(item["_id"])  
            all_data.append({
                "collection_name": collection_name,
                "list_name": list_name,
                "data": collection_data
            })

        return all_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/delete_contact")
async def delete_contact(collection_name: str, id: str,token_data: str = Depends(verify_token)):
    
    try:
        collection = db[collection_name]
        result = collection.delete_one({"_id": ObjectId(id)})
        if result.deleted_count == 0:
            raise HTTPException(status_code=404, detail="Contact not found")
        return {"message": "Contact deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
@app.get("/get_contact")
async def get_contact(id: str, collection_name: str,token_data: str = Depends(verify_token)):
    try:
        collection = db[collection_name]
        contact = collection.find_one({"_id": ObjectId(id)})
        if not contact:
            raise HTTPException(status_code=404, detail="Contact not found")
        contact["_id"] = str(contact["_id"])
        return contact
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/update_contact")
async def update_contact(
    id: str, 
    collection_name: str, 
    employeeName: str = Form(...), 
    Salary: str = Form(...), 
    location: str = Form(...), 
    department: str = Form(...), 
   
):
    try:
        
        object_id = ObjectId(id)
        collection = db[collection_name]
        
        update_result = collection.update_one(
            {"_id": object_id},
            {"$set": {
                "employee_name": employeeName,
                "employee_salary": Salary,
                "employee_location": location,
                "employee_department": department
            }}
        )

        if update_result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Contact not found")

        return {"message": "Contact updated successfully"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/logout")
async def logout_user(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())):
    token_key = credentials.credentials
    try:
       
        await redis.delete(token_key)
        return {"message": "Logged out successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to log out: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=True)