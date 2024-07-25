import os
from flask import Flask, request, jsonify, session
from functools import wraps
from dotenv import load_dotenv
from pymongo.mongo_client import MongoClient
from urllib.parse import quote_plus
from werkzeug.security import generate_password_hash, check_password_hash
from pydantic import BaseModel, Field, ValidationError
from datetime import datetime
from typing import Optional
from bson import ObjectId
from typing import List


# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Set secret key for the Flask app 
app.secret_key = os.getenv('SECRET_KEY')

# URL encode the username and password for MongoDB
username = quote_plus(os.getenv('DB_USERNAME'))
password = quote_plus(os.getenv('DB_PASSWORD'))

# Construct the MongoDB URI with encoded username and password
uri = f"mongodb+srv://{username}:{password}@cluster0.xjdjd5a.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

# Create a MongoDB client
client = MongoClient(uri)

# Access the MongoDB database
db = client.flask_db

# Define Pydantic models for validation
class User(BaseModel):
    username: str
    name: str
    email: str
    password: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    groups: List[str] = Field(default_factory=list)

class Group(BaseModel):
    name: str
    user_id: str  # This will store the ObjectId of the user as a string
    files: dict = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)

@app.route("/")
def home():
    return jsonify("hi I am something"),200

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    username = data.get('username')
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    # Validate input data
    if not username or not name or not email or not password:
        return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400

    if db.users.find_one({'email': email}):
        return jsonify({'status': 'error', 'message': 'Email already registered'}), 400

    hashed_password = generate_password_hash(password, method='sha256')
    new_user = User(username=username, name=name, email=email, password=hashed_password)

    try:
        user_id = db.users.insert_one(new_user.dict()).inserted_id
        return jsonify({
            'status': 'success',
            'message': 'User successfully registered!',
            'data': {
                'id': str(user_id),
                'username': new_user.username,
                'name': new_user.name,
                'email': new_user.email,
                'created_at': new_user.created_at.isoformat()
            }
        }), 201
    except ValidationError as e:
        return jsonify({'status': 'error', 'message': f'Validation error: {e.errors()}'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Error! User could not be registered. {str(e)}'}), 500

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'status': 'error', 'message': 'Missing email or password'}), 400

    user = db.users.find_one({'email': email})

    if not user or not check_password_hash(user['password'], password):
        return jsonify({'status': 'error', 'message': 'Invalid email or password'}), 401

    # Store user_id in session
    session['user_id'] = str(user['_id'])

    # Fetch all groups for the user
    groups_list = []
    for group_id in user.get('groups', []):
        group = db.groups.find_one({'_id': ObjectId(group_id)})
        if group:
            groups_list.append({
                'id': str(group['_id']),
                'name': group['name'],
                'files': group.get('files', {})
            })

    return jsonify({
        'status': 'success',
        'message': 'Login successful',
        'user': {
            'username': user['username'],
            'name': user['name'],
        },
        'groups': groups_list
    }), 200

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'status': 'error', 'message': 'Access denied. Please log in.'}), 403
        return f(*args, **kwargs)
    return wrapper

@app.route("/create_group", methods=["POST"])
@login_required
def create_group():
    try:
        data = request.get_json()  
        grp_name = data.get('group_name')
        user_id = session.get('user_id')

        if not grp_name:
            return jsonify({'status': 'error', 'message': 'Missing group_name'}), 400

        if db.groups.find_one({'name': grp_name}):
            return jsonify({'status': 'error', 'message': 'Group already exists'}), 400

        new_group = Group(name=grp_name, user_id=user_id)
        db.groups.insert_one(new_group.dict())
        return jsonify({'status': 'success', 'message': 'Group created successfully'}), 201

    except ValidationError as e:
        return jsonify({'status': 'error', 'message': f'Validation error: {e.errors()}'}), 400
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'An error occurred: {str(e)}'}), 500

@app.route("/groups", methods=["GET"])
# @login_required
def get_all_groups():
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'status': 'error', 'message': 'User not found in session'}), 403

        groups = db.groups.find()
        groups_list = [{'id': str(group['_id']), 'name': group['name'], 'files': group['files']} for group in groups]

        return jsonify({'status': 'success', 'groups': groups_list}), 200
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'An error occurred: {str(e)}'}), 500

@app.route('/add/group/', methods=["POST"])
@login_required
def add_group():
    data = request.get_json()
    group_name = data.get('name')

    if not group_name:
        return jsonify({'status': 'error', 'message': 'Missing group name'}), 400

    # Find the group by name
    group = db.groups.find_one({'name': group_name})

    if not group:
        return jsonify({'status': 'error', 'message': 'Group does not exist'}), 404

    # Retrieve user ID from session
    user_id = session.get('user_id')
    
    # Find the user document
    user = db.users.find_one({'_id': ObjectId(user_id)})

    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404

    # Append the group ID to the user's groups list
    group_id = str(group['_id'])
    if group_id not in user.get('groups', []):
        db.users.update_one(
            {'_id': ObjectId(user_id)},
            {'$push': {'groups': group_id}}
        )
        return jsonify({'status': 'success', 'message': 'Group added to user successfully'}), 200
    else:
        return jsonify({'status': 'error', 'message': 'Group is already added to the user'}), 400



if __name__ == "__main__":
    app.run(debug=True)
