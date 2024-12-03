from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from pymongo import MongoClient
from gridfs import GridFS
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
import io
import os
import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv
from functools import wraps
load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}})
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

mongo_uri = os.getenv('MONGO_URI')
client = MongoClient(mongo_uri)
db = client['fileDB']
fs = GridFS(db)
users_collection = db['users']
shared_files_collection = db['shared_files']

def generate_token(username):
    return jwt.encode(
        {'username': username, 'exp': datetime.utcnow() + timedelta(days=1)},
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )

def token_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token không hợp lệ"}), 401
        try:
            token = token.split()[1]
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user = decoded_token['username']
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token hết hạn"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token không hợp lệ"}), 401
        return f(*args, **kwargs)
    return wrap

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    fullname = data.get('fullname')

    if not username or not password or not fullname:
        return jsonify({"error": "Thiếu thông tin"}), 400

    if users_collection.find_one({"username": username}):
        return jsonify({"error": "Tên đăng nhập đã tồn tại"}), 400

    hashed_password = generate_password_hash(password)
    users_collection.insert_one({
        "username": username,
        "password": hashed_password,
        "fullname": fullname,
        "files": []
    })
    token = generate_token(username)
    return jsonify({"message": "Đăng ký thành công", "token": token}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Thiếu thông tin"}), 400

    user = users_collection.find_one({"username": username})
    if user and check_password_hash(user['password'], password):
        token = generate_token(username)
        return jsonify({
            "message": "Đăng nhập thành công",
            "token": token,
            "user": {"username": username, "fullname": user['fullname']}
        }), 200
    return jsonify({"error": "Thông tin đăng nhập không đúng"}), 401

@app.route('/files', methods=['GET'])
@token_required
def get_user_files():
    username = request.user
    user = users_collection.find_one({"username": username})
    if user:
        files_info = []
        for file_id in user['files']:
            try:
                file = fs.get(ObjectId(file_id))
                files_info.append({
                    "filename": file.filename,
                    "file_size": len(file.read()),
                    "upload_date": file.uploadDate,
                    "file_id": str(file._id)
                })
            except Exception as e:
                continue
        return jsonify({"files": files_info}), 200
    return jsonify({"error": "Người dùng không tồn tại"}), 404

@app.route('/upload', methods=['POST'])
@token_required
def upload_file():
    username = request.user

    if 'file' not in request.files:
        return jsonify({"error": "Không có file nào được chọn"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "Không có file nào được chọn"}), 400

    file_id = fs.put(file, filename=file.filename)
    users_collection.update_one({"username": username}, {"$push": {"files": str(file_id)}})

    return jsonify({"message": "Tải lên thành công", "file_id": str(file_id)}), 200

@app.route('/download/<file_id>', methods=['GET'])
def download_file(file_id):
    try:
        file = fs.get(ObjectId(file_id))
        return send_file(io.BytesIO(file.read()), as_attachment=True, download_name=file.filename)
    except Exception as e:
        return jsonify({"error": "Tệp không tồn tại"}), 404

@app.route('/shared/files', methods=['GET'])
@token_required
def get_shared_files():
    username = request.user
    shared_files = shared_files_collection.find({"to_user": username})
    result = []
    for shared in shared_files:
        try:
            file = fs.get(ObjectId(shared['file_id']))
            download_link = f"{request.host_url}download/{str(file._id)}"  
            result.append({
                "filename": file.filename,
                "file_size": len(file.read()),
                "shared_by": shared['from_user'],
                "file_id": str(file._id),
                "download_link": download_link  
            })
        except:
            continue
    return jsonify({"shared_files": result}), 200


@app.route('/friend/share', methods=['POST'])
@token_required
def share_file_with_user():
    data = request.json
    from_user = request.user
    to_user = data.get('to_user')
    file_id = data.get('file_id')

    if not to_user or not users_collection.find_one({"username": to_user}):
        return jsonify({"error": "Người nhận không tồn tại"}), 400

    try:
       
        fs.get(ObjectId(file_id))
    except Exception:
        return jsonify({"error": "Tệp tin không hợp lệ"}), 400

    
    shared_files_collection.insert_one({
        "from_user": from_user,
        "to_user": to_user,
        "file_id": file_id
    })
    to_user_data = users_collection.find_one({"username": to_user})
    if to_user_data:
        if file_id not in to_user_data['files']:
            users_collection.update_one({"username": to_user}, {"$push": {"files": file_id}})

    return jsonify({"message": "Đã chia sẻ tệp tin thành công"}), 200

@app.route('/user', methods=['GET', 'PUT'])
@token_required
def manage_user_info():
    username = request.user
    if request.method == 'GET':
        user = users_collection.find_one({"username": username})
        if user:
            return jsonify({
                "username": user['username'],
                "fullname": user.get('fullname'),
                "avatar": user.get('avatar'),
                "files": user['files']
            }), 200
        return jsonify({"error": "Người dùng không tồn tại"}), 404

    if request.method == 'PUT':
        data = request.json
        updates = {}
        if data.get('fullname'):
            updates['fullname'] = data['fullname']
        if data.get('avatar'):
            updates['avatar'] = data['avatar']
        if data.get('password'):
            updates['password'] = generate_password_hash(data['password'])

        users_collection.update_one({"username": username}, {"$set": updates})
        return jsonify({"message": "Cập nhật thông tin thành công"}), 200

if __name__ == '__main__':
    app.run(debug=True)
