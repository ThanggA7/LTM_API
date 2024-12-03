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

# Cấu hình CORS, cho phép frontend trên localhost:5173 truy cập
CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}})
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY')

mongo_uri = os.getenv('MONGO_URI')
client = MongoClient(mongo_uri)
db = client['fileDB']
fs = GridFS(db)  # Quản lý file
users_collection = db['users']
friends_collection = db['friends']

def generate_random_avatar(name):
    return f"https://api.dicebear.com/6.x/initials/svg?seed={name}"

def generate_token(username):
    return jwt.encode(
        {'username': username, 'exp': datetime.utcnow() + timedelta(days=1)},
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )

# Middleware để xác thực token
def token_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"error": "Token không hợp lệ"}), 401
        try:
            token = token.split()[1]
            decoded_token = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            request.user = decoded_token['username']  # Gán thông tin người dùng vào request
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
    avatar = generate_random_avatar(fullname)
    users_collection.insert_one({
        "username": username,
        "password": hashed_password,
        "fullname": fullname,
        "avatar": avatar,
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
            "user": {
                "username": username,
                "fullname": user['fullname'],
                "avatar": user['avatar']
            }
        }), 200
    return jsonify({"error": "Thông tin đăng nhập không đúng"}), 401

@app.route('/user', methods=['GET'])
@token_required
def get_user_info():
    username = request.user
    user = users_collection.find_one({"username": username})
    if user:
        return jsonify({
            "username": user['username'],
            "fullname": user['fullname'],
            "avatar": user['avatar'],
            "files": user['files']
        }), 200
    return jsonify({"error": "Người dùng không tồn tại"}), 404

@app.route('/files', methods=['GET'])
@token_required
def get_user_files():
    username = request.user
    user = users_collection.find_one({"username": username})
    if user:
        files_info = []
        for file_id in user['files']:
            file = fs.get(ObjectId(file_id))
            files_info.append({
                "filename": file.filename,
                "file_size": len(file.read()),
                "upload_date": file.uploadDate,
                "file_id": str(file._id)
            })
        return jsonify({"files": files_info}), 200
    return jsonify({"error": "Người dùng không tồn tại"}), 404

@app.route('/friends', methods=['GET'])
@token_required
def list_friends():
    username = request.user
    friends = friends_collection.find({"$or": [{"from_user": username, "status": "accepted"}, {"to_user": username, "status": "accepted"}]})
    friends_list = []
    for f in friends:
        friend_username = f["from_user"] if f["to_user"] == username else f["to_user"]
        friend_user = users_collection.find_one({"username": friend_username})
        if friend_user:
            friends_list.append({
                "username": friend_user["username"],
                "fullname": friend_user["fullname"],
                "avatar": friend_user["avatar"]
            })
    return jsonify({"friends": friends_list}), 200

@app.route('/friend/request', methods=['POST'])
@token_required
def send_friend_request():
    data = request.json
    from_user = request.user
    to_user = data.get('to_user')

    if not to_user or not users_collection.find_one({"username": to_user}):
        return jsonify({"error": "Người dùng không tồn tại"}), 400

    if friends_collection.find_one({"from_user": from_user, "to_user": to_user, "status": "pending"}):
        return jsonify({"error": "Đã gửi lời mời kết bạn"}), 400

    friends_collection.insert_one({"from_user": from_user, "to_user": to_user, "status": "pending"})
    return jsonify({"message": "Đã gửi lời mời kết bạn"}), 200

@app.route('/friend/accept', methods=['POST'])
@token_required
def accept_friend_request():
    data = request.json
    username = request.user
    from_user = data.get('from_user')

    friends_collection.update_one({"from_user": from_user, "to_user": username, "status": "pending"}, {"$set": {"status": "accepted"}})
    return jsonify({"message": "Đã chấp nhận lời mời kết bạn"}), 200

@app.route('/upload', methods=['POST'])
@token_required
def upload_file():
    username = request.user

    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    file_id = fs.put(file, filename=file.filename)
    users_collection.update_one({"username": username}, {"$push": {"files": str(file_id)}})

    return jsonify({"message": "File uploaded successfully", "file_id": str(file_id)}), 200

@app.route('/download/<file_id>', methods=['GET'])
@token_required
def download_file(file_id):
    try:
        file = fs.get(ObjectId(file_id))
        return send_file(io.BytesIO(file.read()), as_attachment=True, download_name=file.filename)
    except Exception as e:
        return jsonify({"error": str(e)}), 404

@app.route('/friend/requests', methods=['GET'])
@token_required
def get_friend_requests():
    username = request.user

    friend_requests = friends_collection.find({
        "$or": [
            {"from_user": username, "status": "pending"},
            {"to_user": username, "status": "pending"}
        ]
    })

    requests_list = []
    for request in friend_requests:
        if request['from_user'] == username:
            requests_list.append({
                "from_user": request['from_user'],
                "to_user": request['to_user'],
                "status": request['status']
            })
        else:
            requests_list.append({
                "from_user": request['from_user'],
                "to_user": request['to_user'],
                "status": request['status']
            })

    return jsonify({"requests": requests_list}), 200

@app.route('/shared/files', methods=['GET'])
@token_required
def get_shared_files():
    username = request.user

    shared_files = []
    shared_friends = friends_collection.find({"$or": [{"from_user": username, "status": "accepted"}, {"to_user": username, "status": "accepted"}]})

    for friend in shared_friends:
        friend_username = friend["from_user"] if friend["to_user"] == username else friend["to_user"]
        user = users_collection.find_one({"username": friend_username})
        if user:
            for file_id in user['files']:
                file = fs.get(ObjectId(file_id))
                shared_files.append({
                    "filename": file.filename,
                    "file_size": len(file.read()),
                    "upload_date": file.uploadDate,
                    "file_id": str(file._id),
                    "shared_by": user["username"]
                })
    
    return jsonify({"shared_files": shared_files}), 200


@app.route('/friend/share', methods=['POST'])
@token_required
def share_file_with_friend():
    data = request.json
    from_user = request.user
    to_user = data.get('to_user')
    file_id = data.get('file_id')

    # Kiểm tra người dùng và bạn bè
    if not to_user or not users_collection.find_one({"username": to_user}):
        return jsonify({"error": "Người nhận không tồn tại"}), 400

    # Kiểm tra xem người nhận có phải là bạn bè đã chấp nhận hay không
    friend_relationship = friends_collection.find_one({
        "$or": [
            {"from_user": from_user, "to_user": to_user, "status": "accepted"},
            {"from_user": to_user, "to_user": from_user, "status": "accepted"}
        ]
    })

    if not friend_relationship:
        return jsonify({"error": "Không thể chia sẻ với người này vì họ không phải là bạn bè"}), 400

    try:
        file = fs.get(ObjectId(file_id))
    except Exception as e:
        return jsonify({"error": "Tệp tin không hợp lệ"}), 400

    users_collection.update_one({"username": to_user}, {"$push": {"files": file_id}})

    return jsonify({"message": "Đã chia sẻ tệp tin thành công"}), 200


if __name__ == '__main__':
    app.run(debug=True)
