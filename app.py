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
    def token_decorator_wrap(*args, **kwargs):
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
    return token_decorator_wrap


@app.route('/register', methods=['POST'], endpoint='register')
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


@app.route('/login', methods=['POST'], endpoint='login')
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


@app.route('/user', methods=['GET'], endpoint='get_user_info')
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


@app.route('/user', methods=['PUT'], endpoint='update_user_info')
@token_required
def update_user_info():
    username = request.user
    data = request.json
    fullname = data.get('fullname')
    avatar = data.get('avatar')
    password = data.get('password')

    updates = {}
    if fullname:
        updates['fullname'] = fullname
    if avatar:
        updates['avatar'] = avatar
    if password:
        updates['password'] = generate_password_hash(password)

    users_collection.update_one({"username": username}, {"$set": updates})
    return jsonify({"message": "Cập nhật thông tin thành công"}), 200


@app.route('/user/avatar', methods=['POST'], endpoint='update_avatar')
@token_required
def update_avatar():
    username = request.user

    if 'avatar' not in request.files:
        return jsonify({"error": "No file part"}), 400

    avatar = request.files['avatar']
    if avatar.filename == '':
        return jsonify({"error": "No selected file"}), 400

    avatar_id = fs.put(avatar, filename=avatar.filename)
    users_collection.update_one({"username": username}, {"$set": {"avatar": str(avatar_id)}})

    return jsonify({"message": "Avatar updated successfully", "avatar_id": str(avatar_id)}), 200


@app.route('/user/password', methods=['PUT'], endpoint='change_password')
@token_required
def change_password():
    username = request.user
    data = request.json
    old_password = data.get('old_password')
    new_password = data.get('new_password')

    if not old_password or not new_password:
        return jsonify({"error": "Thiếu thông tin mật khẩu"}), 400

    user = users_collection.find_one({"username": username})
    if not user or not check_password_hash(user['password'], old_password):
        return jsonify({"error": "Mật khẩu cũ không đúng"}), 400

    hashed_password = generate_password_hash(new_password)
    users_collection.update_one({"username": username}, {"$set": {"password": hashed_password}})
    return jsonify({"message": "Mật khẩu đã được thay đổi thành công"}), 200


@app.route('/friend/request', methods=['POST'], endpoint='send_friend_request')
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


@app.route('/friend/accept', methods=['POST'], endpoint='accept_friend_request')
@token_required
def accept_friend_request():
    data = request.json
    username = request.user
    from_user = data.get('from_user')

    friends_collection.update_one({"from_user": from_user, "to_user": username, "status": "pending"}, {"$set": {"status": "accepted"}})
    return jsonify({"message": "Đã chấp nhận lời mời kết bạn"}), 200


@app.route('/friends', methods=['GET'], endpoint='list_friends')
@token_required
def list_friends():
    username = request.user

    friends = friends_collection.find({"$or": [{"from_user": username, "status": "accepted"}, {"to_user": username, "status": "accepted"}]})
    friends_list = [{"friend": f["from_user"] if f["to_user"] == username else f["to_user"]} for f in friends]
    return jsonify({"friends": friends_list}), 200


@app.route('/upload', methods=['POST'], endpoint='upload_file')
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


@app.route('/download/<file_id>', methods=['GET'], endpoint='download_file')
@token_required
def download_file(file_id):
    try:
        file = fs.get(ObjectId(file_id))
        return send_file(io.BytesIO(file.read()), as_attachment=True, download_name=file.filename)
    except Exception as e:
        return jsonify({"error": str(e)}), 404


@app.route('/shared/files', methods=['GET'], endpoint='get_shared_files')
@token_required
def get_shared_files():
    username = request.user

    shared_files = []
    shared_friends = friends_collection.find({"$or": [{"from_user": username, "status": "accepted"}, {"to_user": username, "status": "accepted"}]})
    for friend in shared_friends:
        shared_files += users_collection.find({"username": friend["from_user"] if friend["to_user"] == username else friend["to_user"]})["files"]

    return jsonify({"files": shared_files}), 200

@app.route('/files', methods=['GET'], endpoint='get_user_files')
@token_required
def get_user_files():
    username = request.user
    user = users_collection.find_one({"username": username})
    if user:
        files = user['files']
        return jsonify({"files": files}), 200
    return jsonify({"error": "Người dùng không tồn tại"}), 404


if __name__ == '__main__':
    app.run(debug=True)
