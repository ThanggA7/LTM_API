from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from pymongo import MongoClient
from gridfs import GridFS
from bson import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
import io
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}})

mongo_uri = os.getenv('MONGO_URI')  
client = MongoClient(mongo_uri)  
db = client['fileDB']  
fs = GridFS(db)  
users_collection = db['users']

@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Thiếu tên đăng nhập hoặc mật khẩu"}), 400

    if users_collection.find_one({"username": username}):
        return jsonify({"error": "Tên đăng nhập đã tồn tại"}), 400

    hashed_password = generate_password_hash(password)
    users_collection.insert_one({"username": username, "password": hashed_password})
    return jsonify({"message": "Đăng ký thành công"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({"error": "Thiếu tên đăng nhập hoặc mật khẩu"}), 400

    user = users_collection.find_one({"username": username})
    if user and check_password_hash(user['password'], password):
        return jsonify({"message": "Đăng nhập thành công"}), 200
    return jsonify({"error": "Tên đăng nhập hoặc mật khẩu không đúng"}), 401

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    file_id = fs.put(file, filename=file.filename)
    return jsonify({"message": "File uploaded successfully", "file_id": str(file_id)}), 200

@app.route('/download/<file_id>', methods=['GET'])
def download_file(file_id):
    try:
        file = fs.get(ObjectId(file_id))
        return send_file(io.BytesIO(file.read()), as_attachment=True, download_name=file.filename)
    except Exception as e:
        return jsonify({"error": str(e)}), 404

@app.route('/files', methods=['GET'])
def list_files():
    try:
        files = fs.find()
        file_list = []
        for file in files:
            file_list.append({
                "file_id": str(file._id),
                "filename": file.filename,
                "file_size": f"{(file.length / 1024 / 1024):.2f} MB",  
                "upload_date": file.upload_date.strftime('%Y-%m-%d %H:%M:%S')
            })
        
        return jsonify({"files": file_list}), 200
    except Exception as e:
        return jsonify({"error": f"Failed to retrieve files: {str(e)}"}), 500
    
@app.route('/delete/<file_id>', methods=['DELETE'])
def delete_file(file_id):
    try:
        fs.delete(ObjectId(file_id))
        return jsonify({"message": "File deleted successfully"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    app.run(debug=True)
