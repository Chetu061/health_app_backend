from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import jwt
import datetime
import os
import psycopg2

app = Flask(__name__)

# conn = psycopg2.connect(
#     host="localhost",
#     database="health_db",
#     user="postgres",
#     password="123456",
#     port="5432"
# )

db_url = os.environ.get("DATABASE_URL")

if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)

conn = psycopg2.connect(db_url)

@app.route("/api/register", methods=["POST"])
def register():
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        name = data.get("name")
        email = data.get("email")
        password = data.get("password")

        if not name or not email or not password:
            return jsonify({"error": "All fields required"}), 400

        hashed_password = generate_password_hash(password)

        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
            (name, email, hashed_password)
        )

        conn.commit()

        cursor.close()

        return jsonify({"message": "User registered successfully"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

SECRET_KEY = "mysecretkey"

@app.route("/api/login", methods=["POST"])
def login():
    try:
        data = request.get_json()

        if not data:
            return jsonify({"error": "Invalid JSON"}), 400

        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400

        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, name, email, password FROM users WHERE email=%s",
            (email,)
        )

        user = cursor.fetchone()
        cursor.close()

        if not user:
            return jsonify({"error": "User not found"}), 404

        stored_password = user[3]

        # Check password
        if not check_password_hash(stored_password, password):
            return jsonify({"error": "Invalid password"}), 401

        token = jwt.encode({
            "user_id": user[0],
            "email": user[2],
            "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
        }, SECRET_KEY, algorithm="HS256")

        return jsonify({
    "data": {
        "id": user[0],
        "name": user[1],
        "email": user[2]
    },
    "token": token,
    "message": "Login successful"
})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
if __name__ == "__main__":
    app.run()