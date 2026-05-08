from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import jwt
import datetime
import os

app = Flask(__name__)

SECRET_KEY = "mysecretkey"


# 🔥 Database connection function (IMPORTANT FOR RENDER)
def get_db_connection():
    db_url = os.environ.get("DATABASE_URL")

    if db_url:
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql://", 1)

        return psycopg2.connect(db_url)

    # fallback local DB (for development only)
    return psycopg2.connect(
        host="localhost",
        database="health_db",
        user="postgres",
        password="123456",
        port="5432"
    )


# =========================
# REGISTER API
# =========================
@app.route("/api/register", methods=["POST"])
def register():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        data = request.get_json()

        name = data.get("name")
        email = data.get("email")
        password = data.get("password")

        if not name or not email or not password:
            return jsonify({"error": "All fields required"}), 400

        # Check duplicate email
        cursor.execute("SELECT id FROM users WHERE email=%s", (email,))
        if cursor.fetchone():
            return jsonify({"error": "Email already exists"}), 400

        hashed_password = generate_password_hash(password)

        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
            (name, email, hashed_password)
        )

        conn.commit()

        return jsonify({"message": "User registered successfully"})

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

    finally:
        cursor.close()
        conn.close()


# =========================
# LOGIN API
# =========================
@app.route("/api/login", methods=["POST"])
def login():
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        data = request.get_json()

        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400

        cursor.execute(
            "SELECT id, name, email, password FROM users WHERE email=%s",
            (email,)
        )

        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "User not found"}), 404

        if not check_password_hash(user[3], password):
            return jsonify({"error": "Invalid password"}), 401

        token = jwt.encode(
            {
                "user_id": user[0],
                "email": user[2],
                "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)
            },
            SECRET_KEY,
            algorithm="HS256"
        )

        return jsonify({
            "message": "Login successful",
            "token": token,
            "data": {
                "id": user[0],
                "name": user[1],
                "email": user[2]
            }
        })

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

    finally:
        cursor.close()
        conn.close()


# =========================
# TEST ROUTE
# =========================
@app.route("/", methods=["GET"])
def home():
    return jsonify({"message": "Flask API is running"})


# =========================
# RUN APP
# =========================
if __name__ == "__main__":
    app.run()