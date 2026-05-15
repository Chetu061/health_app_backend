from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
import psycopg2
import jwt
import os
from functools import wraps
from google import genai
from werkzeug.utils import secure_filename
import time
from datetime import date,datetime,timedelta

app = Flask(__name__)

SECRET_KEY = "mysecretkey"
GEMINI_MODEL = os.environ.get("GEMINI_MODEL", "gemini-2.5-flash")


def get_env_value(name):
    env_file = os.path.join(os.path.dirname(__file__), ".env")

    if os.path.exists(env_file):
        with open(env_file, "r") as file:
            for line in file:
                key, sep, value = line.strip().partition("=")
                if sep and key == name:
                    return value.strip().strip('"').strip("'")

    return None


def get_gemini_api_key():
    return (
        os.environ.get("GEMINI_API_KEY")
        or get_env_value("GEMINI_API_KEY")
        or request.headers.get("X-Gemini-API-Key")
        or request.headers.get("X-Gemini-Key")
    )

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        # Get token from header
        auth_header = request.headers.get("Authorization")

        if auth_header and "Bearer" in auth_header:
            token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"error": "Token is missing"}), 401

        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            request.user_id = data["user_id"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expired"}), 401
        except Exception:
            return jsonify({"error": "Invalid token"}), 401

        return f(*args, **kwargs)

    return decorated

# 🔥 Database connection function (IMPORTANT FOR RENDER)
def get_db_connection():
    db_url = os.environ.get("DATABASE_URL") or get_env_value("DATABASE_URL")

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


def ensure_profile_columns(conn):
    cursor = conn.cursor()

    try:
        cursor.execute("""
            ALTER TABLE users
            ADD COLUMN IF NOT EXISTS role VARCHAR(100),
            ADD COLUMN IF NOT EXISTS age INTEGER,
            ADD COLUMN IF NOT EXISTS height NUMERIC,
            ADD COLUMN IF NOT EXISTS weight NUMERIC,
            ADD COLUMN IF NOT EXISTS goal VARCHAR(100),
            ADD COLUMN IF NOT EXISTS profile_photo VARCHAR(500),
            ADD COLUMN IF NOT EXISTS updated_at TIMESTAMP DEFAULT NOW()
        """)
        conn.commit()
    finally:
        cursor.close()


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
                "exp": datetime.utcnow() + timedelta(hours=1)
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
#updateprofile API
# =========================
@app.route("/api/update-profile", methods=["POST"])
@token_required
def update_profile():
    conn = get_db_connection()
    ensure_profile_columns(conn)
    cursor = conn.cursor()

    try:
        data = request.get_json()
        user_id = request.user_id 
        role = data.get("role")
        age = data.get("age")
        height = data.get("height")
        weight = data.get("weight")
        goal = data.get("goal")


        cursor.execute("""
            UPDATE users
            SET role=%s, age=%s, height=%s, weight=%s, goal=%s, updated_at=NOW()
            WHERE id=%s
            RETURNING id, role, age, height, weight, goal, updated_at
        """, (role, age, height, weight, goal, user_id))

        updated_user = cursor.fetchone()

        if not updated_user:
            conn.rollback()
            return jsonify({"error": "User not found"}), 404

        conn.commit()

        return jsonify({
            "message": "Profile updated successfully",
            "data": {
                "id": updated_user[0],
                "role": updated_user[1],
                "age": updated_user[2],
                "height": float(updated_user[3]) if updated_user[3] is not None else None,
                "weight": float(updated_user[4]) if updated_user[4] is not None else None,
                "goal": updated_user[5],
                "updated_at": updated_user[6].isoformat() if updated_user[6] else None
            }
        })

    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

    finally:
        cursor.close()
        conn.close()


# =========================
# health score API
# =========================
@app.route("/api/health-score", methods=["POST"])
@token_required
def health_score():
    try:
        
        conn = get_db_connection()
        cursor = conn.cursor()
        user_id = request.user_id 
     

        # Fetch user data
        cursor.execute("""
            SELECT age, height, weight, goal, activity_level
            FROM users
            WHERE id = %s
        """, (user_id,))

        user = cursor.fetchone()
        cursor.close()

        if not user:
            return jsonify({"error": "User not found"}), 404

        age, height, weight, goal, activity_level = user

        if not height or not weight:
            return jsonify({"error": "Height and weight required"}), 400

        # 🧠 BMI Calculation
        height_m = height / 100
        bmi = weight / (height_m ** 2)

        score = 0
        tips = []

        # 🔹 BMI Score (40)
        if 18.5 <= bmi <= 24.9:
            bmi_score = 40
            bmi_status = "Normal"
        elif bmi < 18.5:
            bmi_score = 25
            bmi_status = "Underweight"
            tips.append("Increase healthy calorie intake")
        else:
            bmi_score = 25
            bmi_status = "Overweight"
            tips.append("Focus on weight loss with exercise")

        score += bmi_score

        # 🔹 Activity Score (20)
        if activity_level == "High":
            activity_score = 20
        elif activity_level == "Medium":
            activity_score = 15
            tips.append("Try to increase daily activity")
        else:
            activity_score = 10
            tips.append("Add walking or light exercise")

        score += activity_score

        # 🔹 Age-based Score (10)
        if age and age < 30:
            age_score = 10
        elif age and age < 50:
            age_score = 8
        else:
            age_score = 6
            tips.append("Focus more on regular health checkups")

        score += age_score

        # 🔹 Goal-based Score (10)
        if goal == "Weight Loss" and bmi > 25:
            goal_score = 10
        elif goal == "Maintain" and 18.5 <= bmi <= 24.9:
            goal_score = 10
        elif goal == "Energy Gain":
            goal_score = 8
        else:
            goal_score = 5
            tips.append("Adjust your goal or lifestyle")

        score += goal_score

        # 🔹 Hydration Score (10 - assumed)
        hydration_score = 8
        tips.append("Drink 2-3 liters of water daily")
        score += hydration_score

        # 🔹 Sleep Score (10 - assumed)
        sleep_score = 8
        tips.append("Sleep at least 7-8 hours")
        score += sleep_score

        # Final score cap
        if score > 100:
            score = 100

        return jsonify({
            "score": int(score),
            "bmi": round(bmi, 2),
            "bmi_status": bmi_status,
            "breakdown": {
                "bmi": bmi_score,
                "activity": activity_score,
                "age": age_score,
                "goal": goal_score,
                "hydration": hydration_score,
                "sleep": sleep_score
            },
            "tips": tips
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =========================
# Daily Mission API
# =========================
@app.route("/api/daily-mission", methods=["GET"])
@token_required
def daily_mission():
    try:
        user_id = request.user_id

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT role, height, weight, goal
            FROM users
            WHERE id = %s
        """, (user_id,))

        user = cursor.fetchone()
        cursor.close()
        conn.close()

        if not user:
            return jsonify({"error": "User not found"}), 404

        role, height, weight, goal = user

        if not height or not weight:
            return jsonify({"error": "Complete profile first"}), 400

        # BMI
        height_m = height / 100
        bmi = weight / (height_m ** 2)

        missions = []

        # 🔹 Common missions
        missions.append({
            "task": "Drink 2-3 liters of water",
            "priority": "High"
        })

        missions.append({
            "task": "Sleep at least 7-8 hours",
            "priority": "High"
        })

        # 🔹 Role-based missions
        if role == "Working Woman":
            missions.append({
                "task": "Take a 5-min walk every 2 hours",
                "priority": "Medium"
            })
            missions.append({
                "task": "Avoid long sitting (stretch break)",
                "priority": "Medium"
            })

        elif role == "Housewife":
            missions.append({
                "task": "Do 20 mins home workout/yoga",
                "priority": "High"
            })
            missions.append({
                "task": "Avoid skipping meals",
                "priority": "Medium"
            })

        # 🔹 BMI-based missions
        if bmi > 25:
            missions.append({
                "task": "Walk 7000+ steps today",
                "priority": "High"
            })
            missions.append({
                "task": "Avoid sugar & fried food",
                "priority": "High"
            })

        elif bmi < 18.5:
            missions.append({
                "task": "Eat high-calorie healthy meals",
                "priority": "High"
            })
            missions.append({
                "task": "Add protein-rich foods",
                "priority": "High"
            })

        else:
            missions.append({
                "task": "Maintain balanced diet",
                "priority": "Medium"
            })

        # 🔹 Goal-based missions
        if goal == "Weight Loss":
            missions.append({
                "task": "Do 30 mins cardio",
                "priority": "High"
            })

        elif goal == "Energy Gain":
            missions.append({
                "task": "Include fruits & dry fruits",
                "priority": "Medium"
            })

        # 🎯 Completion target
        total_tasks = len(missions)

        return jsonify({
            "total_tasks": total_tasks,
            "missions": missions
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# =========================
# MEAL PLAN AI API
# =========================
# @app.route("/api/meal-plan", methods=["POST"])
# @token_required
# def meal_plan():
#     try:
#         data = request.get_json()
#         user_input = data.get("message")

#         if not user_input:
#             return jsonify({"error": "message is required"}), 400

#         api_key = get_gemini_api_key()
#         if not api_key:
#             return jsonify({"error": "GEMINI_API_KEY is required"}), 500

#         client = genai.Client(api_key=api_key)
#         prompt = (
#             (
#                 "You are a professional health and nutrition assistant. "
#                 "Give simple, clear, practical answers. Focus on Indian diet when possible. "
#                 "Avoid medical diagnosis. Suggest healthy meals, workouts, and habits. "
#                 "Keep the response short and structured. If the user asks diet, give "
#                 "breakfast/lunch/dinner plan. If user asks fitness, give daily routine."
#             )
#             + "\n\nUser message:\n"
#             + user_input
#         )

#         response = client.models.generate_content(
#             model=GEMINI_MODEL,
#             contents=prompt
#         )

#         return jsonify({"reply": response.text})

#     except Exception as e:
#         return jsonify({"error": str(e)}), 500

def shorten(text, max_words=5):
    return " ".join(text.split()[:max_words])
@app.route("/api/meal-plan", methods=["POST"])
@token_required
def meal_plan():
    try:
        data = request.get_json()
        user_input = data.get("message")

        if not user_input:
            return jsonify({"error": "message is required"}), 400

        api_key = get_gemini_api_key()
        if not api_key:
            return jsonify({"error": "GEMINI_API_KEY is required"}), 500

        client = genai.Client(api_key=api_key)

        # 🔥 SHORT + STRUCTURED PROMPT
        prompt = (
            "You are a health assistant.\n"
            "Respond ONLY in JSON.\n"
            "Keep answers VERY SHORT (max 3-5 words).\n"
            "No explanation.\n\n"

            "{\n"
            '  "meal_plan": [\n'
            '    {"meal": "Breakfast", "food": ""},\n'
            '    {"meal": "Lunch", "food": ""},\n'
            '    {"meal": "Dinner", "food": ""}\n'
            "  ],\n"
            '  "workout": [\n'
            '    {"type": "", "duration": ""}\n'
            "  ],\n"
            '  "timing": {\n'
            '    "breakfast": "",\n'
            '    "lunch": "",\n'
            '    "dinner": "",\n'
            '    "sleep": ""\n'
            "  }\n"
            "}\n\n"

            "Example:\n"
            '{"meal_plan":[{"meal":"Breakfast","food":"Poha"},{"meal":"Lunch","food":"Dal Rice"},{"meal":"Dinner","food":"Khichdi"}],"workout":[{"type":"Walk","duration":"20 min"}],"timing":{"breakfast":"8 AM","lunch":"1 PM","dinner":"8 PM","sleep":"10 PM"}}\n\n'

            "User:\n" + user_input
        )

        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=prompt
        )

        raw_text = response.text.strip()

        # 🧹 Clean markdown if exists
        if raw_text.startswith("```"):
            raw_text = raw_text.replace("```json", "").replace("```", "").strip()

        try:
            ai_data = json.loads(raw_text)

            # 🔥 SHORTEN TEXT (extra safety)
            for meal in ai_data.get("meal_plan", []):
                meal["food"] = shorten(meal.get("food", ""))

            for w in ai_data.get("workout", []):
                w["type"] = shorten(w.get("type", ""))
                w["duration"] = shorten(w.get("duration", ""))

            for key in ai_data.get("timing", {}):
                ai_data["timing"][key] = shorten(ai_data["timing"][key])

            return jsonify(ai_data)

        except Exception:
            # fallback if AI fails
            return jsonify({
                "meal_plan": [
                    {"meal": "Breakfast", "food": "Poha"},
                    {"meal": "Lunch", "food": "Dal Rice"},
                    {"meal": "Dinner", "food": "Khichdi"}
                ],
                "workout": [
                    {"type": "Walk", "duration": "20 min"}
                ],
                "timing": {
                    "breakfast": "8 AM",
                    "lunch": "1 PM",
                    "dinner": "8 PM",
                    "sleep": "10 PM"
                }
            })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =========================
# GET PROFILE API
# =========================
@app.route("/api/profile", methods=["GET"])
@token_required
def get_profile():
    conn = get_db_connection()
    ensure_profile_columns(conn)
    cursor = conn.cursor()

    try:
        user_id = request.user_id

        cursor.execute("""
            SELECT role, age, height, weight, goal, profile_photo
            FROM users
            WHERE id = %s
        """, (user_id,))

        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "User not found"}), 404

        role, age, height, weight, goal, profile_photo = user

        return jsonify({
            "role": role,
            "age": age,
            "height": float(height) if height is not None else None,
            "weight": float(weight) if weight is not None else None,
            "goal": goal,
            "profile_photo": request.host_url + "uploads/" + profile_photo.replace("\\", "/") if profile_photo else None
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

    finally:
        cursor.close()
        conn.close()


# =========================
# profile photo API
# =========================
@app.route('/api/upload-photo', methods=['POST'])
@token_required
def upload_photo():
    try:
        conn = get_db_connection()
        ensure_profile_columns(conn)
        conn.close()

        file = request.files.get('photo')

        if not file:
            return jsonify({"error": "No file uploaded"}), 400

        # ✅ validate file type
        if not file.filename.lower().endswith(('.png', '.jpg', '.jpeg')):
            return jsonify({"error": "Invalid file type"}), 400

        filename = secure_filename(file.filename)

        # ✅ unique filename
        import time
        filename = str(int(time.time())) + "_" + filename

        upload_folder = "uploads"

        # ✅ create folder if not exists
        if not os.path.exists(upload_folder):
            os.makedirs(upload_folder)

        path = os.path.join(upload_folder, filename)
        file.save(path)

        user_id = request.user_id

        conn = get_db_connection()
        cursor = conn.cursor()

        # ✅ check user exists
        cursor.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()

        if not user:
            cursor.close()
            conn.close()
            return jsonify({"error": "User not found"}), 404

        # 🔴 FIX: store ONLY filename (not full path)
        cursor.execute(
            "UPDATE users SET profile_photo = %s WHERE id = %s",
            (filename, user_id)
        )

        conn.commit()
        cursor.close()
        conn.close()

        # 🔴 FIX: dynamic URL (works everywhere)
        photo_url = request.host_url + "uploads/" + filename

        return jsonify({
            "message": "Photo uploaded",
            "photo_url": photo_url
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =========================
# GET STREAK  API
# =========================
def update_streak(user_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT streak, last_active FROM users WHERE id = %s",
        (user_id,)
    )
    result = cursor.fetchone()

    if not result:
        cursor.close()
        conn.close()
        return 0

    streak, last_active = result
    today = date.today()

    if last_active is None:
        streak = 1

    elif last_active == today:
        cursor.close()
        conn.close()
        return streak

    elif last_active == today - timedelta(days=1):
        streak += 1

    else:
        streak = 1

    cursor.execute(
        "UPDATE users SET streak = %s, last_active = %s WHERE id = %s",
        (streak, today, user_id)
    )

    conn.commit()
    cursor.close()
    conn.close()

    return streak

@app.route('/api/update-streak', methods=['POST'])
@token_required
def update_streak_api():
    try:
        user_id = request.user_id

        streak = update_streak(user_id)

        return jsonify({
            "message": "Streak updated",
            "streak": streak
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
# =========================
# GET habit check  API
# =========================
@app.route('/api/habit-check', methods=['POST'])
@token_required
def habit_check():
    try:
        data = request.get_json()
        habit_name = data.get("habit_name")
        status = data.get("status", True)

        if not habit_name:
            return jsonify({"error": "habit_name required"}), 400

        user_id = request.user_id

        conn = get_db_connection()
        cursor = conn.cursor()

        # ✅ insert habit
        cursor.execute("""
            INSERT INTO habits (user_id, habit_name, status)
            VALUES (%s, %s, %s)
        """, (user_id, habit_name, status))

        conn.commit()
        cursor.close()
        conn.close()

        # 🔥 update streak
        streak = update_streak(user_id)

        return jsonify({
            "message": "Habit recorded",
            "streak": streak
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
        
# =========================
# Habbit History API
# =========================
@app.route('/api/habit-history', methods=['GET'])
@token_required
def habit_history():
    try:
        user_id = request.user_id

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT habit_name, status, created_at
            FROM habits
            WHERE user_id = %s
            ORDER BY created_at DESC
        """, (user_id,))

        rows = cursor.fetchall()

        result = []
        for r in rows:
            result.append({
                "habit": r[0],
                "status": r[1],
                "date": r[2]
            })

        cursor.close()
        conn.close()

        return jsonify({"history": result})

    except Exception as e:
        return jsonify({"error": str(e)}), 500
# =========================
# water intake  API
# =========================
@app.route('/api/water-intake', methods=['POST'])
@token_required
def water_intake():
    try:
        user_id = request.user_id

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            UPDATE users 
            SET last_water_time = NOW()
            WHERE id = %s
        """, (user_id,))

        conn.commit()
        cursor.close()
        conn.close()

        return jsonify({"message": "Water intake recorded"})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =========================
# CHECK ALERTS API
# =========================
@app.route('/api/check-alerts', methods=['GET'])
@token_required
def check_alerts():
    try:
        user_id = request.user_id

        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("""
            SELECT last_water_time FROM users WHERE id = %s
        """, (user_id,))

        row = cursor.fetchone()
        alerts = []

        if row and row[0]:
            last_time = row[0]

            if datetime.now() - last_time > timedelta(hours=4):
                alerts.append("You haven’t drunk water in 4 hours")

        cursor.close()
        conn.close()

        return jsonify({"alerts": alerts})

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# =========================
# GET Logout API
# =========================
@app.route('/api/logout', methods=['POST'])
@token_required  
def logout():
    user_id = request.user_id 
    return jsonify({"message": "Logout successful"})


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
