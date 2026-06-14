import os
from flask import Flask, render_template, request, jsonify, redirect, url_for, session
from dotenv import load_dotenv
from database import init_db, register_user, get_user, save_scan, get_history, get_scan_by_id
from analyzer import analyze_with_gemini, check_url_virustotal, translate_to_tamil, generate_voice_alert

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "fraudguard-secret-123")


    

init_db()

def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

@app.route("/")
def home():
    if 'user_id' in session:
        return redirect(url_for('index'))
    return redirect(url_for('login'))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        if "@" not in email:
            error = "Email must contain @"
        elif len(password) < 4:
            error = "Password too short"
        else:
            user = get_user(email, password)
            if user:
                session['user_id'] = user[0]
                session['user_email'] = user[1]
                return redirect(url_for('index'))
            else:
                error = "Invalid email or password"

    return render_template("login.html", error=error)

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None
    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "").strip()

        if "@" not in email:
            error = "Email must contain @"
        elif len(password) < 4:
            error = "Password must be at least 4 characters"
        else:
            ok = register_user(email, password)
            if ok:
                success = "Account created! Please login."
            else:
                error = "Email already registered"

    return render_template("register.html", error=error, success=success)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route("/dashboard")
@login_required
def index():
    return render_template("index.html", email=session.get('user_email'))

@app.route("/analyze", methods=["POST"])
@login_required
def analyze():
    data = request.get_json()
    input_text = data.get("text", "").strip()
    input_type = data.get("type", "message")

    if not input_text:
        return jsonify({"error": "No text provided"}), 400

    result = analyze_with_gemini(input_text, input_type)

    vt_result = None
    if input_type == "link":
        vt_result = check_url_virustotal(input_text)
        if vt_result and vt_result["is_dangerous"]:
            result["risk_score"] = min(100, result["risk_score"] + 20)
            result["verdict"] = "SCAM"
            result["red_flags"].append(f"VirusTotal: {vt_result['malicious_count']} engines flagged this URL")

    tamil_explanation = translate_to_tamil(result["explanation"])

    audio_file = None
    if result["risk_score"] >= 50:
        voice_text = f"Warning! {result['explanation']} {result['safety_advice']}"
        audio_filename = f"alert_{hash(input_text) % 100000}.mp3"
        generate_voice_alert(voice_text, audio_filename)
        audio_file = f"/static/audio/{audio_filename}"

    save_scan(
        user_id=session['user_id'],
        input_text=input_text,
        input_type=input_type,
        risk_score=result["risk_score"],
        verdict=result["verdict"],
        explanation=result["explanation"],
        explanation_tamil=tamil_explanation
    )

    return jsonify({
        "risk_score": result["risk_score"],
        "verdict": result["verdict"],
        "explanation": result["explanation"],
        "explanation_tamil": tamil_explanation,
        "scam_type": result.get("scam_type", ""),
        "red_flags": result.get("red_flags", []),
        "safety_advice": result.get("safety_advice", ""),
        "audio_file": audio_file,
        "virustotal": vt_result
    })

@app.route("/history")
@login_required
def history():
    scans = get_history(session['user_id'])
    return render_template("history.html", scans=scans, email=session.get('user_email'))

@app.route("/result/<int:scan_id>")
@login_required
def result(scan_id):
    scan = get_scan_by_id(scan_id)
    if not scan:
        return redirect(url_for('index'))
    return render_template("result.html", scan=scan)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, host="0.0.0.0", port=port)