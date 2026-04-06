from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from ..models import User
from ..services.audit_service import log_audit
from ..extensions import db

auth_bp = Blueprint("auth", __name__)

# ✅ Home route
@auth_bp.route("/dashboard")
def home():
    return redirect(url_for("auth.login"))


# ✅ LOGIN (SECURE - uses hash)
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        user = User.query.filter_by(username=username).first()

        # 🔍 DEBUG START
        print("USERNAME:", username)
        print("USER:", user)

        if user:
            print("HASH:", user.password_hash)
            print("PASSWORD CHECK:", user.check_password(password))
        # 🔍 DEBUG END

        if user and user.active and user.check_password(password):
            print("LOGIN SUCCESS")
            login_user(user)
            return redirect(url_for("main.dashboard"))   # 🔥 force redirect

        print("LOGIN FAILED")
        flash("Invalid credentials", "danger")

    return render_template("login.html")


# ✅ LOGOUT
@auth_bp.route("/logout")
@login_required
def logout():
    log_audit("user", current_user.id, "logout", reason_code="AUTH", user_id=current_user.id)
    logout_user()
    return redirect(url_for("auth.login"))


# ✅ REGISTER (CORRECT - uses hashing)
@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash("User already exists", "warning")
            return redirect(url_for("auth.register"))

        # ✅ FIXED: no password field directly
        new_user = User(
            username=username,
            full_name=username,   # simple default
            role="Banker",
            active=True
        )

        # ✅ IMPORTANT
        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        flash("User registered successfully. Please login.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html")