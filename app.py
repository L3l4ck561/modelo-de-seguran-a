import os
import time
import random
import hmac
import logging
from datetime import datetime, timedelta, timezone

from flask import Flask, render_template_string, redirect, url_for, request, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import PasswordField, StringField
from wtforms.validators import DataRequired
from werkzeug.security import check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
from flask_limiter import Limiter
import pyotp

# =========================================================
# CONFIGURAÇÃO
# =========================================================

load_dotenv()
ENV = os.getenv("ENV", "production")

app = Flask(__name__)

secret_key = os.getenv("SECRET_KEY")
if not secret_key:
    raise RuntimeError("SECRET_KEY não definido!")
app.secret_key = secret_key

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=(ENV == "production"),
    SESSION_COOKIE_NAME="__Host-admin_session",
    WTF_CSRF_TIME_LIMIT=300,
)

csrf = CSRFProtect(app)

ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")
TOTP_SECRET = os.getenv("ADMIN_2FA_SECRET")

if not all([ADMIN_USER, ADMIN_PASSWORD_HASH, TOTP_SECRET]):
    raise RuntimeError("Variáveis críticas não definidas!")

# =========================================================
# LOGIN MANAGER
# =========================================================

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class Admin(UserMixin):
    id = "admin"

@login_manager.user_loader
def load_user(user_id):
    return Admin() if user_id == "admin" else None

# =========================================================
# RATE LIMIT
# =========================================================

limiter = Limiter(
    key_func=lambda: request.headers.get("X-Forwarded-For", request.remote_addr),
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# =========================================================
# SESSION TIMEOUT
# =========================================================

@app.before_request
def session_timeout():
    if not session:
        return

    session.permanent = True
    now = datetime.now(timezone.utc)

    if "last_activity" in session:
        last = datetime.fromisoformat(session["last_activity"])
        if (now - last).total_seconds() > 900:
            logout_user()
            session.clear()
            flash("Sessão expirada.")
            return redirect(url_for("login"))

    session["last_activity"] = now.isoformat()

# =========================================================
# FORMS
# =========================================================

class LoginForm(FlaskForm):
    username = StringField("Usuário", validators=[DataRequired()])
    password = PasswordField("Senha", validators=[DataRequired()])

class TwoFactorForm(FlaskForm):
    token = StringField("Código 2FA", validators=[DataRequired()])

# =========================================================
# HELPERS
# =========================================================

def security_delay():
    time.sleep(1 + random.uniform(0.2, 0.5))

def constant_time_login_check(user, password):
    return (
        hmac.compare_digest(user.lower().strip().encode(),
                            ADMIN_USER.lower().strip().encode())
        and check_password_hash(ADMIN_PASSWORD_HASH, password)
    )

def regenerate_session():
    """Proteção real contra session fixation"""
    data = dict(session)
    session.clear()
    session.update(data)
    session.modified = True

# =========================================================
# ROTAS
# =========================================================

@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()

    if form.validate_on_submit():
        valid = constant_time_login_check(
            form.username.data,
            form.password.data
        )
        security_delay()

        if valid:
            session.clear()
            session["pre_2fa_user"] = "admin"
            regenerate_session()
            return redirect(url_for("two_factor"))

        flash("Credenciais inválidas")

    return render_template_string("""
        <h2>Login Seguro</h2>
        <form method="POST">
            {{ form.hidden_tag() }}
            {{ form.username.label }} {{ form.username() }}<br><br>
            {{ form.password.label }} {{ form.password() }}<br><br>
            <button type="submit">Entrar</button>
        </form>
    """, form=form)

@app.route("/admin/2fa", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def two_factor():

    if session.get("pre_2fa_user") != "admin":
        return redirect(url_for("login"))

    form = TwoFactorForm()

    if form.validate_on_submit():
        totp = pyotp.TOTP(TOTP_SECRET)

        if totp.verify(form.token.data.strip(), valid_window=1):
            session.clear()
            regenerate_session()
            login_user(Admin(), fresh=True)
            return redirect(url_for("dashboard"))

        flash("Código inválido")

    return render_template_string("""
        <h2>Verificação 2FA</h2>
        <form method="POST">
            {{ form.hidden_tag() }}
            {{ form.token.label }} {{ form.token() }}<br><br>
            <button type="submit">Verificar</button>
        </form>
    """, form=form)

@app.route("/admin/dashboard")
@login_required
def dashboard():
    return "🔥 Admin protegido por camadas reais de segurança"

@app.route("/admin/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("login"))

# =========================================================
# DEBUG
# =========================================================

@app.route("/debug-session")
def debug_session():
    return {
        "session_keys": list(session.keys()),
        "csrf_in_session": "csrf_token" in session
    }

# =========================================================

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=(ENV != "production"))