import os
import time
import random
import hmac
import logging
import ipaddress
from datetime import timedelta, datetime

from flask import Flask, render_template_string, redirect, url_for, request, abort, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import PasswordField, StringField
from wtforms.validators import DataRequired
from werkzeug.security import check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import pyotp

# =========================================================
# CONFIG INICIAL
# =========================================================

load_dotenv()
ENV = os.getenv("ENV", "development")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")

# Variáveis críticas
ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")
TOTP_SECRET = os.getenv("ADMIN_2FA_SECRET")
ADMIN_ALLOWED_IP = os.getenv("ADMIN_ALLOWED_IP")  # IP público permitido

if not all([app.secret_key, ADMIN_USER, ADMIN_PASSWORD_HASH, TOTP_SECRET]):
    raise RuntimeError("Variáveis críticas não definidas.")

app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)

app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=True if ENV == "production" else False,
    SESSION_COOKIE_NAME="__Host-admin_session",
    WTF_CSRF_TIME_LIMIT=300
)

csrf = CSRFProtect(app)

# =========================================================
# LOGGING
# =========================================================

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s")
logger = logging.getLogger("security")

# =========================================================
# RATE LIMIT
# =========================================================

limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# =========================================================
# BLOQUEIO PROGRESSIVO
# =========================================================

FAILED_LOGINS = {}
BLOCKED_IPS = {}

def is_ip_blocked(ip):
    if ip in BLOCKED_IPS:
        if time.time() < BLOCKED_IPS[ip]:
            return True
        else:
            del BLOCKED_IPS[ip]
    return False

def register_failed_attempt(ip):
    now = time.time()
    attempts = FAILED_LOGINS.get(ip, [])
    # só mantém tentativas nos últimos 15 minutos
    attempts = [t for t in attempts if now - t < 900]
    attempts.append(now)
    FAILED_LOGINS[ip] = attempts
    if len(attempts) >= 10:
        BLOCKED_IPS[ip] = now + 900

# =========================================================
# VERIFICAÇÃO DE IP PERMITIDO
# =========================================================

def is_ip_allowed(ip):
    if not ADMIN_ALLOWED_IP:
        return True  # libera todos se variável não estiver definida
    try:
        return ipaddress.ip_address(ip) == ipaddress.ip_address(ADMIN_ALLOWED_IP)
    except ValueError:
        return False

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
    if user_id == "admin":
        return Admin()
    return None

# =========================================================
# HEADERS DE SEGURANÇA
# =========================================================

@app.after_request
def secure_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Referrer-Policy"] = "no-referrer"
    if ENV == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response

# =========================================================
# TIMEOUT
# =========================================================

@app.before_request
def session_timeout():
    session.permanent = True
    now = datetime.utcnow()
    if "last_activity" in session:
        delta = now - datetime.fromisoformat(session["last_activity"])
        if delta.total_seconds() > 900:
            logout_user()
            session.clear()
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
# SEGURANÇA LOGIN
# =========================================================

def security_delay():
    time.sleep(1 + random.uniform(0.2, 0.5))

def constant_time_login_check(input_user, input_pass):
    user_valid = hmac.compare_digest(input_user.encode(), ADMIN_USER.encode())
    pass_valid = check_password_hash(ADMIN_PASSWORD_HASH, input_pass)
    return user_valid and pass_valid

# =========================================================
# LOGIN
# =========================================================

@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    ip = request.remote_addr

    # bloqueio de IP
    if is_ip_blocked(ip):
        flash("Seu IP está temporariamente bloqueado devido a múltiplas tentativas falhas.")
        logger.warning(f"IP bloqueado tentou login | IP: {ip} | UA: {request.headers.get('User-Agent')}")
        return render_template_string("<p style='color:red;'>IP bloqueado temporariamente.</p>")

    # whitelist de IP
    if not is_ip_allowed(ip):
        flash("Seu IP não tem permissão para acessar este sistema.")
        logger.warning(f"IP não autorizado tentou login | IP: {ip} | UA: {request.headers.get('User-Agent')}")
        return render_template_string("<p style='color:red;'>IP não autorizado.</p>")

    form = LoginForm()
    if form.validate_on_submit():
        valid = constant_time_login_check(form.username.data, form.password.data)
        security_delay()

        if valid:
            session.clear()
            session["pre_2fa"] = True
            return redirect(url_for("two_factor"))

        register_failed_attempt(ip)
        logger.warning(f"Falha login | IP: {ip} | UA: {request.headers.get('User-Agent')}")
        flash("Credenciais inválidas")

    return render_template_string("""
        <h2>Login Seguro</h2>
        {% with messages = get_flashed_messages() %}
        {% if messages %}
        <p style="color:red;">{{ messages[0] }}</p>
        {% endif %}
        {% endwith %}
        <form method="POST">
            {{ form.hidden_tag() }}
            {{ form.username.label }} {{ form.username() }}<br><br>
            {{ form.password.label }} {{ form.password() }}<br><br>
            <button type="submit">Entrar</button>
        </form>
    """, form=form)

# =========================================================
# 2FA
# =========================================================

@app.route("/admin/2fa", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def two_factor():
    ip = request.remote_addr

    if not session.get("pre_2fa"):
        return redirect(url_for("login"))

    form = TwoFactorForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(TOTP_SECRET)
        if totp.verify(form.token.data, valid_window=1):
            session.clear()
            login_user(Admin(), fresh=True)
            logger.info(f"Login sucesso | IP: {ip}")
            return redirect(url_for("dashboard"))

        register_failed_attempt(ip)
        flash("Código inválido")

    return render_template_string("""
        <h2>Verificação 2FA</h2>
        <form method="POST">
            {{ form.hidden_tag() }}
            {{ form.token.label }} {{ form.token() }}<br><br>
            <button type="submit">Verificar</button>
        </form>
    """, form=form)

# =========================================================
# DASHBOARD
# =========================================================

@app.route("/admin/dashboard")
@login_required
def dashboard():
    return "🔥 Admin protegido por camadas reais de segurança"

# =========================================================
# LOGOUT
# =========================================================

@app.route("/admin/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for("login"))

# =========================================================
# MAIN
# =========================================================

@app.route("/debug-ip")
def debug_ip():
    return f"""
    remote_addr: {request.remote_addr}<br>
    x_forwarded_for: {request.headers.get('X-Forwarded-For')}<br>
    """

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=(ENV=="development"))