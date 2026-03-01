import os
import time
import random
import hmac
import logging
from datetime import timedelta, datetime

from flask import Flask, render_template_string, redirect, url_for, request, flash, session
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
# CONFIGURAÇÃO INICIAL
# =========================================================

load_dotenv()
ENV = os.getenv("ENV", "production")  # produção por padrão

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    raise RuntimeError("SECRET_KEY não definido!")

# Proxy do Render
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# Variáveis críticas
ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")
TOTP_SECRET = os.getenv("ADMIN_2FA_SECRET")

if not all([ADMIN_USER, ADMIN_PASSWORD_HASH, TOTP_SECRET]):
    raise RuntimeError("Variáveis críticas não definidas!")

# Configuração de sessão segura
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=True,  # exige HTTPS em produção
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
    if ip in BLOCKED_IPS and time.time() < BLOCKED_IPS[ip]:
        return True
    BLOCKED_IPS.pop(ip, None)
    return False

def register_failed_attempt(ip):
    now = time.time()
    attempts = [t for t in FAILED_LOGINS.get(ip, []) if now - t < 900]  # últimas 15 min
    attempts.append(now)
    FAILED_LOGINS[ip] = attempts
    if len(attempts) >= 10:
        BLOCKED_IPS[ip] = now + 900

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
# HEADERS DE SEGURANÇA
# =========================================================

@app.after_request
def secure_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'self'"

    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

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
# FUNÇÕES DE LOGIN
# =========================================================

def security_delay():
    time.sleep(1 + random.uniform(0.2, 0.5))

def constant_time_login_check(input_user, input_pass):
    user_valid = hmac.compare_digest(input_user.encode(), ADMIN_USER.encode())
    pass_valid = check_password_hash(ADMIN_PASSWORD_HASH, input_pass)
    return user_valid and pass_valid

# =========================================================
# ROTAS
# =========================================================

@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    ip = request.remote_addr

    if is_ip_blocked(ip):
        flash("Seu IP está temporariamente bloqueado.")
        logger.warning(f"IP bloqueado tentou login | IP: {ip}")
        return render_template_string("<p style='color:red;'>IP bloqueado temporariamente.</p>")

    form = LoginForm()
    if form.validate_on_submit():
        valid = constant_time_login_check(form.username.data, form.password.data)
        security_delay()
        if valid:
            session.clear()
            session["pre_2fa"] = True
            return redirect(url_for("two_factor"))

        register_failed_attempt(ip)
        flash("Credenciais inválidas")
        logger.warning(f"Falha login | IP: {ip}")

    return render_template_string("""
        <h2>Login Seguro</h2>
        {% with messages = get_flashed_messages() %}
          {% if messages %}<p style="color:red;">{{ messages[0] }}</p>{% endif %}
        {% endwith %}
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
# DEBUGS (opcional)
# =========================================================

@app.route("/debug-ip")
def debug_ip():
    return f"""
    remote_addr: {request.remote_addr}<br>
    x_forwarded_for: {request.headers.get('X-Forwarded-For')}<br>
    """

@app.route("/debug-scheme")
def debug_scheme():
    return f"""
    scheme: {request.scheme}<br>
    is_secure: {request.is_secure}<br>
    """

@app.route("/debug-referrer")
def debug_referrer():
    return {
        "referrer": request.referrer,
        "host": request.host,
        "scheme": request.scheme,
        "is_secure": request.is_secure,
        "headers": dict(request.headers)
    }

# =========================================================
# MAIN
# =========================================================

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)