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
from flask_limiter.util import get_remote_address
import pyotp

# =========================================================
# CONFIGURAÇÃO INICIAL
# =========================================================

load_dotenv()
ENV = os.getenv("ENV", "production")

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY") or os.urandom(32)  # fallback se não definido
if not app.secret_key:
    raise RuntimeError("SECRET_KEY não definido!")

# Proxy confiável (Render / outros PaaS geralmente usam 1 hop)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

# Configurações de segurança da sessão
app.config.update(
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=(ENV == "production"),          # só Secure em prod
    SESSION_COOKIE_NAME="__Host-admin_session",
    WTF_CSRF_TIME_LIMIT=300,
    WTF_CSRF_SSL_STRICT=True,                             # mantemos true agora que referrer funciona
)

csrf = CSRFProtect(app)

# Variáveis críticas
ADMIN_USER = os.getenv("ADMIN_USER")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")
TOTP_SECRET = os.getenv("ADMIN_2FA_SECRET")

if not all([ADMIN_USER, ADMIN_PASSWORD_HASH, TOTP_SECRET]):
    raise RuntimeError("Variáveis críticas (ADMIN_USER, ADMIN_PASSWORD_HASH, TOTP_SECRET) não definidas!")

# =========================================================
# LOGGING
# =========================================================

logging.basicConfig(level=logging.INFO, format="%(asctime)s | %(levelname)s | %(message)s | IP: %(client_ip)s")
logger = logging.getLogger("security")

def get_client_ip():
    """Obtém o IP real do cliente considerando proxies"""
    if forwarded := request.headers.get("X-Forwarded-For"):
        # Pega o primeiro IP da cadeia (o mais confiável)
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"

# =========================================================
# RATE LIMIT & BLOQUEIO PROGRESSIVO
# =========================================================

# Atenção: em múltiplas instâncias → usar Redis / Upstash no futuro
FAILED_LOGINS = {}
BLOCKED_IPS = {}

def is_ip_blocked():
    ip = get_client_ip()
    if ip in BLOCKED_IPS and time.time() < BLOCKED_IPS[ip]:
        return True, ip
    BLOCKED_IPS.pop(ip, None)
    return False, ip

def register_failed_attempt():
    ip = get_client_ip()
    now = time.time()
    attempts = [t for t in FAILED_LOGINS.get(ip, []) if now - t < 900]  # 15 min
    attempts.append(now)
    FAILED_LOGINS[ip] = attempts
    if len(attempts) >= 10:
        BLOCKED_IPS[ip] = now + 900  # bloqueio de 15 min
        logger.warning("IP bloqueado por excesso de tentativas", extra={"client_ip": ip})

limiter = Limiter(
    key_func=get_client_ip,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

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
# HEADERS DE SEGURANÇA (mais completo)
# =========================================================

@app.after_request
def secure_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    
    # CSP mais restritivo
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "form-action 'self'; "
        "base-uri 'self'; "
        "frame-ancestors 'none'; "
        "upgrade-insecure-requests;"
    )
    
    if ENV == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    
    return response

# =========================================================
# TIMEOUT DE SESSÃO
# =========================================================

@app.before_request
def session_timeout():
    if not session:
        return
    
    session.permanent = True
    now = datetime.now(timezone.utc)
    
    if "last_activity" in session:
        try:
            last = datetime.fromisoformat(session["last_activity"]).replace(tzinfo=timezone.utc)
            if (now - last).total_seconds() > 900:  # 15 minutos
                logout_user()
                session.clear()
                flash("Sessão expirada por inatividade.")
                return redirect(url_for("login"))
        except (ValueError, TypeError):
            session.clear()  # formato inválido → limpa
    
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
# FUNÇÕES AUXILIARES
# =========================================================

def security_delay():
    time.sleep(1 + random.uniform(0.2, 0.5))

def constant_time_login_check(input_user, input_pass):
    return (
        hmac.compare_digest(input_user.strip().lower().encode(), ADMIN_USER.strip().lower().encode()) and
        check_password_hash(ADMIN_PASSWORD_HASH, input_pass)
    )

# =========================================================
# ROTAS
# =========================================================

@app.route("/admin/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    blocked, ip = is_ip_blocked()
    if blocked:
        flash("Seu IP está temporariamente bloqueado por excesso de tentativas.")
        logger.warning("Tentativa de acesso com IP bloqueado", extra={"client_ip": ip})
        return render_template_string("<p style='color:red; text-align:center;'>IP bloqueado temporariamente (15 min).</p>")

    form = LoginForm()
    if form.validate_on_submit():
        valid = constant_time_login_check(form.username.data, form.password.data)
        security_delay()
        
        if valid:
            session.clear()
            session["pre_2fa"] = True
            logger.info("Pré-login 2FA iniciado", extra={"client_ip": ip})
            return redirect(url_for("two_factor"))

        register_failed_attempt()
        flash("Credenciais inválidas.")
        logger.warning("Falha na autenticação (usuário/senha)", extra={"client_ip": ip})

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
    blocked, ip = is_ip_blocked()
    if blocked:
        return redirect(url_for("login"))

    if not session.get("pre_2fa"):
        return redirect(url_for("login"))

    form = TwoFactorForm()
    if form.validate_on_submit():
        totp = pyotp.TOTP(TOTP_SECRET)
        if totp.verify(form.token.data.strip(), valid_window=1):
            session.clear()
            login_user(Admin(), fresh=True, remember=False)
            logger.info("Login bem-sucedido (2FA validado)", extra={"client_ip": ip})
            return redirect(url_for("dashboard"))

        register_failed_attempt()  # ← importante: também bloqueia por falha no 2FA
        flash("Código 2FA inválido.")
        logger.warning("Falha na verificação 2FA", extra={"client_ip": ip})

    return render_template_string("""
        <h2>Verificação 2FA</h2>
        {% with messages = get_flashed_messages() %}
          {% if messages %}<p style="color:red;">{{ messages[0] }}</p>{% endif %}
        {% endwith %}
        <form method="POST">
            {{ form.hidden_tag() }}
            {{ form.token.label }} {{ form.token(size=8, maxlength=6, pattern="[0-9]{6}") }}<br><br>
            <button type="submit">Verificar</button>
        </form>
    """, form=form)

@app.route("/admin/dashboard")
@login_required
def dashboard():
    return "🔥 Área administrativa protegida com sucesso"

@app.route("/admin/logout")
@login_required
def logout():
    logout_user()
    session.clear()
    flash("Você saiu do sistema.")
    return redirect(url_for("login"))

# =========================================================
# DEBUG (remova ou proteja em produção real)
# =========================================================

@app.route("/debug-ip")
def debug_ip():
    return f"Client IP: {get_client_ip()}<br>X-Forwarded-For: {request.headers.get('X-Forwarded-For')}"

# =========================================================
# INICIALIZAÇÃO
# =========================================================

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=(ENV != "production"))