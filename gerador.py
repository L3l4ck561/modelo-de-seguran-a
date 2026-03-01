from werkzeug.security import generate_password_hash
print(generate_password_hash("sua_senha"))

import pyotp
print('2FA:')
print(pyotp.random_base32())

import pyotp
totp = pyotp.TOTP("SEU_SEGREDO_GERADO")
print('google authenticator')
print(totp.provisioning_uri("Admin", issuer_name="SeuSistema"))

import secrets
print(secrets.token_urlsafe(64))