from werkzeug.security import generate_password_hash
print(generate_password_hash("123456"))

import pyotp
print('2FA:')
print(pyotp.random_base32())

import pyotp
totp = pyotp.TOTP("SEU_SEGREDO_GERADO")
print('google authenticator')
print(totp.provisioning_uri("Admin", issuer_name="SeuSistema"))