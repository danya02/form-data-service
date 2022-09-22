from database import *
from getpass import getpass

db.connect()
email = input('Email: ')
user = User.get_or_none(User.email == email)
if user is None:
    print('User not found.')
    exit(1)
password = getpass('New password: ')
user.set_password(password)
user.pwned_login_count = 5
user.save()
print('Password changed.')
db.close()