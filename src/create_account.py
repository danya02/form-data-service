from database import *
import getpass

email = input('Email: ')
name = input('Name: ')
password = getpass.getpass('Password: ')

user = User.get_or_none(User.email == email)
if user:
    print('User already exists; would you like to reset the password?')
    if input('y/N: ').lower() == 'y':
        user.set_password(password)
        user.save()
        print('Password reset.')
    else:
        print(f'User {email} not changed.')
else:
    user = User(email=email, name=name)
    user.set_password(password)
    user.save()
    print(f'User {email} created.')