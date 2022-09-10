import peewee as pw
import hashlib
import hmac
import secrets

db = pw.SqliteDatabase('database.db')

class MyModel(pw.Model):
    class Meta:
        database = db

def create_table(cls):
    db.create_tables([cls])
    return cls

@create_table
class FlaskSecretKey(MyModel):
    secret_key = pw.BlobField()
    created_at = pw.DateTimeField(default=pw.datetime.datetime.now)

    @classmethod
    def get_current(cls):
        latest = cls.select().get_or_none()
        if latest is None:
            latest = cls.create(secret_key=secrets.token_bytes(64))
            return latest.secret_key
        else:
            if latest.created_at < pw.datetime.datetime.now() - pw.datetime.timedelta(days=7):
                cls.delete().execute()
                latest = cls.create(secret_key=secrets.token_bytes(64))
                return latest.secret_key
            else:
                return latest.secret_key

@create_table
class User(MyModel):
    email = pw.CharField(unique=True)
    name = pw.CharField()
    password_scrypt_hash = pw.BlobField()
    password_scrypt_salt = pw.BlobField()
    password_scrypt_n = pw.IntegerField(default=16384)
    password_scrypt_r = pw.IntegerField(default=8)
    password_scrypt_p = pw.IntegerField(default=1)

    def check_password(self, password):
        return hmac.compare_digest(self.password_scrypt_hash, 
            hashlib.scrypt(password.encode(),
                salt=self.password_scrypt_salt,
                n=self.password_scrypt_n,
                r=self.password_scrypt_r,
                p=self.password_scrypt_p))

    def set_password(self, password):
        self.password_scrypt_salt = secrets.token_bytes(32)
        self.password_scrypt_n = 16384
        self.password_scrypt_r = 8
        self.password_scrypt_p = 1
        self.password_scrypt_hash = hashlib.scrypt(password.encode(),
            salt=self.password_scrypt_salt,
            n=self.password_scrypt_n,
            r=self.password_scrypt_r,
            p=self.password_scrypt_p)
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if 'password' in kwargs:
            self.set_password(kwargs['password'])

@create_table
class Project(MyModel):
    """A project is a collection of forms that are a part of the same site."""
    slug = pw.CharField(unique=True, default=lambda: secrets.token_hex(16))  # This is the identifier that should be used everywhere user-facing; the default ID is still included for query performance, but only ever show the slug in web pages.
    name = pw.CharField()
    description = pw.TextField(default='')
    owner = pw.ForeignKeyField(User, backref='projects', on_delete='RESTRICT')  # Users must transfer or delete their projects before deleting their account.
    created_at = pw.DateTimeField(default=pw.datetime.datetime.now)

@create_table
class ProjectUser(MyModel):
    """
    A mapping between projects and users that are part of them.
    Even if not included, the owner of the project is a user of the project.
    """
    project = pw.ForeignKeyField(Project, backref='users', on_delete='CASCADE')
    user = pw.ForeignKeyField(User, backref='projects', on_delete='CASCADE')


# At the very end of the file, reset the database connection.
# Otherwise, the very first request will fail with an peewee.OperationalError: Connection already opened.
try: db.close()
except: pass