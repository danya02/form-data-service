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


@create_table
class Form(MyModel):
    """
    A form holds some fields, and the inputted data from those fields.
    """
    project = pw.ForeignKeyField(Project, backref='forms', on_delete='CASCADE')
    slug = pw.CharField(unique=True, default=lambda: secrets.token_hex(16))
    name = pw.CharField()
    created_at = pw.DateTimeField(default=pw.datetime.datetime.now)
    fields = pw.JSONField(default=[])  # List of fields.
    # Fields should have the format:
    # {
    #     'name': 'field_name',
    #     'required': false
    # }
    # name is the name of the field, the expected formdata key.
    # required is a boolean indicating whether the field is required -- if it is, and the corresponding key is not present in the formdata,
    # the submission will be rejected with a 400 error. If there is no 'required' key, it is assumed to be false.

    config = pw.JSONField(default={})  # Configuration for the form. JSON is used for extensibility. The following keys are used:
    # 'redirect': The URL to redirect to after a successful submission. If not present, the submission will be returned as JSON.
    # 'store_only_fields': if True, only the fields specified in the 'fields' key will be stored. If False, all fields sent by the user-agent will be stored. If not present, defaults to False.
    # 'store_ip': if True, the IP address of the user-agent will be stored. If False, it will not. If not present, defaults to False.
    # 'store_headers': if True, the headers of the user-agent will be stored. If False, they will not. If not present, defaults to False.
    # 'max_data_size': the maximum size of the formdata, in bytes. If not present, defaults to 1*1024*1024 characters (1 MiB).

@create_table
class FormRecord(MyModel):
    """
    A record of a form submission.
    """
    form = pw.ForeignKeyField(Form, backref='records', on_delete='CASCADE')
    created_at = pw.DateTimeField(default=pw.datetime.datetime.now)
    unread = pw.BooleanField(default=True)  # Whether the record has been read (or acted upon) by someone.
    data = pw.JSONField(default={}) # The data submitted in the form.
    metadata = pw.JSONField(default={}) # Metadata about the submission. JSON is used for extensibility. The following keys are used:
    # 'ip': The IP address of the user-agent that submitted the form. Null or not present if not stored.
    # 'headers': The headers of the user-agent that submitted the form. Null or not present if not stored.




# At the very end of the file, reset the database connection.
# Otherwise, the very first request will fail with an peewee.OperationalError: Connection already opened.
try: db.close()
except: pass