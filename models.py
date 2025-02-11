from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    token = db.Column(db.String(255), nullable=True)

    def set_password(self, password):
        """Hashes the password and stores it."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Verifies if the password is correct."""
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f"<User {self.username}>"

class BatchFileUpload(db.Model):
    __tablename__ = 'batch_file_uploads'

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    batch_name = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(100), nullable=False)
    s3_key = db.Column(db.String(255), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False)

    def __repr__(self):
        return f"<BatchFileUpload {self.batch_name} - {self.file_type}>"
