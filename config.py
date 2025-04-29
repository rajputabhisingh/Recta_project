import os

class Config:
    SECRET_KEY = 'super-secret-key'
    SQLALCHEMY_DATABASE_URI = "postgresql://postgres:admin@localhost:5432/customer_support"
    SQLALCHEMY_TRACK_MODIFICATIONS = False
     # Email Configuration
    MAIL_SERVER = 'smtp.gmail.com'  # Use Gmail SMTP
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USERNAME = "bcnews54@gmail.com"  # Change this
    MAIL_PASSWORD = "odef ntza arrc scpg"   # Change this
