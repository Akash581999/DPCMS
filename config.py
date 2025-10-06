import os
from dotenv import load_dotenv # type: ignore
load_dotenv()

class Config:
    SECRET_KEY = os.environ.get("akashkumar1999") or "akashkumar1999"
    SQLALCHEMY_DATABASE_URI = 'postgresql://postgres:postgres@localhost:5432/project3'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    JWT_SECRET_KEY = os.environ.get("akashkumar1999") or "akashkumar1999"
    JWT_ACCESS_TOKEN_EXPIRES = 3600  # 1 hour

# PostgreSQL
DATABASE = {
    'ENGINE': 'postgresql',
    'NAME': 'project3',
    'USER': 'postgres',
    'PASSWORD': 'postgres',
    'HOST': 'localhost',
    'PORT': '5432',  # MySQL is usually 3306
}

# Gmail SMTP settings
EMAIL = {
    'SENDER': 'akash581999@gmail.com',
    'APP_PASSWORD': 'ycuw jsnr btcn johr'
}