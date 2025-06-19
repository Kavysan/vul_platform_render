import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'))

class Config():
    '''
        Set config variables for the flask app
        Using Environment variables where available.
        Otherwise create the config variable if not done already
    '''

    FLASK_APP = os.getenv('FLASK_APP')
    FLASK_ENV = os.getenv('FLASK_ENV')
    SECRET_KEY = os.getenv('SECRET_KEY') or 'Kavya'
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URI') or 'sqlite:///' + os.path.join(basedir,'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ECHO = True
    FLASK_DEBUG = os.getenv('FLASK_DEBUG', FLASK_ENV == 'development')
    S3_BUCKET = os.getenv("S3_BUCKET")
    S3_KEY = os.getenv("S3_KEY")
    S3_SECRET = os.getenv("S3_SECRET_ACCESS_KEY")
