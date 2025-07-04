import os
from dotenv import load_dotenv

basedir = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(basedir, '.env'), override=True)

class Config(object):
    SECRET_KEY = os.environ.get('SECRET_KEY')
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'app.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    MAIL_SENDER = os.environ.get('MAIL_SENDER')
    HCAPTCHA_SITE_KEY = os.environ.get('HCAPTCHA_SITE_KEY')
    HCAPTCHA_SECRET_KEY = os.environ.get('HCAPTCHA_SECRET_KEY')
    MAILJET_KEY = os.environ.get('MAILJET_KEY')
    MAILJET_SECRET = os.environ.get('MAILJET_SECRET')
    ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL')
    PHONE = os.environ.get('PHONE')
