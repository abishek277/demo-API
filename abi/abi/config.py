import os

basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = '1234567890098765412345678'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'myshop.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False
