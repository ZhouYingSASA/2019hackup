from flask import Flask
from flask_bootstrap import Bootstrap
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_moment import Moment
from config import config

bootstrap = Bootstrap()
mail = Mail()
db = SQLAlchemy()
moment = Moment()
login_manager = LoginManager()


def create_app(config_name):
    application = Flask(__name__)
    bootstrap.init_app(application)
    application.config.from_object(config[config_name])
    config[config_name].init_app(application)
    moment.init_app(application)
    db.init_app(application)

    "——注册蓝本——"
    # from .main import main as main_blueprint
    # application.register_blueprint(main_blueprint)
    from .auth import auth as auth_blueprint
    application.register_blueprint(auth_blueprint, url_prefix='/auth')

    return application
