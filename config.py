import os
basedir = os.path.abspath(os.path.dirname(__file__))


class Config:
    SQLALCHEMY_COMMIT_ON_TEARDOWN = True
    SQLALCHEMY_TRACK_MODIFICATIONS = True

    #     ' ///---环境变量需要---/// '

    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD')

    #     ' ///---环境变量需要---/// '

    SECRET_KEY = os.environ.get('SECRET_KEY', '*****')
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.qq.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 25))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in \
        ['true', 'on', '1']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME', '649414476@qq.com')
    FLASKY_MAIL_SUBJECT_PREFIX = '[No.996]'
    FLASKY_MAIL_SENDER = 'No.996 Team <649414476@qq.com>'
    FLASKY_ADMIN = os.environ.get('FLASKY_ADMIN', '649414476@qq.com')

    @staticmethod
    def init_app(app):
        pass


class ProductionConfig(Config):
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data.sqlite')


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('DEV_DATABASE_URL') or \
        'sqlite:///' + os.path.join(basedir, 'data-dev.sqlite')


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = os.environ.get('TEST_DATABASE_URL') or \
        'sqlite://'
    WTF_CSRF_ENABLED = False


config = {
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}
