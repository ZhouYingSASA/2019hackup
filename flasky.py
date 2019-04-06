# config=utf-8
import os
from flask_migrate import Migrate
from application import create_app, db


application = create_app(os.getenv('FLASK_CONFIG') or 'default')
migrate = Migrate(application, db)


@application.shell_context_processor
def make_shell_context():
    return dict(db=db)

