# config=utf-8
import os
from flask_migrate import Migrate, MigrateCommand
from application import create_app, db
from application.auth.views import Users


application = create_app(os.getenv('FLASK_CONFIG') or 'default')
migrate = Migrate(application, db)
MigrateCommand.add_command('db', MigrateCommand)


@application.shell_context_processor
def make_shell_context():
    return dict(db=db, Users=Users)
