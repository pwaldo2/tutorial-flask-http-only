import os, sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask_script import Manager, Server
from flask_migrate import Migrate, MigrateCommand
from api import create_app
from api.db import db

app =  create_app()
app.config.from_object(os.environ['APP_SETTINGS'])
migrate = Migrate(app, db)
manager = Manager(app)

manager.add_command("runserver", Server(
    use_debugger = True,
    use_reloader = True,
    host = os.getenv('IP', '0.0.0.0'),
    port = int(os.getenv('PORT', 5000)))
)

manager.add_command('db', MigrateCommand)

if __name__ == '__main__':
    manager.run()