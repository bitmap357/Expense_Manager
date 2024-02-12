from flask import Flask 
from flask_sqlalchemy import SQLAlchemy 
from flask_login import LoginManager 
import os

from .auth import auth
from .app import app

db = SQLAlchemy()

def create_app():
    app = Flask(__name__)
    
    project_dir = os.path.dirname(os.path.abspath(__file__))
    database_file = "sqlite:///{}".format(
    os.path.join(project_dir, "mydatabase.db")
    )

    app.config['SECRET_KEY'] = 'thisismysecretkey'
    app.config["SQLALCHEMY_DATABASE_URI"] = database_file

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # from .auth import auth as auth_blueprint
    app.register_blueprint(auth)

    # from .app import app as app_blueprint
    app.register_blueprint(app)
    
    if __name__ == '__main__':
        app.run(debug=True)
    
    return app