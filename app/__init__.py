from flask import Flask
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from models import db
from flask_migrate import Migrate
from config import Config 
from .authentication.routes import auth
from .api.routes import api



app = Flask(__name__)
app.config.from_object(Config)

# Register extensions
db.init_app(app)
JWTManager(app)
migrate = Migrate(app, db)
CORS(app)

# Register Blueprints
app.register_blueprint(api)
app.register_blueprint(auth)


if __name__ == '__main__':
    app.debug = True
    app.run()