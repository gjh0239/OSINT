from flask import Flask
from flasgger import Swagger
# Remove this import: from app.modules.main.route import main_bp
from app.db.db import db

def initialize_route(app: Flask):
    # Either remove this function entirely or leave it empty
    # (who knows if i will need it later)
    pass

def initialize_db(app: Flask):
    with app.app_context():
        db.init_app(app)
        db.create_all()

def initialize_swagger(app: Flask):
    with app.app_context():
        swagger = Swagger(app)
        return swagger