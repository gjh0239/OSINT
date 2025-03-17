from flask import Flask, request, jsonify
from flask_cors import CORS
from app.blueprints.main import main_bp
from app.config.config import get_config_by_name
from app.initialize_functions import initialize_db, initialize_swagger

def create_app(config=None) -> Flask:
    """
    Create a Flask application.

    Args:
        config: The configuration object to use.

    Returns:
        A Flask application instance.
    """
    app = Flask(__name__)
    CORS(app)  # Apply CORS globally
    
    # Register blueprint with a URL prefix to match the previous modules approach
    app.register_blueprint(main_bp, url_prefix='/api/v1/main')
    
    if config:
        app.config.from_object(get_config_by_name(config))

    # Initialize extensions
    initialize_db(app)

    # Remove this line: initialize_route(app)
    
    # Initialize Swagger
    initialize_swagger(app)

    return app

if __name__ == "__main__":
    app = create_app()
    app.run(debug=True)