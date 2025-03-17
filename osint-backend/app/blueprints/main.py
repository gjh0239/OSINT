from flask import Blueprint, request, jsonify
import requests

main_bp = Blueprint('main', __name__)

@main_bp.route('/query', methods=['GET'])
def query_api():
    user_input = request.args.get('input', '')
    if not user_input:
        return jsonify({"error": "No input provided"}), 400

    # Example API call
    try:
        response = requests.get(f"https://api.example.com/search?q={user_input}")
        response.raise_for_status()  # Raise an error for failed requests
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500

# Add the index route from modules/main/route.py
@main_bp.route('/', methods=['GET'])
def index():
    """ Example endpoint with simple greeting.
    ---
    tags:
      - Example API
    responses:
      200:
        description: A simple greeting
        schema:
          type: object
          properties:
            data:
              type: object
              properties:
                message:
                  type: string
                  example: "Hello World!"
    """
    return jsonify(data={'message': 'Hello, World!'})

@main_bp.route('/check-email', methods=['POST'])
def check_email_breach():
    """
    Check if an email has been involved in data breaches using LeakCheck.io API.
    ---
    tags:
      - Email Security API
    parameters:
      - name: email
        in: body
        required: true
        schema:
          type: object
          properties:
            email:
              type: string
              description: Email address to check
              example: "user@example.com"
    responses:
      200:
        description: Email breach check results
        schema:
          type: object
          properties:
            breached:
              type: boolean
            found:
              type: integer
            exposed_data:
              type: array
              items:
                type: string
            breaches:
              type: array
              items:
                type: object
      400:
        description: Missing or invalid email
      500:
        description: Server error
    """
    data = request.json
    email = data.get('email', '')
    
    if not email:
        return jsonify({"error": "No email provided"}), 400
    
    # LeakCheck.io API call
    try:
        response = requests.get(f"https://leakcheck.io/api/public?check={email}")
        response.raise_for_status()
        
        data = response.json()
        
        if not data.get('success'):
            return jsonify({"error": data.get('message', 'Unknown error from API')}), 500
            
        return jsonify({
            "breached": data.get('found', 0) > 0,
            "found": data.get('found', 0),
            "exposed_data": data.get('fields', []),
            "breaches": data.get('sources', [])
        })
            
    except requests.exceptions.RequestException as e:
        return jsonify({"error": str(e)}), 500