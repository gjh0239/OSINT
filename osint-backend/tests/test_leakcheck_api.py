import unittest
from unittest.mock import patch, MagicMock
import json
import os
import sys
from dotenv import load_dotenv

# Add the app directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.blueprints.GET_API import LeakCheckAPI

class TestLeakCheckAPI(unittest.TestCase):

    def setUp(self):
        # Load environment variables for API keys
        load_dotenv()
        self.api = LeakCheckAPI()
        
        # Sample responses for mocking
        self.success_response = {
            "success": True,
            "found": 3,
            "sources": ["Adobe", "LinkedIn", "Collection1"],
            "fields": ["password", "email", "username"],
            "result": [
                {"sources": "Adobe", "password": "hashed_password"}
            ]
        }
        
        self.error_response = {
            "success": False,
            "message": "API Key limit reached"
        }
    
    @patch('app.blueprints.GET_API.GET_API.make_api_request')
    def test_get_email_report_success(self, mock_request):
        # Setup mock
        mock_request.return_value = self.success_response
        
        # Call the method
        result = self.api.get_email_report("user@example.com")
        
        # Verify results
        self.assertTrue(result["breached"])
        self.assertEqual(result["found"], 3)
        self.assertEqual(result["exposed_data"], ["password", "email", "username"])
        self.assertEqual(result["breaches"], ["Adobe", "LinkedIn", "Collection1"])
        mock_request.assert_called_once()
        self.assertEqual(mock_request.call_args[1]['params']['check'], "user@example.com")
    
    @patch('app.blueprints.GET_API.GET_API.make_api_request')
    def test_get_email_report_error(self, mock_request):
        # Setup mock
        mock_request.return_value = self.error_response
        
        # Call the method and check for exception
        with self.assertRaises(Exception) as context:
            self.api.get_email_report("user@example.com")
        
        self.assertEqual(str(context.exception), "API Key limit reached")
    
    @patch('app.blueprints.GET_API.LeakCheckAPI.get_email_report')
    def test_lookup_query_email(self, mock_get_email):
        # Setup mock
        formatted_response = {
            "breached": True,
            "found": 3,
            "exposed_data": ["password", "email", "username"],
            "breaches": ["Adobe", "LinkedIn", "Collection1"]
        }
        mock_get_email.return_value = formatted_response
        
        # Call the method
        result = self.api.lookup_query("user@example.com")
        
        # Verify results
        self.assertEqual(result, formatted_response)
        mock_get_email.assert_called_once_with("user@example.com")
    
    def test_lookup_query_invalid(self):
        # Call the method
        result = self.api.lookup_query("invalid-format")
        
        # Verify results
        self.assertEqual(result, {"error": "No valid query type"})

if __name__ == '__main__':
    unittest.main()
