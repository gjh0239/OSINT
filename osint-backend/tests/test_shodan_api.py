import unittest
from unittest.mock import patch, MagicMock
import json
import os
import sys
from dotenv import load_dotenv

# Add the app directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.blueprints.GET_API import ShodanAPI

class TestShodanAPI(unittest.TestCase):

    def setUp(self):
        # Load environment variables for API keys
        load_dotenv()
        self.api = ShodanAPI()
        
        # Sample responses for mocking
        self.ip_response = {
            "ip_str": "8.8.8.8",
            "country_name": "United States",
            "org": "Google LLC",
            "ports": [53, 443],
            "hostnames": ["dns.google"]
        }
        
        self.domain_response = {
            "matches": [
                {
                    "ip_str": "93.184.216.34",
                    "hostnames": ["example.com"]
                }
            ],
            "total": 1
        }
    
    @patch('app.blueprints.GET_API.GET_API.make_api_request')
    def test_get_ip_report(self, mock_request):
        # Setup mock
        mock_request.return_value = self.ip_response
        
        # Call the method
        result = self.api.get_ip_report("8.8.8.8")
        
        # Verify results
        self.assertEqual(result, self.ip_response)
        mock_request.assert_called_once()
        self.assertEqual(mock_request.call_args[1]['endpoint'], 
                         "https://api.shodan.io/shodan/host/8.8.8.8")
        self.assertIn("key", mock_request.call_args[1]['params'])
    
    @patch('app.blueprints.GET_API.GET_API.make_api_request')
    def test_get_domain_report(self, mock_request):
        # Setup mock
        mock_request.return_value = self.domain_response
        
        # Call the method
        result = self.api.get_domain_report("example.com")
        
        # Verify results
        self.assertEqual(result, self.domain_response)
        mock_request.assert_called_once()
        self.assertEqual(mock_request.call_args[1]['endpoint'], 
                         "https://api.shodan.io/shodan/host/search")
        self.assertEqual(mock_request.call_args[1]['params']['query'], 
                         "hostname:example.com")
    
    @patch('app.blueprints.GET_API.ShodanAPI.get_ip_report')
    def test_lookup_query_ip(self, mock_get_ip):
        # Setup mock
        mock_get_ip.return_value = self.ip_response
        
        # Call the method
        result = self.api.lookup_query("8.8.8.8")
        
        # Verify results
        self.assertEqual(result, self.ip_response)
        mock_get_ip.assert_called_once_with("8.8.8.8")
    
    @patch('app.blueprints.GET_API.ShodanAPI.get_domain_report')
    def test_lookup_query_domain(self, mock_get_domain):
        # Setup mock
        mock_get_domain.return_value = self.domain_response
        
        # Call the method
        result = self.api.lookup_query("example.com")
        
        # Verify results
        self.assertEqual(result, self.domain_response)
        mock_get_domain.assert_called_once_with("example.com")
    
    def test_lookup_query_invalid(self):
        # Call the method
        result = self.api.lookup_query("invalid-format")
        
        # Verify results
        self.assertEqual(result, {"error": "No valid query type"})

if __name__ == '__main__':
    unittest.main()
