import unittest
from unittest.mock import patch, MagicMock
import json
import os
import sys
from dotenv import load_dotenv

# Add the app directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.blueprints.GET_API import AbuseIPDBAPI

class TestAbuseIPDBAPI(unittest.TestCase):

    def setUp(self):
        # Load environment variables for API keys
        load_dotenv()
        self.api = AbuseIPDBAPI()
        
        # Sample response for mocking
        self.ip_response = {
            "data": {
                "ipAddress": "8.8.8.8",
                "abuseConfidenceScore": 0,
                "countryCode": "US",
                "usageType": "Data Center/Web Hosting/Transit",
                "isp": "Google LLC",
                "domain": "google.com",
                "hostnames": ["dns.google"],
                "totalReports": 0
            }
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
                         "https://api.abuseipdb.com/api/v2/check")
        self.assertEqual(mock_request.call_args[1]['params']['ipAddress'], "8.8.8.8")
        self.assertEqual(mock_request.call_args[1]['params']['maxAgeInDays'], 90)
        self.assertTrue(mock_request.call_args[1]['params']['verbose'])
    
    @patch('app.blueprints.GET_API.AbuseIPDBAPI.get_ip_report')
    def test_lookup_query_ip(self, mock_get_ip):
        # Setup mock
        mock_get_ip.return_value = self.ip_response
        
        # Call the method
        result = self.api.lookup_query("8.8.8.8")
        
        # Verify results
        self.assertEqual(result, self.ip_response)
        mock_get_ip.assert_called_once_with("8.8.8.8")
    
    def test_lookup_query_invalid(self):
        # Call the method
        result = self.api.lookup_query("example.com")
        
        # Verify results
        self.assertEqual(result, "No valid query type")

if __name__ == '__main__':
    unittest.main()
