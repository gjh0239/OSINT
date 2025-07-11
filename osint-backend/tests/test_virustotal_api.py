import unittest
from unittest.mock import patch, MagicMock
import json
import os
import sys
from dotenv import load_dotenv

# Add the app directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.blueprints.GET_API import VirusTotalAPI

class TestVirusTotalAPI(unittest.TestCase):

	def setUp(self):
		# Load environment variables for API keys
		load_dotenv()
		self.api = VirusTotalAPI()
		
		# Sample responses for mocking
		self.ip_response = {
			"data": {
				"attributes": {
					"last_analysis_stats": {
						"malicious": 0,
						"suspicious": 0
					},
					"country": "US"
				}
			}
		}
		
		self.domain_response = {
			"data": {
				"attributes": {
					"last_dns_records": [],
					"last_analysis_stats": {
						"malicious": 0,
						"suspicious": 0
					}
				}
			}
		}
		
		self.email_response = {
			"data": [
				{
					"type": "file",
					"attributes": {
						"names": ["test.txt"]
					}
				}
			]
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
		self.assertEqual(mock_request.call_args[0][0], 
						"https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8")
	
	@patch('app.blueprints.GET_API.GET_API.make_api_request')
	def test_get_domain_report(self, mock_request):
		# Setup mock
		mock_request.return_value = self.domain_response
		
		# Call the method
		result = self.api.get_domain_report("example.com")
		
		# Verify results
		self.assertEqual(result, self.domain_response)
		mock_request.assert_called_once()
		self.assertEqual(mock_request.call_args[0][0], 
                     "https://www.virustotal.com/api/v3/domains/example.com")
	
	@patch('app.blueprints.GET_API.GET_API.make_api_request')
	def test_get_email_report(self, mock_request):
		# Setup mock
		mock_request.return_value = self.email_response
		
		# Call the method
		result = self.api.get_email_report("user@example.com")
		
		# Verify results
		self.assertEqual(result, self.email_response)
		mock_request.assert_called_once()
		self.assertEqual(mock_request.call_args[1]['params']['query'], 
						 "user@example.com")
	
	@patch('app.blueprints.GET_API.VirusTotalAPI.get_ip_report')
	def test_lookup_query_ip(self, mock_get_ip):
		# Setup mock
		mock_get_ip.return_value = self.ip_response
		
		# Call the method
		result = self.api.lookup_query("8.8.8.8")
		
		# Verify results
		self.assertEqual(result, self.ip_response)
		mock_get_ip.assert_called_once_with("8.8.8.8")
	
	@patch('app.blueprints.GET_API.VirusTotalAPI.get_domain_report')
	def test_lookup_query_domain(self, mock_get_domain):
		# Setup mock
		mock_get_domain.return_value = self.domain_response
		
		# Call the method
		result = self.api.lookup_query("example.com")
		
		# Verify results
		self.assertEqual(result, self.domain_response)
		mock_get_domain.assert_called_once_with("example.com")
	
	@patch('app.blueprints.GET_API.VirusTotalAPI.get_email_report')
	def test_lookup_query_email(self, mock_get_email):
		# Setup mock
		mock_get_email.return_value = self.email_response
		
		# Call the method
		result = self.api.lookup_query("user@example.com")
		
		# Verify results
		self.assertEqual(result, self.email_response)
		mock_get_email.assert_called_once_with("user@example.com")

if __name__ == '__main__':
	unittest.main()
