import unittest
from unittest.mock import patch, MagicMock
import json
import os
import sys
from dotenv import load_dotenv

# Add the app directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.blueprints.GET_API import DNSService

class TestDNSService(unittest.TestCase):

    def setUp(self):
        # Load environment variables
        load_dotenv()
        self.service = DNSService()
        
        # Sample response for mocking
        self.dns_records = {
            "A": ["93.184.216.34"],
            "AAAA": ["2606:2800:220:1:248:1893:25c8:1946"],
            "MX": ["0 example-com.mail.protection.outlook.com"],
            "NS": ["ns1.example.com", "ns2.example.com"],
            "TXT": ["v=spf1 -all"],
            "SOA": ["ns1.example.com. hostmaster.example.com. 2023080801 7200 900 1209600 86400"],
            "CNAME": []
        }
    
    @patch('app.blueprints.GET_API.redis_client.get')
    @patch('dns.resolver.resolve')
    def test_get_dns_records_no_cache(self, mock_dns_resolve, mock_redis_get):
        # Setup mocks
        mock_redis_get.return_value = None
        
        # Create mock answers for each record type
        mock_answers = {}
        for record_type, values in self.dns_records.items():
            mock_answer = MagicMock()
            mock_answers[record_type] = [MagicMock(__str__=lambda self, rt=value: rt) for value in values]
        
        # Configure the DNS resolver mock to return appropriate answers
        def mock_resolve_side_effect(domain, record_type):
            if record_type in mock_answers and mock_answers[record_type]:
                return mock_answers[record_type]
            else:
                from dns.resolver import NoAnswer
                raise NoAnswer()
                
        mock_dns_resolve.side_effect = mock_resolve_side_effect
        
        # Setup Redis mock
        mock_redis_setex = MagicMock()
        with patch('app.blueprints.GET_API.redis_client.setex', mock_redis_setex):
            # Call the method
            result = self.service.get_dns_records("example.com")
            
            # Verify results
            for record_type in self.dns_records:
                self.assertEqual(result[record_type], self.dns_records[record_type])
            
            # Verify Redis was called to set the cache
            mock_redis_setex.assert_called_once()
    
    @patch('app.blueprints.GET_API.redis_client.get')
    def test_get_dns_records_cache_hit(self, mock_redis_get):
        # Setup mock
        mock_redis_get.return_value = json.dumps(self.dns_records).encode('utf-8')
        
        # Call the method
        result = self.service.get_dns_records("example.com")
        
        # Verify results
        self.assertEqual(result, self.dns_records)
        mock_redis_get.assert_called_once_with("dns:domain:example.com")

if __name__ == '__main__':
    unittest.main()
