import unittest
from unittest.mock import patch, MagicMock
import json
import os
import sys
from dotenv import load_dotenv

# Add the app directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.blueprints.GET_API import WHOISService

class TestWHOISService(unittest.TestCase):

    def setUp(self):
        # Load environment variables
        load_dotenv()
        self.service = WHOISService()
        
        # Sample WHOIS result for mocking
        self.whois_data = {
            "domain_name": ["EXAMPLE.COM", "example.com"],
            "registrar": "ICANN",
            "creation_date": "1995-08-14 04:00:00",
            "expiration_date": "2023-08-13 04:00:00",
            "updated_date": "2022-08-14 04:00:00",
            "name_servers": ["NS1.EXAMPLE.COM", "NS2.EXAMPLE.COM"],
            "status": ["clientTransferProhibited"],
            "emails": ["admin@example.com"],
            "registrant": None,
            "admin": None,
            "tech": None,
            "raw": "Domain Name: EXAMPLE.COM\nRegistry Domain ID: 2336799_DOMAIN_COM-VRSN\n..."
        }
    
    @patch('app.blueprints.GET_API.redis_client.get')
    @patch('whois.whois')
    def test_get_whois_info_no_cache(self, mock_whois, mock_redis_get):
        # Setup mocks
        mock_redis_get.return_value = None
        
        # Create a mock WHOIS result object
        mock_result = MagicMock()
        for key, value in self.whois_data.items():
            setattr(mock_result, key, value)
        mock_result.text = self.whois_data["raw"]
        
        mock_whois.return_value = mock_result
        
        # Setup Redis mock
        mock_redis_setex = MagicMock()
        with patch('app.blueprints.GET_API.redis_client.setex', mock_redis_setex):
            # Call the method
            result = self.service.get_whois_info("example.com")
            
            # Verify results
            self.assertEqual(result["domain_name"], self.whois_data["domain_name"])
            self.assertEqual(result["registrar"], self.whois_data["registrar"])
            self.assertEqual(result["creation_date"], str(self.whois_data["creation_date"]))
            
            # Verify Redis was called to set the cache
            mock_redis_setex.assert_called_once()
    
    @patch('app.blueprints.GET_API.redis_client.get')
    def test_get_whois_info_cache_hit(self, mock_redis_get):
        # Setup mock
        mock_redis_get.return_value = json.dumps(self.whois_data).encode('utf-8')
        
        # Call the method
        result = self.service.get_whois_info("example.com")
        
        # Verify results
        self.assertEqual(result, self.whois_data)
        mock_redis_get.assert_called_once_with("whois:domain:example.com")

if __name__ == '__main__':
    unittest.main()
