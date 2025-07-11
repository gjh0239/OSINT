import unittest
from unittest.mock import patch, MagicMock
import json
import os
import sys
from dotenv import load_dotenv

# Add the app directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.blueprints.GET_API import URLScanAPI

class TestURLScanAPI(unittest.TestCase):

    def setUp(self):
        # Load environment variables for API keys
        load_dotenv()
        self.api = URLScanAPI()
        
        # Sample responses for mocking
        self.scan_submission_response = {
            "message": "Submission successful",
            "uuid": "test-uuid-12345",
            "result": "https://urlscan.io/result/test-uuid-12345/",
            "api": "https://urlscan.io/api/v1/result/test-uuid-12345/"
        }
        
        self.scan_result_response = {
            "task": {
                "uuid": "test-uuid-12345",
                "url": "https://example.com",
                "visibility": "public",
                "screenshotURL": "https://urlscan.io/screenshots/test-uuid-12345.png"
            },
            "page": {
                "url": "https://example.com",
                "domain": "example.com",
                "ip": "93.184.216.34",
                "title": "Example Domain",
                "asnname": "EDGECAST-NETBLK-03"
            },
            "stats": {
                "resourceStats": {"total": 1}
            },
            "ips": ["93.184.216.34"],
            "domains": ["example.com"],
            "countries": ["US"]
        }
        
    @patch('app.blueprints.GET_API.GET_API.make_api_request')
    @patch('app.blueprints.GET_API.GET_API.get_from_cache')
    @patch('app.blueprints.GET_API.GET_API.set_in_cache')
    @patch('time.sleep')  # Mock sleep to speed up tests 
    def test_get_url_report_success(self, mock_sleep, mock_set_cache, mock_get_cache, mock_request):
        # Setup mocks
        mock_get_cache.return_value = None  # No cache hit
        mock_request.side_effect = [
            self.scan_submission_response,  # First call - scan submission
            self.scan_result_response       # Second call - result retrieval
        ]
        
        # Call the method
        result = self.api.get_url_report("example.com", initial_wait=1)
        
        # Verify results
        self.assertIsNotNone(result)
        self.assertIn("summary", result)
        self.assertIn("page_title", result)
        self.assertEqual(result["page_title"], "Example Domain")
        self.assertEqual(result["summary"]["ip"], "93.184.216.34")
        self.assertEqual(result["summary"]["domain"], "example.com")
        
        # Verify API was called twice
        self.assertEqual(mock_request.call_count, 2)
        
        # Verify the result was cached
        mock_set_cache.assert_called_once()
        
    @patch('app.blueprints.GET_API.GET_API.make_api_request')
    @patch('app.blueprints.GET_API.GET_API.get_from_cache')
    @patch('time.sleep')  # Mock sleep to speed up tests
    def test_get_url_report_cached(self, mock_sleep, mock_get_cache, mock_request):
        # Setup cache hit
        cached_result = {
            "summary": {"domain": "example.com"},
            "page_title": "Cached Example"
        }
        mock_get_cache.return_value = cached_result
        
        # Call the method
        result = self.api.get_url_report("example.com")
        
        # Verify cached result was returned
        self.assertEqual(result, cached_result)
        
        # Verify API was NOT called
        mock_request.assert_not_called()
    
    @patch('app.blueprints.GET_API.GET_API.make_api_request')
    @patch('app.blueprints.GET_API.GET_API.get_from_cache')
    @patch('time.sleep')  # Mock sleep to speed up tests
    def test_get_url_report_error(self, mock_sleep, mock_get_cache, mock_request):
        # Setup mocks
        mock_get_cache.return_value = None  # No cache hit
        # First call succeeds, then timeout errors
        mock_request.side_effect = [
            self.scan_submission_response,  # First call - successful scan submission
            {"status": "pending"},          # Still processing
            {"status": "pending"},          # Still processing
            {"status": "pending"}           # Still processing (will time out)
        ]
        
        # Call the method with fewer retries for faster test
        result = self.api.get_url_report("example.com", max_retries=3, initial_wait=1)
        
        # Verify error response
        self.assertIn("error", result)
        self.assertIn("uuid", result)
        self.assertEqual(result["uuid"], "test-uuid-12345")
        
        # Verify correct number of API calls (1 submission + 3 result checks)
        self.assertEqual(mock_request.call_count, 4)

if __name__ == '__main__':
    unittest.main()