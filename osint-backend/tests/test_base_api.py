import unittest
from unittest.mock import patch, MagicMock
import json
import os
import sys
import requests
from dotenv import load_dotenv

# Add the app directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.blueprints.GET_API import GET_API

class TestBaseAPI(unittest.TestCase):

    def setUp(self):
        # Load environment variables for API keys
        load_dotenv()
        self.api = GET_API('test_service')
        
        # Sample response for mocking
        self.sample_response = {"data": "test_data"}
    
    @patch('app.blueprints.GET_API.redis_client.get')
    def test_get_from_cache_hit(self, mock_redis_get):
        # Setup mock
        mock_redis_get.return_value = json.dumps(self.sample_response).encode('utf-8')
        
        # Call the method
        result = self.api.get_from_cache("test_key")
        
        # Verify results
        self.assertEqual(result, self.sample_response)
        mock_redis_get.assert_called_once_with("test_key")
    
    @patch('app.blueprints.GET_API.redis_client.get')
    def test_get_from_cache_miss(self, mock_redis_get):
        # Setup mock
        mock_redis_get.return_value = None
        
        # Call the method
        result = self.api.get_from_cache("test_key")
        
        # Verify results
        self.assertIsNone(result)
        mock_redis_get.assert_called_once_with("test_key")
    
    @patch('app.blueprints.GET_API.redis_client.setex')
    def test_set_in_cache(self, mock_redis_setex):
        # Call the method
        self.api.set_in_cache("test_key", self.sample_response, 3600)
        
        # Verify results
        mock_redis_setex.assert_called_once_with(
            "test_key", 
            3600, 
            json.dumps(self.sample_response)
        )
    
    @patch('app.blueprints.GET_API.requests.get')
    @patch('app.blueprints.GET_API.GET_API.get_from_cache')
    @patch('app.blueprints.GET_API.GET_API.set_in_cache')
    def test_make_api_request_get(self, mock_set_cache, mock_get_cache, mock_requests_get):
        # Setup mocks
        mock_get_cache.return_value = None
        mock_response = MagicMock()
        mock_response.json.return_value = self.sample_response
        mock_requests_get.return_value = mock_response
        
        # Call the method
        result = self.api.make_api_request(
            endpoint="https://jsonplaceholder.typicode.com/posts/1",
            headers={"Accept": "application/json"},
            params={"userId": "1"}
        )
        
        # Verify results
        self.assertEqual(result, self.sample_response)
        mock_requests_get.assert_called_once()
        mock_set_cache.assert_called_once()
    
    @patch('app.blueprints.GET_API.requests.post')
    @patch('app.blueprints.GET_API.GET_API.get_from_cache')
    @patch('app.blueprints.GET_API.GET_API.set_in_cache')
    def test_make_api_request_post(self, mock_set_cache, mock_get_cache, mock_requests_post):
        # Setup mocks
        mock_get_cache.return_value = None
        mock_response = MagicMock()
        mock_response.json.return_value = self.sample_response
        mock_requests_post.return_value = mock_response
        
        # Call the method
        result = self.api.make_api_request(
            endpoint="https://jsonplaceholder.typicode.com/posts",
            method="POST",
            json_data={"title": "test", "body": "test content", "userId": 1}
        )
        
        # Verify results
        self.assertEqual(result, self.sample_response)
        mock_requests_post.assert_called_once()
        mock_set_cache.assert_called_once()

    @patch('app.blueprints.GET_API.GET_API.get_from_cache')
    def test_make_api_request_cached(self, mock_get_cache):
        # Setup cache hit
        mock_get_cache.return_value = self.sample_response
        
        # Call the method
        result = self.api.make_api_request(endpoint="https://jsonplaceholder.typicode.com/posts/1")
        
        # Verify results
        self.assertEqual(result, self.sample_response)

    @patch('app.blueprints.GET_API.requests.get')
    @patch('app.blueprints.GET_API.GET_API.get_from_cache')
    def test_make_api_request_error(self, mock_get_cache, mock_requests_get):
        # Setup mocks
        mock_get_cache.return_value = None
        mock_requests_get.side_effect = requests.exceptions.RequestException("API request failed")
        
        # Call the method
        result = self.api.make_api_request(endpoint="https://jsonplaceholder.typicode.com/nonexistent")
        
        # Verify results
        self.assertIn("error", result)

if __name__ == '__main__':
    unittest.main()
