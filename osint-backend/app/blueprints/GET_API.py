from flask import Blueprint
import requests
import os
import json
import logging
from dotenv import load_dotenv
import re
import redis

classes = Blueprint('classes', __name__)

# Load environment variables
load_dotenv()
REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0') # TODO: Replace default with production URL

# Configure Logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Redis 
#TODO: WILL MIGRATE TO POSTGRES LATER
redis_client = redis.StrictRedis.from_url(REDIS_URL) # Strictredis does not provide backwards compatibility - use redis.Redis instead

# Cache TTL values (in seconds) #TODO: Move to config file
CACHE_TTL = {
    'default': 3600,		# 1 hour
    'email_breach': 86400,	# 1 day
    'ip_lookup': 3600,		# 1 hour
     'domain_lookup': 3600,	# 1 hour
    'email_lookup': 86400	# 1 day
}

class GET_API:
    
    def __init__(self, service_name):
        self.service_name = service_name
        self.api_key = os.getenv(f'{service_name.upper()}_API_KEY')
        if not self.api_key:
            logger.error(f"API key not found for service: {service_name}") # should not be happening, if it error occurs, please check .env
  
    def get_from_cache(self, cache_key):
        # Retrieve data from Redis cache
        try:
            cached_data = redis_client.get(cache_key)
            if cached_data:
                logger.info(f"Cache: Entry found for: {cache_key}")
                return json.loads(cached_data)
            logger.info(f"Cache: No entry found for: {cache_key}")
        except Exception as e:
            logger.error(f"Cache: Error retrieving `{cache_key}`from Redis cache: {str(e)}")
        return None

    def set_in_cache(self, cache_key, data, ttl=3600):
        """Store data in Redis cache with TTL"""
        try:
            redis_client.setex(
                cache_key,
                ttl,
                json.dumps(data)
            )
            logger.info(f"Stored data in cache with key: {cache_key}, TTL: {ttl}s")
        except Exception as e:
            logger.error(f"Failed to store data in Redis cache: {str(e)}")

    def make_api_request(self, endpoint, headers=None, params=None, json_data=None, 
                         method='GET', cache_ttl=None, cache_key_prefix=None): 
        # why is python a b**** and doesnt allow self.service_name as a default :<
        
        # Ensures that prefix will always be set
        cache_key_prefix = self.service_name if not cache_key_prefix else cache_key_prefix
        
        # create cache key for grabber
        cache_parts = [cache_key_prefix, endpoint]
        if params:
            sorted_params = sorted([(k, v) for k, v in params.items() if k != 'api_key' or k != 'key'])
            cache_parts.extend([f"{k}={v}" for k, v in sorted_params])
            
        cache_key = '::'.join(cache_parts)
        
        # Check cache
        cached_data = self.get_from_cache(cache_key)
        if cached_data:
            return cached_data
        
        # Add API key to headers or params if needed
        request_headers = headers or {}
        request_params = params or {}
        
        # Make the API request
        try:
            if method.upper() == 'GET':
                response = requests.get(
                    endpoint,
                    headers=request_headers,
                    params=request_params   # No need to manually format the query string, requests automatically parses it
                )
            elif method.upper() == 'POST':
                response = requests.post(
                    endpoint,
                    headers=request_headers,
                    params=request_params, # Same case, makes life much easier
                    json=json_data
                )
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            result = response.json()
            
            # Store in cache
            ttl = cache_ttl or CACHE_TTL.get(cache_key_prefix, CACHE_TTL['default'])
            self.set_in_cache(cache_key, result, ttl)
            
            return result
        
        except requests.exceptions.RequestException as e:
            logger.error(f"API request failed: {str(e)}")
            return {"error": f"API request failed: {str(e)}"}

class VirusTotalAPI(GET_API):
    
    def __init__(self):
        super().__init__('virustotal')
        self.base_url = 'https://www.virustotal.com/api/v3'
        self.headers = {"X-Apikey": self.api_key}
    
    def get_ip_report(self, ip):
        endpoint = f"{self.base_url}/ip_addresses/{ip}"
        cache_key_prefix = f"virustotal:ip:{ip}"
        
        return self.make_api_request(
            endpoint,
            headers = self.headers,
            cache_ttl = CACHE_TTL['ip_lookup'],
            cache_key_prefix = cache_key_prefix
        )
        
    def get_domain_report(self, domain):
        endpoint = f"{self.base_url}/domains/{domain}"
        cache_key_prefix = f"virustotal:domain:{domain}"
        
        return self.make_api_request(
            endpoint,
            headers = self.headers,
            cache_ttl = CACHE_TTL['domain_lookup'],
            cache_key_prefix = cache_key_prefix
        )
        
    def get_email_report(self, email):
        endpoint = f"{self.base_url}/search"
        cache_key_prefix = f"virustotal:email:{email}"
        
        return self.make_api_request(
            endpoint=endpoint,
            headers=self.headers,
            params={"query": email},
            cache_ttl=CACHE_TTL['email_lookup'],
            cache_key_prefix=cache_key_prefix
        )
        
    def lookup_query(self, query):
        # Look up generic query - automatically detects if it's an IP, domain, or email
        try:
            if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', query):
                return self.get_ip_report(query)
            elif '@' in query:                          # Exact regex i have no idea #TODO: implement proper regex check
                return self.get_email_report(query)
            elif '.' in query:                          # Exact regex i have no idea #TODO: implement proper regex check
                return self.get_domain_report(query)
            else:
                return {'error': 'No valid query type'}
        except Exception as e:
            logger.error(f"VirusTotal lookup error: {str(e)}")
            return {'error': str(e)}

class ShodanAPI(GET_API):
    
    def __init__(self):
        super().__init__('shodan')
        self.base_url = "https://api.shodan.io/shodan"
    
    def get_ip_report(self, ip):
        endpoint = f"{self.base_url}/host/{ip}"
        cache_key_prefix = f"shodan:ip:{ip}"
        
        return self.make_api_request(
            endpoint=endpoint,
            params={"key": self.api_key},
            cache_ttl=CACHE_TTL['ip_lookup'],
            cache_key_prefix=cache_key_prefix
        )
    
    def get_domain_report(self, domain):
        endpoint = f"{self.base_url}/host/search"
        cache_key_prefix = f"shodan:domain:{domain}"
        
        return self.make_api_request(
            endpoint=endpoint,
            params={
                "key": self.api_key,
                "query": f"hostname:{domain}"
            },
            cache_ttl=CACHE_TTL['domain_lookup'],
            cache_key_prefix=cache_key_prefix
        )
        
    def lookup_query(self, query):
        # Look up generic query - automatically detects if it's an IP or domain
        try:
            if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', query):
                return self.get_ip_report(query)
            elif '.' in query:                          # Exact regex i have no idea, refer to #VIRUS_TOTAL for the domain regex #TODO: copy regex from VIRUS_TOTAL
                return self.get_domain_report(query)
            else:
                return {"error": "No valid query type"}
        except Exception as e:
            logger.error(f"Shodan lookup error: {str(e)}")
            return {'error': str(e)}
        
class LeakCheckAPI(GET_API):
    
    def __init__(self):
        super().__init__('leakcheck')
        self.base_url = "https://leakcheck.io/api/public"
        
    def get_email_report(self, email):
        # endpoint = self.base_url
        cache_key_prefix = f"leakcheck:email:{email}"
        
        response = self.make_api_request(
            endpoint = self.base_url,
            params = {
                'key' : self.api_key,
                'check' : email
            },
            cache_ttl = CACHE_TTL['email_lookup'],
            cache_key_prefix = cache_key_prefix
        )
        
        # Format the response to match existing schema # TODO: Fixed schema across all 'email' objects
        if not response.get('success'):
            raise Exception(response.get('message', 'Unknown error from LeakCheck API'))
        
        return {
            "breached": response.get('found', 0) > 0,
            "found": response.get('found', 0),
            "exposed_data": response.get('fields', []),
            "breaches": response.get('sources', [])
        }
        
    def lookup_query(self, query):
        try:
            if '@' in query:
                return self.get_email_report(query)
            else:
                return {'error': 'No valid query type'}
        except Exception as e:
            logger.error(f"LeakCheck lookup error: {str(e)}")
            return {'error': str(e)}
        
class URLScanAPI(GET_API):
    
    def __init__(self):
        super().__init__('urlscan')
        self.base_url = "https://urlscan.io/api/v1"
        
    def get_url_report(self, domain):
        endpoint = f"{self.base_url}/scan/"
        cache_key_prefix = f"urlscan:domain:{domain}"
        
        headers = {"API-Key": self.api_key, "Content-Type": "application/json"}
        scan_data = {"url": domain, "visibility": "public"}
        
        return self.make_api_request(
            endpoint=f"{self.base_url}/scan/",
            headers=headers,
            json_data=scan_data,
            method='POST',
            cache_ttl=CACHE_TTL['domain_lookup'],
            cache_key_prefix=cache_key_prefix
        )
        
    def lookup_query(self, query):
        try:
            if '.' in query:
                return self.get_url_report(query)
            else:
                return 'No valid query type'
        except Exception as e:
            logger.error(f"URLScan lookup error: {str(e)}")
            return {'error': str(e)}
        
class AbuseIPDBAPI(GET_API):
    def __init__(self):
        super().__init__('abuseipdb')
        self.base_url = "https://api.abuseipdb.com/api/v2"
        
    def get_ip_report(self, ip):
        endpoint = f"{self.base_url}/check"
        cache_key_prefix = f"abuseipdb:ip:{ip}"
        
        headers = {
            'Accept': 'application/json',
            'Key': self.api_key
        }
        
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,
            'verbose': True
        }
        
        return self.make_api_request(
            endpoint=endpoint,
            headers=headers,
            params=params,
            cache_ttl=CACHE_TTL['ip_lookup'],
            cache_key_prefix=cache_key_prefix
        )
    
    def lookup_query(self, query):
        try:
            if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', query):
                return self.get_ip_report(query)
            else:
                return 'No valid query type'
        except Exception as e:
            logger.error(f"AbuseIPDB lookup error: {str(e)}")
            return {'error': str(e)}
        
# Helper classes for local services
class DNSService:
    
    def __init__(self):
        self.cache_ttl = CACHE_TTL['domain_lookup']
        
    def get_dns_records(self, domain):
        """Look up DNS records for a domain"""
        cache_key = f"dns:domain:{domain}"
        
        # Check cache first
        cached_result = redis_client.get(cache_key)
        if cached_result:
            return json.loads(cached_result)
        
        try:
            import dns.resolver
            result = {}
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME']
            
            for record_type in record_types:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    result[record_type] = [str(answer) for answer in answers]
                except dns.resolver.NoAnswer:
                    result[record_type] = []
                except Exception as e:
                    result[record_type] = [f"Error: {str(e)}"]
            
            # Cache the result
            redis_client.setex(cache_key, self.cache_ttl, json.dumps(result))
            
            return result
        except Exception as e:
            logger.error(f"DNS lookup error: {str(e)}")
            return {"error": str(e)}
        
class WHOISService:
    
    def __init__(self):
        self.cache_ttl = CACHE_TTL['domain_lookup']
        
    def get_whois_info(self, domain):
        """Look up WHOIS information for a domain"""
        cache_key = f"whois:domain:{domain}"
        
        # Check cache first
        cached_result = redis_client.get(cache_key)
        if cached_result:
            return json.loads(cached_result)
        
        try:
            import whois
            result = whois.whois(domain)
            
            # Convert complex objects to strings for JSON serialization
            whois_data = {
                "domain_name": result.domain_name,
                "registrar": result.registrar,
                "creation_date": str(result.creation_date),
                "expiration_date": str(result.expiration_date),
                "updated_date": str(result.updated_date),
                "name_servers": result.name_servers,
                "status": result.status,
                "emails": result.emails,
                "registrant": result.registrant,
                "admin": result.admin,
                "tech": result.tech,
                "raw": result.text
            }
            
            # Cache the result
            redis_client.setex(cache_key, self.cache_ttl, json.dumps(whois_data))
            
            return whois_data
        
        except Exception as e:
            logger.error(f"WHOIS error: {str(e)}")
            return {"error": str(e)}