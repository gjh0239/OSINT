# OSINT Intelligence Tool

A comprehensive cybersecurity intelligence tool that aggregates data from multiple threat intelligence sources to provide insights on IP addresses, domains, and email addresses.

![OSINT Intelligence Tool](https://via.placeholder.com/800x400?text=OSINT+Intelligence+Tool)

## Overview

This OSINT (Open Source Intelligence) tool allows security analysts and researchers to quickly gather intelligence about potential threats by querying multiple security APIs through a single unified interface. The application provides detailed analysis for:

- **IP addresses**: Reputation, geolocation, exposed services, and vulnerabilities
- **Domain names**: WHOIS information, DNS records, security scanning, and risk assessment
- **Email addresses**: Data breach information and exposure analysis

## Features

- **Unified Search**: Single query interface for all intelligence sources
- **Multi-target Analysis**: Process comma-separated lists of IPs, domains, or emails
- **Rich Visualization**: Structured presentation of complex security data
- **API Usage Tracking**: Monitor consumption of external API services
- **Caching**: Redis-based caching to reduce redundant API calls
- **Dockerized Deployment**: Easy deployment with containerization

## Architecture

The application follows a modern microservices architecture:

- **Frontend**: React-based UI with responsive design
- **Backend**: Flask API with modular design for intelligence sources
- **Cache**: Redis for response caching to improve performance
- **Docker**: Container orchestration for all components

## Intelligence Sources

The tool integrates with the following intelligence sources:

| Source | Type | Information Provided |
|--------|------|----------------------|
| VirusTotal | IP, Domain, Email | Reputation, malware detection, categorization |
| Shodan | IP, Domain | Open ports, services, vulnerabilities, banners |
| LeakCheck | Email | Data breach history, exposed credentials |
| AbuseIPDB | IP | Abuse reports, confidence score |
| URLScan | Domain | Web scanning, screenshot capture |
| WHOIS | Domain | Registration information, contacts |
| DNS | Domain | DNS records (A, AAAA, MX, TXT, etc.) |

## Installation

### Prerequisites

- Docker and Docker Compose
- API keys for all intelligence sources

### Using Docker (Recommended)

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/osint-tool.git
   cd osint-tool
   ```

2. Configure environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

3. Start the application:
   ```bash
   docker-compose up -d
   ```

4. Access the application at [http://localhost:3000](http://localhost:3000)

### Manual Setup

#### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd osint-backend
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Configure environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

5. Run the application:
   ```bash
   flask run
   ```

#### Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd osint-frontend
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Configure environment variables:
   ```bash
   cp .env.example .env
   # Edit .env with your API keys
   ```

4. Run the application:
   ```bash
   npm start
   ```

## Configuration

### Environment Variables

#### Backend (.env)

```
SHODAN_API_KEY=your_shodan_api_key
LEAKCHECK_API_KEY=your_leakcheck_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
URLSCAN_API_KEY=your_urlscan_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
REDIS_URL=redis://localhost:6379/0
FLASK_ENV=development
```

#### Frontend (.env)

```
REACT_APP_BACKEND_URL=http://localhost:5000/api/v1/main
```

### Docker Environment Variables

Additional environment variables for Docker deployment:

```
FLASK_ENV=production
REDIS_DOCKER_URL=redis://redis:6379/0
APP_DEBUG=false
FRONTEND_PORT=3000
```

## Usage

### Unified Search

1. Enter an IP address, domain, or email in the search box
2. For batch processing, enter multiple targets separated by commas
3. View the results in the unified interface
4. Toggle between summary and detailed views
5. Analyze results from each intelligence source

### Example Queries

- IP addresses: `8.8.8.8` or `1.1.1.1,8.8.8.8`
- Domains: `example.com` or `example.com,example.org`
- Emails: `user@example.com` or `user1@example.com,user2@example.com`

## API Reference

### Unified Search Endpoint

```
POST /api/v1/main/unified-search
Content-Type: application/json

{
  "query": "8.8.8.8"
}
```

Response:
```json
{
  "results": {
    "8.8.8.8": {
      "type": "ip",
      "virustotal": { ... },
      "shodan": { ... },
      "abuseipdb": { ... }
    }
  },
  "api_usage": {
    "virustotal_ip": 1,
    "shodan": 1,
    "abuseipdb": 1,
    "total_calls": 3
  },
  "errors": [],
  "query_count": 1,
  "success_count": 1
}
```

## Development

### Project Structure

```
osint-tool/
├── docker-compose.yml
├── .env
├── osint-backend/
│   ├── app/
│   │   ├── blueprints/
│   │   │   ├── main.py
│   │   │   └── GET_API.py
│   │   └── __init__.py
│   ├── requirements.txt
│   └── Dockerfile
└── osint-frontend/
    ├── public/
    ├── src/
    │   ├── components/
    │   │   ├── UnifiedSearch.js
    │   │   └── UnifiedSearch.css
    │   ├── config.js
    │   └── App.js
    ├── .env
    └── Dockerfile
```

### Class Hierarchy

The backend uses an OOP approach with a base class for API interactions:

```
GET_API (Base class)
├── VirusTotalAPI
├── ShodanAPI
├── LeakCheckAPI
├── URLScanAPI
└── AbuseIPDBAPI
```

Additional service classes:
- DNSService
- WHOISService

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [VirusTotal](https://www.virustotal.com/)
- [Shodan](https://www.shodan.io/)
- [LeakCheck](https://leakcheck.io/)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [URLScan](https://urlscan.io/)

---

Built with ❤️ by your dearest interns :O