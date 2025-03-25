import React, { useState } from 'react';
import axios from 'axios';
import './UnifiedSearch.css';

function UnifiedSearch() {
    const [query, setQuery] = useState('');
    const [results, setResults] = useState({
        emailResults: null,
        vtResults: null,
        shodanResults: null,
        domainResults: null
    });
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false);
    const [inputType, setInputType] = useState(null); // 'ip', 'email', 'domain'
    const [activeView, setActiveView] = useState('combined'); // 'combined', 'detailed'

    // Function to detect input type
    const detectInputType = (input) => {
        // IP address pattern
        const ipPattern = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
        // Email pattern
        const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        // Domain pattern (simple version)
        const domainPattern = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/;

        if (ipPattern.test(input)) return 'ip';
        if (emailPattern.test(input)) return 'email';
        if (domainPattern.test(input)) return 'domain';
        return null;
    };

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
        setLoading(true);
        
        // Reset results
        setResults({
            emailResults: null,
            vtResults: null,
            shodanResults: null,
            domainResults: null
        });

        // Detect input type
        const type = detectInputType(query);
        setInputType(type);

        if (!type) {
            setError('Invalid input format. Please enter a valid IP address, domain, or email.');
            setLoading(false);
            return;
        }

        try {
            // Make API calls based on input type
            if (type === 'ip') {
                // For IP lookups, get both VirusTotal and Shodan data
                const [vtResponse, shodanResponse] = await Promise.all([
                    axios.post('http://localhost:5000/api/v1/main/virustotal-lookup', { ip: query }),
                    axios.post('http://localhost:5000/api/v1/main/shodan-lookup', { query })
                ]);
                
                setResults({
                    ...results,
                    vtResults: vtResponse.data,
                    shodanResults: shodanResponse.data
                });
            } 
            else if (type === 'email') {
                // For email lookups, use the LeakCheck service
                const emailResponse = await axios.post('http://localhost:5000/api/v1/main/check-email', { email: query });
                setResults({
                    ...results,
                    emailResults: emailResponse.data
                });
            } 
            else if (type === 'domain') {
                // For domain lookups, use both Shodan and VirusTotal (if implemented)
                const shodanResponse = await axios.post('http://localhost:5000/api/v1/main/shodan-lookup', { query });
                
                // Note: You would need to implement a domain lookup in your backend for VirusTotal
                // For now, we'll just use Shodan for domains
                setResults({
                    ...results,
                    shodanResults: shodanResponse.data,
                    domainResults: shodanResponse.data // Using Shodan data for domains for now
                });
            }
        } catch (err) {
            console.error("API Error:", err);
            if (err.response?.data?.error) {
                setError(`Error: ${err.response.data.error}`);
            } else {
                setError('An error occurred during the lookup. The service may be unavailable.');
            }
        } finally {
            setLoading(false);
        }
    };

    // Render IP analysis results (VirusTotal + Shodan)
    const renderIPResults = () => {
        const { vtResults, shodanResults } = results;
        
        if (!vtResults && !shodanResults) return null;
        
        // This component reuses parts of the existing VirustotalLookup component
        return (
            <div className="results-section">
                <div className="result-header">
                    <h3>IP Intelligence Results</h3>
                    <div className="source-badges">
                        {vtResults && <span className="source-badge vt-badge">VirusTotal</span>}
                        {shodanResults && <span className="source-badge shodan-badge">Shodan</span>}
                    </div>
                </div>
                
                {/* Show VirusTotal results */}
                {vtResults && vtResults.data && vtResults.data.attributes && (
                    <div className="vt-results">
                        <div className="vt-summary">
                            <h4>IP Reputation</h4>
                            {renderReputationMeter(vtResults.data.attributes)}
                        </div>
                        
                        {/* Network and Geolocation Info */}
                        {renderVTNetworkInfo(vtResults.data.attributes)}
                        
                        {activeView === 'detailed' && renderVTDetailedInfo(vtResults.data.attributes)}
                    </div>
                )}
                
                {/* Show Shodan results */}
                {shodanResults && shodanResults.ip_str && (
                    <div className="shodan-results">
                        <div className="vt-info-section shodan-section">
                            <h4>Infrastructure Information</h4>
                            <div className="shodan-ip-info">
                                <p><strong>Organization:</strong> {shodanResults.org || 'Unknown'}</p>
                                <p><strong>ISP:</strong> {shodanResults.isp || 'Unknown'}</p>
                                <p><strong>Location:</strong> {shodanResults.country_name || 'Unknown'}, {shodanResults.city || 'Unknown'}</p>
                            </div>
                            
                            {/* Open Ports */}
                            {shodanResults.ports && shodanResults.ports.length > 0 && (
                                <div className="shodan-ports">
                                    <h5>Open Ports</h5>
                                    <div className="ports-list">
                                        {shodanResults.ports.map(port => (
                                            <span key={port} className="port-tag">{port}</span>
                                        ))}
                                    </div>
                                </div>
                            )}
                            
                            {/* Vulnerabilities */}
                            {shodanResults.vulns && Object.keys(shodanResults.vulns).length > 0 && (
                                <div className="shodan-vulns">
                                    <h5>Potential Vulnerabilities</h5>
                                    <ul className="vulns-list">
                                        {Object.keys(shodanResults.vulns).map(vuln => (
                                            <li key={vuln} className="vuln-item">
                                                <a href={`https://nvd.nist.gov/vuln/detail/${vuln}`} target="_blank" rel="noopener noreferrer">
                                                    {vuln}
                                                </a>
                                            </li>
                                        ))}
                                    </ul>
                                </div>
                            )}
                        </div>
                        
                        {/* Exposed Services (limited in combined view) */}
                        {shodanResults.data && shodanResults.data.length > 0 && (
                            <div className="vt-info-section">
                                <h4>Exposed Services</h4>
                                {activeView === 'combined' ? (
                                    <>
                                        {shodanResults.data.slice(0, 3).map((service, idx) => (
                                            <div key={idx} className="service-preview">
                                                <span className="service-port">Port {service.port}</span>
                                                <span className="service-product">{service.product || 'Unknown'} {service.version || ''}</span>
                                            </div>
                                        ))}
                                        {shodanResults.data.length > 3 && (
                                            <div className="more-services">
                                                <a href="#" onClick={(e) => {e.preventDefault(); setActiveView('detailed');}}>
                                                    Show all {shodanResults.data.length} services...
                                                </a>
                                            </div>
                                        )}
                                    </>
                                ) : (
                                    <div className="services-section">
                                        {shodanResults.data.map((service, idx) => (
                                            <div key={idx} className="service-card">
                                                <div className="service-header">
                                                    <h5>Port {service.port} ({service.transport || 'tcp'})</h5>
                                                    <span className="service-product">{service.product || 'Unknown'} {service.version || ''}</span>
                                                </div>
                                                {service.data && (
                                                    <div className="service-banner">
                                                        <pre>{service.data.substring(0, 300)}{service.data.length > 300 ? '...' : ''}</pre>
                                                    </div>
                                                )}
                                            </div>
                                        ))}
                                    </div>
                                )}
                            </div>
                        )}
                    </div>
                )}
                
                <div className="view-controls">
                    <button 
                        className={activeView === 'combined' ? 'active' : ''} 
                        onClick={() => setActiveView('combined')}>
                        Summary View
                    </button>
                    <button 
                        className={activeView === 'detailed' ? 'active' : ''} 
                        onClick={() => setActiveView('detailed')}>
                        Detailed View
                    </button>
                </div>
            </div>
        );
    };
    
    // Helper function to render the reputation meter
    const renderReputationMeter = (attributes) => {
        const stats = attributes.last_analysis_stats || {};
        const totalEngines = Object.values(stats).reduce((a, b) => a + b, 0);
        const malicious = stats.malicious || 0;
        const suspicious = stats.suspicious || 0;
        
        return (
            <div className="reputation-meter">
                <div className="reputation-bar">
                    <div 
                        className="malicious-bar" 
                        style={{ width: `${(malicious / totalEngines) * 100}%` }}
                    ></div>
                    <div 
                        className="suspicious-bar" 
                        style={{ width: `${(suspicious / totalEngines) * 100}%`, marginLeft: `${(malicious / totalEngines) * 100}%` }}
                    ></div>
                </div>
                <div className="reputation-stats">
                    <span className="stat-item malicious">
                        <strong>Malicious:</strong> {malicious}/{totalEngines}
                    </span>
                    <span className="stat-item suspicious">
                        <strong>Suspicious:</strong> {suspicious}/{totalEngines}
                    </span>
                    <span className="stat-item clean">
                        <strong>Clean:</strong> {stats.harmless || 0}/{totalEngines}
                    </span>
                </div>
            </div>
        );
    };
    
    // Helper function to render VirusTotal network information
    const renderVTNetworkInfo = (attributes) => {
        return (
            <div className="vt-info-section">
                <h4>Network Information</h4>
                <div className="info-grid">
                    {attributes.as_owner && <div className="info-item"><strong>AS Owner:</strong> {attributes.as_owner}</div>}
                    {attributes.asn && <div className="info-item"><strong>ASN:</strong> {attributes.asn}</div>}
                    {attributes.network && <div className="info-item"><strong>Network:</strong> {attributes.network}</div>}
                    {attributes.country && <div className="info-item"><strong>Country:</strong> {attributes.country}</div>}
                    {attributes.continent && <div className="info-item"><strong>Continent:</strong> {attributes.continent}</div>}
                </div>
                
                {/* Tags */}
                {attributes.tags && attributes.tags.length > 0 && (
                    <div className="tags-container">
                        {attributes.tags.map((tag, index) => (
                            <span key={index} className="ip-tag">{tag}</span>
                        ))}
                    </div>
                )}
            </div>
        );
    };
    
    // Helper function to render detailed VirusTotal information
    const renderVTDetailedInfo = (attributes) => {
        return (
            <>
                {/* Malicious/Suspicious vendors */}
                {attributes.last_analysis_results && (
                    <div className="vt-info-section">
                        <h4>Security Vendor Analysis</h4>
                        <div className="vendor-results">
                            {Object.entries(attributes.last_analysis_results)
                                .filter(([_, result]) => result.category === 'malicious' || result.category === 'suspicious')
                                .map(([vendor, result]) => (
                                    <div key={vendor} className={`vendor-item ${result.category}`}>
                                        <span className="vendor-name">{vendor}</span>
                                        <span className="vendor-result">{result.result || result.category}</span>
                                    </div>
                                ))}
                        </div>
                    </div>
                )}
                
                {/* WHOIS Information */}
                {attributes.whois && (
                    <div className="vt-info-section">
                        <h4>WHOIS Information</h4>
                        <pre className="whois-data">{attributes.whois}</pre>
                    </div>
                )}
            </>
        );
    };
    
    // Render domain analysis results
    const renderDomainResults = () => {
        const { shodanResults, domainResults } = results;
        
        if (!shodanResults && !domainResults) return null;
        
        return (
            <div className="results-section">
                <div className="result-header">
                    <h3>Domain Intelligence Results</h3>
                </div>
                
                {/* Domain search results from Shodan */}
                {shodanResults && shodanResults.matches && shodanResults.matches.length > 0 && (
                    <div className="vt-info-section">
                        <h4>Associated IP Addresses</h4>
                        <p>Found {shodanResults.matches.length} IP addresses associated with this domain:</p>
                        
                        <div className="domain-results">
                            {shodanResults.matches.map((match, idx) => (
                                <div key={idx} className="match-item">
                                    <h5>{match.ip_str}</h5>
                                    <p><strong>Hostnames:</strong> {match.hostnames?.join(', ') || 'None'}</p>
                                    <p><strong>Open Ports:</strong> {match.ports ? match.ports.join(', ') : 'None'}</p>
                                    <p><strong>ISP:</strong> {match.isp || 'Unknown'}</p>
                                    <p><strong>Location:</strong> {match.country_name || 'Unknown'}</p>
                                </div>
                            ))}
                        </div>
                    </div>
                )}
                
                {/* No results message */}
                {(!shodanResults || !shodanResults.matches || shodanResults.matches.length === 0) && (
                    <div className="no-results">
                        <p>No information found for this domain.</p>
                    </div>
                )}
            </div>
        );
    };
    
    // Render email breach check results
    const renderEmailResults = () => {
        const { emailResults } = results;
        
        if (!emailResults) return null;
        
        return (
            <div className="results-section">
                <div className="result-header">
                    <h3>Email Security Check Results</h3>
                </div>
                
                <div className="email-results-container">
                    {emailResults.breached ? (
                        <>
                            <div className="alert alert-danger">
                                <strong>Oh no!</strong> Your email was found in {emailResults.found} data breach(es).
                            </div>

                            {emailResults.exposed_data && emailResults.exposed_data.length > 0 && (
                                <div className="exposed-data">
                                    <h4>Exposed Information Types:</h4>
                                    <ul>
                                        {emailResults.exposed_data.map((field, index) => (
                                            <li key={index}>{field}</li>
                                        ))}
                                    </ul>
                                </div>
                            )}

                            <div className="breaches-list">
                                <h4>Breach Sources:</h4>
                                {emailResults.breaches.map((breach, index) => (
                                    <div key={index} className="breach-item">
                                        <h5>{breach.name}</h5>
                                        <p><strong>Date:</strong> {breach.date}</p>
                                    </div>
                                ))}
                            </div>
                        </>
                    ) : (
                        <div className="alert alert-success">
                            <strong>Good news!</strong> Your email wasn't found in any known data breaches.
                        </div>
                    )}
                </div>
            </div>
        );
    };

    return (
        <div className="unified-search-container">
            <h2>OSINT Intelligence Search</h2>
            <p className="search-description">
                Enter an IP address, domain, or email to discover security information, 
                exposed services, data breaches, and potential vulnerabilities.
            </p>

            <form onSubmit={handleSubmit} className="unified-search-form">
                <div className="search-input-container">
                    <input
                        type="text"
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        placeholder="Enter IP address, domain, or email..."
                        required
                        className="unified-search-input"
                    />
                    <button type="submit" disabled={loading} className="search-button">
                        {loading ? 'Searching...' : 'Search'}
                    </button>
                </div>
                
                <div className="search-tips">
                    <p>Examples: 8.8.8.8 (IP), example.com (domain), user@example.com (email)</p>
                </div>
            </form>

            {error && <div className="error-message">{error}</div>}

            <div className="results-container">
                {inputType === 'ip' && renderIPResults()}
                {inputType === 'domain' && renderDomainResults()}
                {inputType === 'email' && renderEmailResults()}
            </div>
        </div>
    );
}

export default UnifiedSearch;
