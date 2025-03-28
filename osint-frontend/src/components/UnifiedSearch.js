import React, { useState } from 'react';
import axios from 'axios';
import './UnifiedSearch.css';

function UnifiedSearch() {
    const [query, setQuery] = useState('');
    const [results, setResults] = useState(null);
    const [error, setError] = useState(null);
    const [loading, setLoading] = useState(false);
    const [activeView, setActiveView] = useState('combined'); // 'combined', 'detailed'
    const [apiStats, setApiStats] = useState(null);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError(null);
        setLoading(true);
        
        // Reset results
        setResults(null);
        setApiStats(null);

        // Sanitize input - trim whitespace
        const sanitizedQuery = query.trim();
        
        if (!sanitizedQuery) {
            setError('Please enter a search query');
            setLoading(false);
            return;
        }

        try {
            // Call the unified search endpoint
            const response = await axios.post('http://10.77.252.160:5000/api/v1/main/unified-search', { 
                query: sanitizedQuery 
            });
            
            // Store the results and API usage statistics
            setResults(response.data.results);
            setApiStats(response.data.api_usage);
            
            // Display any errors returned from the backend
            if (response.data.errors && response.data.errors.length > 0) {
                setError(`${response.data.errors.length} error(s): ${response.data.errors.join('; ')}`);
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

    // Render all search results
    const renderSearchResults = () => {
        if (!results || Object.keys(results).length === 0) {
            return (
                <div className="no-results">
                    <p>No results found.</p>
                </div>
            );
        }

        return (
            <>
                {/* Display API-specific errors if any */}
                {renderApiErrors()}

                {/* Display API usage statistics */}
                {apiStats && (
                    <div className="api-stats-section">
                        <h4>API Calls Summary</h4>
                        <div className="api-stats-grid">
                            <div className="api-stat-item">
                                <span className="stat-label">Total API Calls:</span>
                                <span className="stat-value">{apiStats.total_calls}</span>
                            </div>
                            {apiStats.virustotal_ip > 0 && (
                                <div className="api-stat-item">
                                    <span className="stat-label">VirusTotal IP:</span>
                                    <span className="stat-value">{apiStats.virustotal_ip}</span>
                                </div>
                            )}
                            {apiStats.virustotal_domain > 0 && (
                                <div className="api-stat-item">
                                    <span className="stat-label">VirusTotal Domain:</span>
                                    <span className="stat-value">{apiStats.virustotal_domain}</span>
                                </div>
                            )}
                            {apiStats.shodan > 0 && (
                                <div className="api-stat-item">
                                    <span className="stat-label">Shodan:</span>
                                    <span className="stat-value">{apiStats.shodan}</span>
                                </div>
                            )}
                            {apiStats.leakcheck > 0 && (
                                <div className="api-stat-item">
                                    <span className="stat-label">LeakCheck:</span>
                                    <span className="stat-value">{apiStats.leakcheck}</span>
                                </div>
                            )}
                            {apiStats.abuseipdb > 0 && (
                                <div className="api-stat-item">
                                    <span className="stat-label">AbuseIPDB:</span>
                                    <span className="stat-value">{apiStats.abuseipdb}</span>
                                </div>
                            )}
                            {apiStats.whois > 0 && (
                                <div className="api-stat-item">
                                    <span className="stat-label">WHOIS:</span>
                                    <span className="stat-value">{apiStats.whois}</span>
                                </div>
                            )}
                            {apiStats.dns > 0 && (
                                <div className="api-stat-item">
                                    <span className="stat-label">DNS:</span>
                                    <span className="stat-value">{apiStats.dns}</span>
                                </div>
                            )}
                            {apiStats.urlscan > 0 && (
                                <div className="api-stat-item">
                                    <span className="stat-label">URLScan:</span>
                                    <span className="stat-value">{apiStats.urlscan}</span>
                                </div>
                            )}
                        </div>
                    </div>
                )}

                {/* Display individual result sections */}
                {Object.keys(results).map(key => {
                    const resultItem = results[key];
                    
                    switch(resultItem.type) {
                        case 'ip':
                            return renderIPResult(key, resultItem);
                        case 'email':
                            return renderEmailResult(key, resultItem);
                        case 'domain':
                            return renderDomainResult(key, resultItem);
                        default:
                            return null;
                    }
                })}
            </>
        );
    };
    
    // New function to render API-specific errors
    const renderApiErrors = () => {
        if (!error) return null;
        
        // Extract errors from the error message if it contains multiple errors
        const errorString = error.toString();
        if (errorString.includes('error(s):')) {
            const errorParts = errorString.split(': ');
            if (errorParts.length > 1) {
                const errorsList = errorParts[1].split('; ');
                
                return (
                    <div className="api-errors-section">
                        <h4>API Errors</h4>
                        <ul className="api-errors-list">
                            {errorsList.map((err, index) => (
                                <li key={index} className="api-error-item">{err}</li>
                            ))}
                        </ul>
                    </div>
                );
            }
        }
        
        return null;
    };

    // Render IP analysis result
    const renderIPResult = (ip, data) => {
        const vtData = data.virustotal?.data;
        const shodanData = data.shodan;
        const abuseipdbData = data.abuseipdb?.data;
        
        return (
            <div key={ip} className="results-section">
                <div className="result-header">
                    <h3>IP Intelligence: {ip}</h3>
                    <div className="source-badges">
                        {vtData && <span className="source-badge vt-badge">VirusTotal</span>}
                        {shodanData && <span className="source-badge shodan-badge">Shodan</span>}
                        {abuseipdbData && <span className="source-badge abuseipdb-badge">AbuseIPDB</span>}
                    </div>
                </div>
                
                {/* Show VirusTotal results */}
                {vtData && vtData.attributes && (
                    <div className="vt-results">
                        <div className="vt-summary">
                            <h4>IP Reputation</h4>
                            {renderReputationMeter(vtData.attributes)}
                        </div>
                        
                        {/* Network and Geolocation Info */}
                        {renderVTNetworkInfo(vtData.attributes)}
                        
                        {activeView === 'detailed' && renderVTDetailedInfo(vtData.attributes)}
                    </div>
                )}
                
                {/* Show AbuseIPDB results */}
                {abuseipdbData && (
                    <div className="vt-info-section abuseipdb-section">
                        <h4>IP Abuse History</h4>
                        <div className="abuseipdb-summary">
                            <div className="abuse-score">
                                <strong>Abuse Confidence Score:</strong> 
                                <span className={`score-value ${abuseipdbData.abuseConfidenceScore > 50 ? 'high-risk' : 
                                    abuseipdbData.abuseConfidenceScore > 20 ? 'medium-risk' : 'low-risk'}`}>
                                    {abuseipdbData.abuseConfidenceScore}%
                                </span>
                            </div>
                            <div className="abuse-details">
                                <p><strong>Total Reports:</strong> {abuseipdbData.totalReports || 0}</p>
                                <p><strong>Last Reported:</strong> {abuseipdbData.lastReportedAt || 'Never'}</p>
                                <p><strong>Usage Type:</strong> {abuseipdbData.usageType || 'Unknown'}</p>
                                <p><strong>ISP:</strong> {abuseipdbData.isp || 'Unknown'}</p>
                            </div>
                        </div>
                    </div>
                )}
                
                {/* Show Shodan results */}
                {shodanData && shodanData.ip_str && (
                    <div className="shodan-results">
                        <div className="vt-info-section shodan-section">
                            <h4>Infrastructure Information</h4>
                            <div className="shodan-ip-info">
                                <p><strong>Organization:</strong> {shodanData.org || 'Unknown'}</p>
                                <p><strong>ISP:</strong> {shodanData.isp || 'Unknown'}</p>
                                <p><strong>Location:</strong> {shodanData.country_name || 'Unknown'}, {shodanData.city || 'Unknown'}</p>
                            </div>
                            
                            {/* Open Ports */}
                            {shodanData.ports && shodanData.ports.length > 0 && (
                                <div className="shodan-ports">
                                    <h5>Open Ports</h5>
                                    <div className="ports-list">
                                        {shodanData.ports.map(port => (
                                            <span key={port} className="port-tag">{port}</span>
                                        ))}
                                    </div>
                                </div>
                            )}
                            
                            {/* Vulnerabilities */}
                            {shodanData.vulns && Object.keys(shodanData.vulns).length > 0 && (
                                <div className="shodan-vulns">
                                    <h5>Potential Vulnerabilities</h5>
                                    <ul className="vulns-list">
                                        {Object.keys(shodanData.vulns).map(vuln => (
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
                        {shodanData.data && shodanData.data.length > 0 && (
                            <div className="vt-info-section">
                                <h4>Exposed Services</h4>
                                {activeView === 'combined' ? (
                                    <>
                                        {shodanData.data.slice(0, 3).map((service, idx) => (
                                            <div key={idx} className="service-preview">
                                                <span className="service-port">Port {service.port}</span>
                                                <span className="service-product">{service.product || 'Unknown'} {service.version || ''}</span>
                                            </div>
                                        ))}
                                        {shodanData.data.length > 3 && (
                                            <div className="more-services">
                                                <a href="#" onClick={(e) => {e.preventDefault(); setActiveView('detailed');}}>
                                                    Show all {shodanData.data.length} services...
                                                </a>
                                            </div>
                                        )}
                                    </>
                                ) : (
                                    <div className="services-section">
                                        {shodanData.data.map((service, idx) => (
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

    // Render email result
    const renderEmailResult = (email, data) => {
        const emailData = data.leakcheck;
        
        if (!emailData) return null;
        
        return (
            <div key={email} className="results-section">
                <div className="result-header">
                    <h3>Email Security: {email}</h3>
                </div>
                
                <div className="email-results-container">
                    {emailData.breached ? (
                        <>
                            <div className="alert alert-danger">
                                <strong>Oh no!</strong> This email was found in {emailData.found} data breach(es).
                            </div>

                            {emailData.exposed_data && emailData.exposed_data.length > 0 && (
                                <div className="exposed-data">
                                    <h4>Exposed Information Types:</h4>
                                    <ul>
                                        {emailData.exposed_data.map((field, index) => (
                                            <li key={index}>{field}</li>
                                        ))}
                                    </ul>
                                </div>
                            )}

                            <div className="breaches-list">
                                <h4>Breach Sources:</h4>
                                {emailData.breaches.map((breach, index) => (
                                    <div key={index} className="breach-item">
                                        <h5>{breach.name}</h5>
                                        <p><strong>Date:</strong> {breach.date}</p>
                                    </div>
                                ))}
                            </div>
                        </>
                    ) : (
                        <div className="alert alert-success">
                            <strong>Good news!</strong> This email wasn't found in any known data breaches.
                        </div>
                    )}
                </div>
            </div>
        );
    };

    // Render domain result
    const renderDomainResult = (domain, data) => {
        const vtData = data.virustotal?.data;
        const shodanData = data.shodan;
        const whoisData = data.whois;
        const dnsData = data.dns;
        const urlscanData = data.urlscan;
        
        return (
            <div key={domain} className="results-section">
                <div className="result-header">
                    <h3>Domain Intelligence: {domain}</h3>
                    <div className="source-badges">
                        {vtData && <span className="source-badge vt-badge">VirusTotal</span>}
                        {shodanData && <span className="source-badge shodan-badge">Shodan</span>}
                        {whoisData && <span className="source-badge whois-badge">WHOIS</span>}
                        {dnsData && <span className="source-badge dns-badge">DNS</span>}
                        {urlscanData && <span className="source-badge urlscan-badge">URLScan</span>}
                    </div>
                </div>
                
                {/* VT Domain Info if available */}
                {vtData && vtData.attributes && (
                    <div className="vt-info-section">
                        <h4>Domain Reputation</h4>
                        {vtData.attributes.last_analysis_stats && renderReputationMeter(vtData.attributes)}
                        
                        {/* Domain categories */}
                        {vtData.attributes.categories && Object.keys(vtData.attributes.categories).length > 0 && (
                            <div className="domain-categories">
                                <h5>Categories:</h5>
                                <div className="tags-container">
                                    {Object.entries(vtData.attributes.categories).map(([source, category], index) => (
                                        <span key={index} className="ip-tag">
                                            {category} ({source})
                                        </span>
                                    ))}
                                </div>
                            </div>
                        )}
                    </div>
                )}
                
                {/* WHOIS Information */}
                {whoisData && !whoisData.error && (
                    <div className="vt-info-section whois-section">
                        <h4>WHOIS Information</h4>
                        <div className="whois-grid">
                            {whoisData.registrar && (
                                <div className="whois-item">
                                    <strong>Registrar:</strong> {whoisData.registrar}
                                </div>
                            )}
                            {whoisData.creation_date && (
                                <div className="whois-item">
                                    <strong>Created:</strong> {whoisData.creation_date}
                                </div>
                            )}
                            {whoisData.expiration_date && (
                                <div className="whois-item">
                                    <strong>Expires:</strong> {whoisData.expiration_date}
                                </div>
                            )}
                            {whoisData.name_servers && whoisData.name_servers.length > 0 && (
                                <div className="whois-item">
                                    <strong>Name Servers:</strong> {Array.isArray(whoisData.name_servers) ? 
                                        whoisData.name_servers.join(', ') : whoisData.name_servers}
                                </div>
                            )}
                        </div>
                        
                        {activeView === 'detailed' && whoisData.raw && (
                            <div className="raw-whois">
                                <h5>Raw WHOIS Data:</h5>
                                <pre className="whois-data">{whoisData.raw}</pre>
                            </div>
                        )}
                    </div>
                )}
                
                {/* DNS Records */}
                {dnsData && !dnsData.error && (
                    <div className="vt-info-section dns-section">
                        <h4>DNS Records</h4>
                        <div className="dns-records">
                            {dnsData.A && dnsData.A.length > 0 && (
                                <div className="dns-record-group">
                                    <h5>A Records:</h5>
                                    <div className="dns-values">
                                        {dnsData.A.map((record, idx) => (
                                            <span key={idx} className="dns-value">{record}</span>
                                        ))}
                                    </div>
                                </div>
                            )}
                            
                            {dnsData.AAAA && dnsData.AAAA.length > 0 && (
                                <div className="dns-record-group">
                                    <h5>AAAA Records:</h5>
                                    <div className="dns-values">
                                        {dnsData.AAAA.map((record, idx) => (
                                            <span key={idx} className="dns-value">{record}</span>
                                        ))}
                                    </div>
                                </div>
                            )}
                            
                            {dnsData.MX && dnsData.MX.length > 0 && (
                                <div className="dns-record-group">
                                    <h5>MX Records:</h5>
                                    <div className="dns-values">
                                        {dnsData.MX.map((record, idx) => (
                                            <span key={idx} className="dns-value">{record}</span>
                                        ))}
                                    </div>
                                </div>
                            )}
                            
                            {dnsData.TXT && dnsData.TXT.length > 0 && activeView === 'detailed' && (
                                <div className="dns-record-group">
                                    <h5>TXT Records:</h5>
                                    <div className="dns-values-txt">
                                        {dnsData.TXT.map((record, idx) => (
                                            <div key={idx} className="dns-txt-value">{record}</div>
                                        ))}
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                )}
                
                {/* URLScan Information */}
                {urlscanData && urlscanData.message && (
                    <div className="vt-info-section urlscan-section">
                        <h4>URLScan Analysis</h4>
                        <div className="urlscan-info">
                            <p><strong>Scan Status:</strong> {urlscanData.message}</p>
                            {urlscanData.uuid && (
                                <p>
                                    <strong>Results:</strong> 
                                    <a href={`https://urlscan.io/result/${urlscanData.uuid}/`} 
                                       target="_blank" 
                                       rel="noopener noreferrer" 
                                       className="urlscan-link">
                                        View Scan Results
                                    </a>
                                </p>
                            )}
                            {urlscanData.visibility && (
                                <p><strong>Visibility:</strong> {urlscanData.visibility}</p>
                            )}
                        </div>
                    </div>
                )}
                
                {/* Shodan Domain Search Results */}
                {shodanData && shodanData.matches && shodanData.matches.length > 0 && (
                    <div className="vt-info-section">
                        <h4>Associated IP Addresses</h4>
                        <p>Found {shodanData.matches.length} IP addresses associated with this domain:</p>
                        
                        <div className="domain-results">
                            {shodanData.matches.map((match, idx) => (
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
                {(!shodanData || !shodanData.matches || shodanData.matches.length === 0) && 
                 !vtData && !whoisData && !dnsData && !urlscanData && (
                    <div className="no-results">
                        <p>No information found for this domain.</p>
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
                    <p className="multi-tip">Pro tip: Enter comma-separated values for multiple lookups (e.g., "8.8.8.8,1.1.1.1")</p>
                </div>
            </form>

            {error && !error.includes('error(s):') && <div className="error-message">{error}</div>}

            <div className="results-container">
                {results && renderSearchResults()}
            </div>
        </div>
    );
}

export default UnifiedSearch;
