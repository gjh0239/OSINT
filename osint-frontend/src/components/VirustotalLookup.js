import React, { useState } from 'react';
import axios from 'axios';
import './VirustotalLookup.css';

function VirustotalLookup() {
	const [ip, setIp] = useState('');
	const [results, setResults] = useState(null);
	const [shodanResults, setShodanResults] = useState(null);
	const [error, setError] = useState(null);
	const [loading, setLoading] = useState(false);
	const [combinedView, setCombinedView] = useState(true); // Toggle for combined/separate views

	const handleSubmit = async (e) => {
		e.preventDefault();
		setError(null);
		setLoading(true);
		setResults(null);
		setShodanResults(null);

		try {
			// Make both API calls in parallel
			const [vtResponse, shodanResponse] = await Promise.all([
				axios.post('http://localhost:5000/api/v1/main/virustotal-lookup', { ip }),
				axios.post('http://localhost:5000/api/v1/main/shodan-lookup', { query: ip })
			]);
			
			setResults(vtResponse.data);
			setShodanResults(shodanResponse.data);
		} catch (err) {
			console.error("API Error:", err);
			// Handle specific error cases
			if (err.response?.data?.error) {
				setError(`Error: ${err.response.data.error}`);
			} else {
				setError('An error occurred during the lookup. One or both services may be unavailable.');
			}
		} finally {
			setLoading(false);
		}
	};

	const renderShodanResults = () => {
		if (!shodanResults) return null;
		
		return (
			<div className="vt-info-section shodan-section">
				<h4>Shodan Information</h4>
				
				{/* IP Basic Information */}
				{shodanResults.ip_str && (
					<div className="shodan-ip-info">
						<p><strong>Organization:</strong> {shodanResults.org || 'Unknown'}</p>
						<p><strong>ISP:</strong> {shodanResults.isp || 'Unknown'}</p>
						<p><strong>Location:</strong> {shodanResults.country_name || 'Unknown'}, {shodanResults.city || 'Unknown'}</p>
						<p><strong>Last Update:</strong> {shodanResults.last_update ? new Date(shodanResults.last_update).toLocaleDateString() : 'Unknown'}</p>
					</div>
				)}
				
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
				
				{/* Services Preview */}
				{shodanResults.data && shodanResults.data.length > 0 && (
					<div className="shodan-services">
						<h5>Top Services ({Math.min(3, shodanResults.data.length)} of {shodanResults.data.length})</h5>
						{shodanResults.data.slice(0, 3).map((service, idx) => (
							<div key={idx} className="service-preview">
								<span className="service-port">Port {service.port}</span>
								<span className="service-product">{service.product || 'Unknown'} {service.version || ''}</span>
							</div>
						))}
						{shodanResults.data.length > 3 && (
							<div className="more-services">
								<a href="#" onClick={(e) => {e.preventDefault(); setCombinedView(false);}}>
									Show all {shodanResults.data.length} services...
								</a>
							</div>
						)}
					</div>
				)}
			</div>
		);
	};

	const renderAnalysisResults = () => {
		if (!results || !results.data || !results.data.attributes) return null;
		
		const { attributes } = results.data;
		const stats = attributes.last_analysis_stats || {};
		const totalEngines = Object.values(stats).reduce((a, b) => a + b, 0);
		const malicious = stats.malicious || 0;
		const suspicious = stats.suspicious || 0;
		
		return (
			<div className="results-section">
				{/* Combined View Integration */}
				{combinedView && shodanResults && (
					<div className="combined-summary">
						<div className="vt-summary" style={{marginBottom: '1rem'}}>
							<h4>Comprehensive IP Analysis</h4>
							<div className="source-badges">
								{results && <span className="source-badge vt-badge">VirusTotal</span>}
								{shodanResults && <span className="source-badge shodan-badge">Shodan</span>}
							</div>
						</div>
						{renderShodanResults()}
					</div>
				)}
				
				<div className="vt-summary">
					<h4>IP Reputation Summary</h4>
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
				</div>

				{/* Network Information */}
				<div className="vt-info-section">
					<h4>Network Information</h4>
					<div className="info-grid">
						{attributes.as_owner && <div className="info-item"><strong>AS Owner:</strong> {attributes.as_owner}</div>}
						{attributes.asn && <div className="info-item"><strong>ASN:</strong> {attributes.asn}</div>}
						{attributes.network && <div className="info-item"><strong>Network:</strong> {attributes.network}</div>}
						{attributes.regional_internet_registry && 
							<div className="info-item"><strong>Regional Registry:</strong> {attributes.regional_internet_registry}</div>
						}
					</div>
				</div>

				{/* Geolocation Information */}
				{attributes.country && (
					<div className="vt-info-section">
						<h4>Geolocation</h4>
						<div className="info-grid">
							{attributes.country && <div className="info-item"><strong>Country:</strong> {attributes.country}</div>}
							{attributes.continent && <div className="info-item"><strong>Continent:</strong> {attributes.continent}</div>}
							{attributes.longitude && attributes.latitude && 
								<div className="info-item"><strong>Coordinates:</strong> {attributes.latitude}, {attributes.longitude}</div>
							}
							{attributes.city && <div className="info-item"><strong>City:</strong> {attributes.city}</div>}
						</div>
					</div>
				)}

				{/* Tags and Categories */}
				{attributes.tags && attributes.tags.length > 0 && (
					<div className="vt-info-section">
						<h4>IP Tags</h4>
						<div className="tags-container">
							{attributes.tags.map((tag, index) => (
								<span key={index} className="ip-tag">{tag}</span>
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

				{/* Last Analysis Results */}
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

				{/* Detection Details */}
				{attributes.last_analysis_results && (
					<div className="vt-info-section">
						<h4>All Detection Details ({totalEngines} engines)</h4>
						<div className="detection-details">
							<table className="detection-table">
								<thead>
									<tr>
										<th>Security Vendor</th>
										<th>Category</th>
										<th>Result</th>
										<th>Method</th>
									</tr>
								</thead>
								<tbody>
									{Object.entries(attributes.last_analysis_results)
										.map(([vendor, result]) => (
											<tr key={vendor} className={`detection-row ${result.category}`}>
												<td>{vendor}</td>
												<td className={`category-cell ${result.category}`}>{result.category}</td>
												<td>{result.result || '-'}</td>
												<td>{result.method || '-'}</td>
											</tr>
										))}
								</tbody>
							</table>
						</div>
					</div>
				)}

				{/* Associated URLs */}
				{attributes.last_https_certificate && attributes.last_https_certificate.cert_issuer && (
					<div className="vt-info-section">
						<h4>SSL Certificate Information</h4>
						<div className="info-grid">
							<div className="info-item"><strong>Issuer:</strong> {attributes.last_https_certificate.cert_issuer}</div>
							<div className="info-item"><strong>Subject:</strong> {attributes.last_https_certificate.cert_subject}</div>
							{attributes.last_https_certificate.validity && (
								<>
									<div className="info-item"><strong>Valid From:</strong> {new Date(attributes.last_https_certificate.validity.not_before * 1000).toLocaleDateString()}</div>
									<div className="info-item"><strong>Valid Until:</strong> {new Date(attributes.last_https_certificate.validity.not_after * 1000).toLocaleDateString()}</div>
								</>
							)}
						</div>
					</div>
				)}

				{/* Popularity Ranks */}
				{attributes.popularity_ranks && Object.keys(attributes.popularity_ranks).length > 0 && (
					<div className="vt-info-section">
						<h4>Popularity Rankings</h4>
						<div className="ranks-container">
							{Object.entries(attributes.popularity_ranks).map(([source, data]) => (
								<div key={source} className="rank-item">
									<span className="rank-source">{source}</span>
									<span className="rank-value">Rank: #{data.rank}</span>
								</div>
							))}
						</div>
					</div>
				)}
			</div>
		);
	};

	return (
		<div className="virustotal-container">
			<h2>IP Intelligence Dashboard</h2>
			<p>Check an IP address against VirusTotal and Shodan to identify threats, exposed services, and more.</p>

			<form onSubmit={handleSubmit} className="virustotal-form">
				<div className="form-group">
					<input
						type="text"
						value={ip}
						onChange={(e) => setIp(e.target.value)}
						placeholder="Enter IP address (e.g. 8.8.8.8)"
						required
						className="virustotal-input"
						pattern="^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
						title="Please enter a valid IPv4 address"
					/>
				</div>
				<button type="submit" disabled={loading} className="lookup-button">
					{loading ? 'Analyzing...' : 'Check IP'}
				</button>
			</form>

			{error && <div className="error-message">{error}</div>}

			{(results || shodanResults) && (
				<div className="results-container">
					<div className="results-header">
						<h3>IP Analysis Results</h3>
						{results && shodanResults && (
							<div className="view-toggle">
								<button 
									className={combinedView ? 'active' : ''} 
									onClick={() => setCombinedView(true)}
								>
									Combined View
								</button>
								<button 
									className={!combinedView ? 'active' : ''} 
									onClick={() => setCombinedView(false)}
								>
									Detailed View
								</button>
							</div>
						)}
					</div>
					
					{combinedView ? (
						renderAnalysisResults()
					) : (
						<div className="detailed-view">
							{results && (
								<div className="detailed-section">
									<h4 className="source-heading">VirusTotal Results</h4>
									{renderAnalysisResults()}
								</div>
							)}
							
							{shodanResults && (
								<div className="detailed-section">
									<h4 className="source-heading">Shodan Results</h4>
									<div className="shodan-detailed">
										{/* Display full Shodan details here */}
										{shodanResults.ip_str && (
											<div className="ip-info">
												<h4>IP: {shodanResults.ip_str}</h4>
												<p><strong>Organization:</strong> {shodanResults.org || 'Unknown'}</p>
												<p><strong>ISP:</strong> {shodanResults.isp || 'Unknown'}</p>
												<p><strong>Location:</strong> {shodanResults.country_name || 'Unknown'}, {shodanResults.city || 'Unknown'}</p>
												<p><strong>Last Update:</strong> {shodanResults.last_update ? new Date(shodanResults.last_update).toLocaleDateString() : 'Unknown'}</p>
											</div>
										)}
										
										{shodanResults.ports && shodanResults.ports.length > 0 && (
											<div className="ports-section">
												<h4>Open Ports</h4>
												<div className="ports-list">
													{shodanResults.ports.map(port => (
														<span key={port} className="port-tag">{port}</span>
													))}
												</div>
											</div>
										)}
										
										{shodanResults.data && shodanResults.data.length > 0 && (
											<div className="services-section">
												<h4>Exposed Services</h4>
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
										
										{shodanResults.vulns && Object.keys(shodanResults.vulns).length > 0 && (
											<div className="vulns-section">
												<h4>Potential Vulnerabilities</h4>
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
								</div>
							)}
						</div>
					)}
				</div>
			)}
		</div>
	);
}

export default VirustotalLookup;
