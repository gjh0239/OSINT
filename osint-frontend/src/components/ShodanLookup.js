import React, { useState } from 'react';
import axios from 'axios';
import './ShodanLookup.css';

function ShodanLookup() {
	const [query, setQuery] = useState('');
	const [results, setResults] = useState(null);
	const [error, setError] = useState(null);
	const [loading, setLoading] = useState(false);

	const handleSubmit = async (e) => {
		e.preventDefault();
		setError(null);
		setLoading(true);

		try {
			const response = await axios.post('http://localhost:5000/api/v1/main/shodan-lookup', { query });
			setResults(response.data);
		} catch (err) {
			setError(err.response?.data?.error || 'An error occurred during the lookup');
		} finally {
			setLoading(false);
		}
	};

	return (
		<div className="shodan-container">
			<h2>Shodan IP/Domain Lookup</h2>
			<p>Enter an IP address or domain to discover exposed services and potential vulnerabilities.</p>

			<form onSubmit={handleSubmit} className="shodan-form">
				<div className="form-group">
					<input
						type="text"
						value={query}
						onChange={(e) => setQuery(e.target.value)}
						placeholder="Enter IP address or domain (e.g. 8.8.8.8 or example.com)"
						required
						className="shodan-input"
					/>
				</div>
				<button type="submit" disabled={loading} className="lookup-button">
					{loading ? 'Searching...' : 'Lookup'}
				</button>
			</form>

			{error && <div className="error-message">{error}</div>}

			{results && (
				<div className="results-container">
					<h3>Results</h3>

					{/* IP Information */}
					{results.ip_str && (
						<div className="ip-info">
							<h4>IP: {results.ip_str}</h4>
							<p><strong>Organization:</strong> {results.org || 'Unknown'}</p>
							<p><strong>ISP:</strong> {results.isp || 'Unknown'}</p>
							<p><strong>Location:</strong> {results.country_name || 'Unknown'}, {results.city || 'Unknown'}</p>
							<p><strong>Last Update:</strong> {results.last_update ? new Date(results.last_update).toLocaleDateString() : 'Unknown'}</p>
						</div>
					)}

					{/* Open Ports */}
					{results.ports && results.ports.length > 0 && (
						<div className="ports-section">
							<h4>Open Ports</h4>
							<div className="ports-list">
								{results.ports.map(port => (
									<span key={port} className="port-tag">{port}</span>
								))}
							</div>
						</div>
					)}

					{/* Services/Banners */}
					{results.data && results.data.length > 0 && (
						<div className="services-section">
							<h4>Exposed Services</h4>
							{results.data.map((service, idx) => (
								<div key={idx} className="service-card">
									<div className="service-header">
										<h5>Port {service.port} ({service.transport})</h5>
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

					{/* Vulnerabilities */}
					{results.vulns && Object.keys(results.vulns).length > 0 && (
						<div className="vulns-section">
							<h4>Potential Vulnerabilities</h4>
							<ul className="vulns-list">
								{Object.keys(results.vulns).map(vuln => (
									<li key={vuln} className="vuln-item">
										<a href={`https://nvd.nist.gov/vuln/detail/${vuln}`} target="_blank" rel="noopener noreferrer">
											{vuln}
										</a>
									</li>
								))}
							</ul>
						</div>
					)}

					{/* No results */}
					{!results.ip_str && !results.matches && (
						<div className="no-results">No information found for this query.</div>
					)}

					{/* Search results (domain search) */}
					{results.matches && results.matches.length > 0 && (
						<div className="domain-results">
							<h4>Found {results.matches.length} results</h4>
							{results.matches.map((match, idx) => (
								<div key={idx} className="match-item">
									<h5>{match.ip_str}</h5>
									<p><strong>Hostnames:</strong> {match.hostnames.join(', ') || 'None'}</p>
									<p><strong>Open Ports:</strong> {match.ports ? match.ports.join(', ') : 'None'}</p>
								</div>
							))}
						</div>
					)}
				</div>
			)}
		</div>
	);
}

export default ShodanLookup;