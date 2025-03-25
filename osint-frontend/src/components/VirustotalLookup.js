import React, { useState } from 'react';
import axios from 'axios';
import './VirustotalLookup.css';

function VirustotalLookup() {
	const [ip, setIp] = useState('');
	const [results, setResults] = useState(null);
	const [error, setError] = useState(null);
	const [loading, setLoading] = useState(false);

	const handleSubmit = async (e) => {
		e.preventDefault();
		setError(null);
		setLoading(true);

		try {
			const response = await axios.post('http://localhost:5000/api/v1/main/virustotal-lookup', { ip });
			setResults(response.data);
		} catch (err) {
			setError(err.response?.data?.error || 'An error occurred during the lookup');
		} finally {
			setLoading(false);
		}
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
								style={{ width: `${(suspicious / totalEngines) * 100}%` }}
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

				{attributes.country && (
					<div className="vt-info-section">
						<h4>Geolocation</h4>
						<p><strong>Country:</strong> {attributes.country}</p>
						{attributes.continent && <p><strong>Continent:</strong> {attributes.continent}</p>}
						{attributes.as_owner && <p><strong>AS Owner:</strong> {attributes.as_owner}</p>}
					</div>
				)}

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
			</div>
		);
	};

	return (
		<div className="virustotal-container">
			<h2>VirusTotal IP Reputation Check</h2>
			<p>Check an IP address against VirusTotal's security database to identify potential threats.</p>

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

			{results && (
				<div className="results-container">
					<h3>VirusTotal Analysis Results</h3>
					{renderAnalysisResults()}
				</div>
			)}
		</div>
	);
}

export default VirustotalLookup;
