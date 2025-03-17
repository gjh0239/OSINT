import React, { useState } from 'react';
import axios from 'axios';
import './EmailBreachCheck.css';

function EmailBreachCheck() {
	const [email, setEmail] = useState('');
	const [results, setResults] = useState(null);
	const [error, setError] = useState(null);
	const [loading, setLoading] = useState(false);

	const handleSubmit = async (e) => {
		e.preventDefault();
		setError(null);
		setLoading(true);

		try {
			const response = await axios.post('http://localhost:5000/api/v1/main/check-email', { email });
			setResults(response.data);
		} catch (err) {
			setError(err.response?.data?.error || 'An error occurred while checking the email');
		} finally {
			setLoading(false);
		}
	};

	return (
		<div className="email-breach-container">
			<h2>Check if Your Email Has Been Breached</h2>
			<p>Enter your email address to check if it has appeared in any known data breaches.</p>

			<form onSubmit={handleSubmit} className="email-form">
				<div className="form-group">
					<input
						type="email"
						value={email}
						onChange={(e) => setEmail(e.target.value)}
						placeholder="Enter email address"
						required
						className="email-input"
					/>
				</div>
				<button type="submit" disabled={loading} className="check-button">
					{loading ? 'Checking...' : 'Check Email'}
				</button>
			</form>

			{error && <div className="error-message">{error}</div>}

			{results && (
				<div className="results-container">
					<h3>Results</h3>
					{results.breached ? (
						<>
							<div className="alert alert-danger">
								<strong>Oh no!</strong> Your email was found in {results.found} data breach(es).
							</div>

							{results.exposed_data && results.exposed_data.length > 0 && (
								<div className="exposed-data">
									<h4>Exposed Information Types:</h4>
									<ul>
										{results.exposed_data.map((field, index) => (
											<li key={index}>{field}</li>
										))}
									</ul>
								</div>
							)}

							<div className="breaches-list">
								<h4>Breach Sources:</h4>
								{results.breaches.map((breach, index) => (
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
			)}
		</div>
	);
}

export default EmailBreachCheck;