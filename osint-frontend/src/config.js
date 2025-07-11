const config = {
	// API endpoints
	api: {
		// Use environment variable with fallback for local development
		baseUrl: process.env.REACT_APP_BACKEND_URL || 'http://localhost:5000/api/v1/main',
		endpoints: {
			unifiedSearch: '/unified-search',
			// Add other endpoints as needed
		}
	},

	// Application settings
	app: {
		version: '1.0.0',
		name: 'OSINT Intelligence Tool'
	},

	// Feature flags (useful for enabling/disabling features)
	features: {
		enableCaching: true,
		enableMultiSearch: true
	}
};

export default config;