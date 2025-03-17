import React, { useState } from 'react';
import './App.css';
import EmailBreachCheck from './components/EmailBreachCheck';
import ShodanLookup from './components/ShodanLookup';

function App() {
  const [activeTab, setActiveTab] = useState('email');

  return (
    <div className="App">
      <header className="App-header">
        <h1>OSINT Tool</h1>
      </header>

      <div className="app-tabs">
        <button
          className={`tab-button ${activeTab === 'email' ? 'active' : ''}`}
          onClick={() => setActiveTab('email')}
        >
          Email Breach Check
        </button>
        <button
          className={`tab-button ${activeTab === 'shodan' ? 'active' : ''}`}
          onClick={() => setActiveTab('shodan')}
        >
          Shodan Lookup
        </button>
      </div>

      <main>
        {activeTab === 'email' && <EmailBreachCheck />}
        {activeTab === 'shodan' && <ShodanLookup />}
      </main>
    </div>
  );
}

export default App;