import React from 'react';
import './App.css';
import UnifiedSearch from './components/UnifiedSearch';

function App() {
  return (
    <div className="App">
      <header className="App-header">
        <h1>OSINT Intelligence Tool</h1>
      </header>

      <main>
        <UnifiedSearch />
      </main>
    </div>
  );
}

export default App;