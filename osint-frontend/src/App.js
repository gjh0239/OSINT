import React from 'react';
import './App.css';
import EmailBreachCheck from './components/EmailBreachCheck';

function App() {
  return (
    <div className="App">
      <header className="App-header" style={{ minHeight: '15vh' }}>
        <h1>OSINT Tool</h1>
      </header>
      <main>
        <EmailBreachCheck />
      </main>
    </div>
  );
}

export default App;
