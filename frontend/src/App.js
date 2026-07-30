import React from 'react';
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import './App.css';

import SourcesPage from './pages/SourcesPage';
// import ReportsPage from './pages/ReportsPage';
// import KnowledgePage from './pages/KnowledgePage';
// import DashboardPage from './pages/DashboardPage';

const App = () => {
  return (
    <BrowserRouter>
      <div className="app">
        {/* Navbar */}
        <nav className="navbar">
          <div className="nav-brand">THREAT INTEL</div>
          <div className="nav-links">
            <Link to="/" className="active">Sources</Link>
            <Link to="/reports">Reports</Link>
            <Link to="/knowledge">Knowledge</Link>
            <Link to="/dashboard">Dashboard</Link>
          </div>
        </nav>

        {/* Page content */}
        <Routes>
          <Route path="/" element={<SourcesPage />} />
          <Route path="/reports" element={<div>Reports Page</div>} />
          <Route path="/knowledge" element={<div>Knowledge Page</div>} />
          <Route path="/dashboard" element={<div>Dashboard Page</div>} />
        </Routes>
      </div>
    </BrowserRouter>
  );
};

export default App;