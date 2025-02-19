import React, { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import Navbar from "./components/Navbar";
import LoginPage from "./components/LoginPage";
import LogsPage from "./components/LogsPage";
import IPManagementPage from "./components/IPManagementPage";
import AdminPanel from "./components/AdminPanel";
import AnalyticsPage from "./components/AnalyticsPage";
import GlobalAlert from "./components/GlobalAlert";
import WazuhLogsPage from "./components/WazuhLogsPage";
import AgentsPage from "./components/AgentsPage";  // Import the new Agents page

const App = () => {
  // Check if user is already logged in by checking localStorage
  const [isLoggedIn, setIsLoggedIn] = useState(
    localStorage.getItem("isLoggedIn") === "true"
  );

  // Update the login state when it's changed
  useEffect(() => {
    if (isLoggedIn) {
      localStorage.setItem("isLoggedIn", "true");
    } else {
      localStorage.removeItem("isLoggedIn");
    }
  }, [isLoggedIn]);

  return (
    <Router>
      <GlobalAlert />
      {/* Show Navbar only if user is logged in */}
      {isLoggedIn && (
        <Navbar isLoggedIn={isLoggedIn} setIsLoggedIn={setIsLoggedIn} />
      )}

      <Routes>
        {/* Login */}
        <Route path="/" element={<LoginPage setIsLoggedIn={setIsLoggedIn} />} />

        {/* Protected routes */}
        <Route
          path="/logs"
          element={isLoggedIn ? <LogsPage /> : <Navigate to="/" />}
        />
        <Route
          path="/wazuh-logs"
          element={isLoggedIn ? <WazuhLogsPage /> : <Navigate to="/" />}
        />
        <Route
          path="/ip-management"
          element={isLoggedIn ? <IPManagementPage /> : <Navigate to="/" />}
        />
        <Route
          path="/analytics"
          element={isLoggedIn ? <AnalyticsPage /> : <Navigate to="/" />}
        />
        <Route
          path="/admin"
          element={isLoggedIn ? <AdminPanel /> : <Navigate to="/" />}
        />
        {/* New Agents Route */}
        <Route
          path="/agents"
          element={isLoggedIn ? <AgentsPage /> : <Navigate to="/" />}
        />

        {/* Redirect all others to login */}
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </Router>
  );
};

export default App;