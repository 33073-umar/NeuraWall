import React, { useState, useEffect } from "react";
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import Navbar from "./components/Navbar";
import LoginPage from "./components/LoginPage";
import LogsPage from "./components/LogsPage";
import IPManagementPage from "./components/IPManagementPage";
import AdminPanel from "./components/AdminPanel"; // Import AdminPanel
import AnalyticsPage from "./components/AnalyticsPage"; // Import AnalyticsPage

const App = () => {
  // Check if user is already logged in by checking localStorage
  const [isLoggedIn, setIsLoggedIn] = useState(localStorage.getItem("isLoggedIn") === "true");

  // Update the login state when it's changed
  useEffect(() => {
    if (isLoggedIn) {
      localStorage.setItem("isLoggedIn", "true"); // Save the logged-in state to localStorage
    } else {
      localStorage.removeItem("isLoggedIn"); // Remove the login state from localStorage
    }
  }, [isLoggedIn]);

  return (
    <Router>
      {/* Show Navbar only if user is logged in */}
      {isLoggedIn && <Navbar isLoggedIn={isLoggedIn} setIsLoggedIn={setIsLoggedIn} />}

      <Routes>
        {/* Route for LoginPage */}
        <Route path="/" element={<LoginPage setIsLoggedIn={setIsLoggedIn} />} />

        {/* Protected Routes: only accessible if logged in */}
        <Route
          path="/logs"
          element={isLoggedIn ? <LogsPage /> : <Navigate to="/" />}
        />
        <Route
          path="/ip-management"
          element={isLoggedIn ? <IPManagementPage /> : <Navigate to="/" />}
        />
        <Route
          path="/analytics"
          element={isLoggedIn ? <AnalyticsPage /> : <Navigate to="/" />}
        />

        {/* Admin Panel route (protected if logged in) */}
        <Route
          path="/admin"
          element={isLoggedIn ? <AdminPanel /> : <Navigate to="/" />}
        />

        {/* Optionally, handle redirects for other non-existing paths */}
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </Router>
  );
};

export default App;
