import React, { useState, useEffect } from "react";
import {
  BrowserRouter as Router,
  Routes,
  Route,
  Navigate,
  useLocation,
} from "react-router-dom";
import Navbar from "./components/Navbar";
import LoginPage from "./components/LoginPage";
import LogsPage from "./components/LogsPage";
import IPManagementPage from "./components/IPManagementPage";
import AnalyticsPage from "./components/AnalyticsPage";
import WazuhLogsPage from "./components/WazuhLogsPage";
import AgentsPage from "./components/AgentsPage";
import AdminPanel from "./components/AdminPanel";
import GlobalAlert from "./components/GlobalAlert";

// ← Import your new page
import UserManagementPage from "./components/UserManagementPage";

const AppContent = () => {
  const [isLoggedIn, setIsLoggedIn] = useState(
    localStorage.getItem("isLoggedIn") === "true"
  );

  useEffect(() => {
    if (isLoggedIn) {
      localStorage.setItem("isLoggedIn", "true");
    } else {
      localStorage.removeItem("isLoggedIn");
    }
  }, [isLoggedIn]);

  const location = useLocation();
  const showNavbar = isLoggedIn && location.pathname !== "/";

  return (
    <>
      <GlobalAlert />

      {showNavbar && (
        <Navbar isLoggedIn={isLoggedIn} setIsLoggedIn={setIsLoggedIn} />
      )}

      <Routes>
        {/* Public route */}
        <Route
          path="/"
          element={
            isLoggedIn ? (
              <Navigate to="/logs" replace />
            ) : (
              <LoginPage setIsLoggedIn={setIsLoggedIn} />
            )
          }
        />

        {/* Protected routes */}
        <Route
          path="/logs"
          element={isLoggedIn ? <LogsPage /> : <Navigate to="/" replace />}
        />
        <Route
          path="/wazuh-logs"
          element={
            isLoggedIn ? <WazuhLogsPage /> : <Navigate to="/" replace />
          }
        />
        <Route
          path="/ip-management"
          element={
            isLoggedIn ? <IPManagementPage /> : <Navigate to="/" replace />
          }
        />
        <Route
          path="/analytics"
          element={
            isLoggedIn ? <AnalyticsPage /> : <Navigate to="/" replace />
          }
        />
        <Route
          path="/agents"
          element={isLoggedIn ? <AgentsPage /> : <Navigate to="/" replace />}
        />
        <Route
          path="/admin"
          element={isLoggedIn ? <AdminPanel /> : <Navigate to="/" replace />}
        />

        {/* ← New User Management route */}
        <Route
          path="/user-management"
          element={
            isLoggedIn ? (
              <UserManagementPage />
            ) : (
              <Navigate to="/" replace />
            )
          }
        />

        {/* Catch‑all */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </>
  );
};

export default function App() {
  return (
    <Router>
      <AppContent />
    </Router>
  );
}
