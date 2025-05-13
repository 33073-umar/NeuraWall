import React, { useEffect, useState } from "react";
import {
  Box,
  Typography,
  Paper,
  CircularProgress,
  Button,
  TextField,
  Switch,
  FormControlLabel,
  TablePagination,
  Tabs,
  Tab,
  Alert,
} from "@mui/material";
import axios from "axios";

// Simple sanitization for XSS
const sanitizeInput = (input) =>
  input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");

// IPv4 validation
const isValidIP = (ip) =>
  /^(25[0-5]|2[0-4]\d|[01]?\d?\d)(\.(25[0-5]|2[0-4]\d|[01]?\d?\d)){3}$/.test(
    ip
  );

const IPManagementPage = () => {
  const AGENT = localStorage.getItem("username") || "unknown";
  const HOSTNAME = "server_frontend";

  const [maliciousIPs, setMaliciousIPs] = useState([]);
  const [whitelistIPs, setWhitelistIPs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const [newIP, setNewIP] = useState("");
  const [newWhitelistIP, setNewWhitelistIP] = useState("");
  const [realTimeEnabled, setRealTimeEnabled] = useState(true);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [currentPage, setCurrentPage] = useState(0);
  const [currentTab, setCurrentTab] = useState(0);

  // UI message state
  const [uiMessage, setUIMessage] = useState({ text: "", severity: "" });

  const SERVER_URL = process.env.REACT_APP_SERVER_URL;
  const BLACKLIST_API = `${SERVER_URL}/api/ips/blacklist`;
  const WHITELIST_API = `${SERVER_URL}/api/ips/whitelist`;
  const ADD_IP_API = `${SERVER_URL}/api/ips`;

  const role = localStorage.getItem("role"); // "admin" or "watcher"

  const fetchIPs = () => {
    setLoading(true);
    setError(null);

    const params = { agent_id: AGENT, hostname: HOSTNAME };
    Promise.all([
      axios.get(BLACKLIST_API, { params }),
      axios.get(WHITELIST_API, { params }),
    ])
      .then(([blacklistResponse, whitelistResponse]) => {
        setMaliciousIPs(blacklistResponse.data);
        setWhitelistIPs(whitelistResponse.data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Error fetching IPs:", err);
        setError("Failed to load IPs.");
        setLoading(false);
      });
  };

  const handleAddIP = (type) => {
    setUIMessage({ text: "", severity: "" });
    const raw = type === "blacklist" ? newIP : newWhitelistIP;
    if (!raw) {
      setUIMessage({ text: "Please enter an IP address.", severity: "warning" });
      return;
    }
    if (!isValidIP(raw.trim())) {
      setUIMessage({ text: "Please enter a valid IPv4 address.", severity: "warning" });
      return;
    }
    const safeIP = sanitizeInput(raw.trim());
    const body = { ip: safeIP, list_type: type, agent_id: AGENT, hostname: HOSTNAME };

    axios
      .post(ADD_IP_API, body)
      .then(() => {
        if (type === "blacklist") {
          setMaliciousIPs((prev) => [...prev, safeIP]);
          setNewIP("");
        } else {
          setWhitelistIPs((prev) => [...prev, safeIP]);
          setNewWhitelistIP("");
        }
        setUIMessage({ text: `IP added to ${type} successfully.`, severity: "success" });
      })
      .catch((err) => {
        console.error(`Error adding IP to ${type}:`, err);
        setUIMessage({ text: `Failed to add IP to ${type}.`, severity: "error" });
      });
  };

  const handleRemoveIP = (type, ip) => {
    setUIMessage({ text: "", severity: "" });
    const endpoint = type === "blacklist" ? `${BLACKLIST_API}/${ip}` : `${WHITELIST_API}/${ip}`;
    const params = { agent_id: AGENT, hostname: HOSTNAME };

    axios
      .delete(endpoint, { params })
      .then(() => {
        if (type === "blacklist") setMaliciousIPs((prev) => prev.filter((x) => x !== ip));
        else setWhitelistIPs((prev) => prev.filter((x) => x !== ip));
        setUIMessage({ text: `IP removed from ${type} successfully.`, severity: "info" });
      })
      .catch((err) => {
        console.error(`Error removing IP from ${type}:`, err);
        setUIMessage({ text: `Failed to remove IP from ${type}.`, severity: "error" });
      });
  };

  useEffect(() => {
    fetchIPs();
    let interval;
    if (realTimeEnabled) interval = setInterval(fetchIPs, 5000);
    return () => clearInterval(interval);
  }, [realTimeEnabled]);

  const handlePageChange = (_, newPage) => setCurrentPage(newPage);
  const handleRowsPerPageChange = (e) => {
    const value = e.target.value === "All" ? maliciousIPs.length : parseInt(e.target.value, 10);
    setRowsPerPage(value);
    setCurrentPage(0);
  };

  const renderTable = (data, type) => {
    const paginated =
      rowsPerPage === data.length
        ? data
        : data.slice(currentPage * rowsPerPage, currentPage * rowsPerPage + rowsPerPage);
    return (
      <>
        {paginated.map((ip, idx) => (
          <Paper
            key={idx}
            elevation={3}
            sx={{ p: 2, mb: 2, display: "flex", justifyContent: "space-between", alignItems: "center" }}
          >
            <Typography variant="body1" sx={{ fontWeight: "bold" }}>
              {ip}
            </Typography>
            {role === "admin" && (
              <Button variant="contained" color="success" onClick={() => handleRemoveIP(type, ip)}>
                Remove
              </Button>
            )}
          </Paper>
        ))}
        <Box display="flex" justifyContent="center" mt={3}>
          <TablePagination
            rowsPerPageOptions={[5, 10, 25, "All"]}
            count={data.length}
            rowsPerPage={rowsPerPage}
            page={currentPage}
            onPageChange={handlePageChange}
            onRowsPerPageChange={handleRowsPerPageChange}
          />
        </Box>
      </>
    );
  };

  return (
    <Box p={3} bgcolor="#f4f6f8" minHeight="100vh">
      <Typography variant="h4" mb={3} fontWeight="bold" textAlign="center">
        IP Management
      </Typography>

      <Box mb={2}>
        {uiMessage.text && (
          <Alert severity={uiMessage.severity} sx={{ mb: 2 }}>
            {uiMessage.text}
          </Alert>
        )}
      </Box>

      <Box mb={3} display="flex" justifyContent="flex-end" pr={5}>
        <FormControlLabel
          control={<Switch checked={realTimeEnabled} onChange={(e) => setRealTimeEnabled(e.target.checked)} />}
          label="Real-Time Updates"
        />
      </Box>

      <Tabs
        value={currentTab}
        onChange={(_, v) => setCurrentTab(v)}
        centered
        sx={{ marginBottom: 3 }}
      >
        <Tab label="Blacklist" />
        <Tab label="Whitelist" />
      </Tabs>

      {role === "admin" && (
        <Box mb={3} display="flex" justifyContent="center" alignItems="center" gap={2}>
          <TextField
            label={`Enter ${currentTab === 0 ? "Blacklist" : "Whitelist"} IP`}
            variant="outlined"
            value={currentTab === 0 ? newIP : newWhitelistIP}
            onChange={(e) =>
              currentTab === 0 ? setNewIP(e.target.value) : setNewWhitelistIP(e.target.value)
            }
            sx={{ width: "40%" }}
          />
          <Button
            variant="contained"
            color={currentTab === 0 ? "error" : "primary"}
            onClick={() => handleAddIP(currentTab === 0 ? "blacklist" : "whitelist")}
          >
            Add to {currentTab === 0 ? "Blacklist" : "Whitelist"}
          </Button>
        </Box>
      )}

      {loading ? (
        <CircularProgress size={50} sx={{ display: "block", margin: "0 auto" }} />
      ) : error ? (
        <Typography color="error" textAlign="center">
          {error}
        </Typography>
      ) : currentTab === 0 ? (
        maliciousIPs.length > 0 ? (
          renderTable(maliciousIPs, "blacklist")
        ) : (
          <Typography>No blacklist IPs recorded.</Typography>
        )
      ) : whitelistIPs.length > 0 ? (
        renderTable(whitelistIPs, "whitelist")
      ) : (
        <Typography>No whitelist IPs recorded.</Typography>
      )}
    </Box>
  );
};

export default IPManagementPage;
