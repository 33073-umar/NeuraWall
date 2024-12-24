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
} from "@mui/material";
import axios from "axios";

const IPManagementPage = () => {
  const [maliciousIPs, setMaliciousIPs] = useState([]); // Blacklist IPs
  const [whitelistIPs, setWhitelistIPs] = useState([]); // Whitelist IPs
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [newIP, setNewIP] = useState(""); // New IP for blacklist
  const [newWhitelistIP, setNewWhitelistIP] = useState(""); // New IP for whitelist
  const [realTimeEnabled, setRealTimeEnabled] = useState(true); // Real-time updates
  const [rowsPerPage, setRowsPerPage] = useState(10); // Rows per page
  const [currentPage, setCurrentPage] = useState(0); // Current page index
  const [currentTab, setCurrentTab] = useState(0); // Tab index (0: Blacklist, 1: Whitelist)

  // --- Backend API Endpoints ---
  const BLACKLIST_API = "http://127.0.0.1:5000/api/malicious_ips";
  const WHITELIST_API = "http://127.0.0.1:5000/api/whitelist_ips";

  // --- Fetch IPs ---
  const fetchIPs = () => {
    setLoading(true);

    const fetchBlacklist = axios.get(BLACKLIST_API);
    const fetchWhitelist = axios.get(WHITELIST_API);

    Promise.all([fetchBlacklist, fetchWhitelist])
      .then(([blacklistResponse, whitelistResponse]) => {
        setMaliciousIPs(blacklistResponse.data);
        setWhitelistIPs(whitelistResponse.data);
        setLoading(false);
      })
      .catch((error) => {
        console.error("Error fetching IPs:", error);
        setError("Failed to load IPs.");
        setLoading(false);
      });
  };

  // --- Add IP ---
  const handleAddIP = (type) => {
    const newIPValue = type === "blacklist" ? newIP : newWhitelistIP;
    const endpoint = type === "blacklist" ? BLACKLIST_API : WHITELIST_API;

    if (!newIPValue) {
      alert("Please enter an IP address.");
      return;
    }

    axios
      .post(endpoint, { IP: newIPValue })
      .then(() => {
        if (type === "blacklist") {
          setMaliciousIPs((prev) => [...prev, { IP: newIPValue }]);
          setNewIP("");
          alert("IP added to blacklist successfully.");
        } else {
          setWhitelistIPs((prev) => [...prev, { IP: newIPValue }]);
          setNewWhitelistIP("");
          alert("IP added to whitelist successfully.");
        }
      })
      .catch((error) => {
        console.error(`Error adding IP to ${type}:`, error);
        alert(`Failed to add IP to ${type}. It may already exist.`);
      });
  };

  // --- Remove IP ---
  const handleRemoveIP = (type, ip) => {
    const endpoint = type === "blacklist" ? BLACKLIST_API : WHITELIST_API;

    axios
      .delete(`${endpoint}/${ip}`)
      .then(() => {
        if (type === "blacklist") {
          setMaliciousIPs((prev) => prev.filter((ipData) => ipData.IP !== ip));
        } else {
          setWhitelistIPs((prev) => prev.filter((ipData) => ipData.IP !== ip));
        }
        alert(`IP removed from ${type} successfully.`);
      })
      .catch((error) => {
        console.error(`Error removing IP from ${type}:`, error);
        alert(`Failed to remove IP from ${type}.`);
      });
  };

  // --- Pagination ---
  const handlePageChange = (_, newPage) => {
    setCurrentPage(newPage);
  };

  const handleRowsPerPageChange = (event) => {
    const value = event.target.value === "All" ? maliciousIPs.length : parseInt(event.target.value, 10);
    setRowsPerPage(value);
    setCurrentPage(0); // Reset to the first page
  };

  // --- Real-Time Updates ---
  useEffect(() => {
    fetchIPs();

    let interval;
    if (realTimeEnabled) {
      interval = setInterval(() => {
        fetchIPs();
      }, 5000); // Refresh every 5 seconds
    }
    return () => clearInterval(interval);
  }, [realTimeEnabled]);

  // --- Render Table ---
  const renderTable = (data, type) => {
    const paginatedIPs =
      rowsPerPage === data.length ? data : data.slice(currentPage * rowsPerPage, currentPage * rowsPerPage + rowsPerPage);

    return (
      <>
        {paginatedIPs.map((ipData, index) => (
          <Paper
            key={index}
            elevation={3}
            sx={{
              p: 2,
              mb: 2,
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <Typography variant="body1" sx={{ fontWeight: "bold" }}>
              {ipData.IP}
            </Typography>
            <Button
              variant="contained"
              color="success"
              onClick={() => handleRemoveIP(type, ipData.IP)}
            >
              Remove
            </Button>
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

      {/* Real-Time Toggle */}
      <Box mb={3} display="flex" justifyContent="flex-end" pr={5}>
        <FormControlLabel
          control={
            <Switch
              checked={realTimeEnabled}
              onChange={(e) => setRealTimeEnabled(e.target.checked)}
              color="primary"
            />
          }
          label="Real-Time Updates"
        />
      </Box>

      {/* Tabs for Blacklist and Whitelist */}
      <Tabs
        value={currentTab}
        onChange={(_, newValue) => setCurrentTab(newValue)}
        centered
        sx={{ marginBottom: 3 }}
      >
        <Tab label="Blacklist" />
        <Tab label="Whitelist" />
      </Tabs>

      {/* Add IP Form */}
      <Box mb={3} display="flex" justifyContent="center" alignItems="center" gap={2}>
        <TextField
          label={`Enter ${currentTab === 0 ? "Blacklist" : "Whitelist"} IP`}
          variant="outlined"
          value={currentTab === 0 ? newIP : newWhitelistIP}
          onChange={(e) => (currentTab === 0 ? setNewIP(e.target.value) : setNewWhitelistIP(e.target.value))}
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

      {/* Display Table */}
      {loading ? (
        <CircularProgress color="primary" size={50} sx={{ display: "block", margin: "0 auto" }} />
      ) : error ? (
        <Typography color="error" textAlign="center">
          {error}
        </Typography>
      ) : currentTab === 0 ? (
        maliciousIPs.length > 0 ? renderTable(maliciousIPs, "blacklist") : <Typography>No blacklist IPs recorded.</Typography>
      ) : whitelistIPs.length > 0 ? (
        renderTable(whitelistIPs, "whitelist")
      ) : (
        <Typography>No whitelist IPs recorded.</Typography>
      )}
    </Box>
  );
};

export default IPManagementPage;
