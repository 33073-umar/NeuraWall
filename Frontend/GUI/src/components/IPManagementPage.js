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

  const SERVER_URL = process.env.REACT_APP_SERVER_URL;
  const BLACKLIST_API = `${SERVER_URL}/api/ips/blacklist`;
  const WHITELIST_API = `${SERVER_URL}/api/ips/whitelist`;
  const ADD_IP_API = `${SERVER_URL}/api/ips`;

  const role = localStorage.getItem("role"); // "admin" or "watcher"
  console.log(role);
  const fetchIPs = () => {
    setLoading(true);

    const params = {
      agent_id: AGENT,
      hostname: HOSTNAME,
    };

    const fetchBlacklist = axios.get(BLACKLIST_API, { params });
    const fetchWhitelist = axios.get(WHITELIST_API, { params });

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

  const handleAddIP = (type) => {
    const newIPValue = type === "blacklist" ? newIP : newWhitelistIP;

    if (!newIPValue) {
      alert("Please enter an IP address.");
      return;
    }

    const body = {
      ip: newIPValue,
      list_type: type,
      agent_id: AGENT,
      hostname: HOSTNAME,
    };

    axios
      .post(ADD_IP_API, body)
      .then(() => {
        if (type === "blacklist") {
          setMaliciousIPs((prev) => [...prev, newIPValue]);
          setNewIP("");
          alert("IP added to blacklist successfully.");
        } else {
          setWhitelistIPs((prev) => [...prev, newIPValue]);
          setNewWhitelistIP("");
          alert("IP added to whitelist successfully.");
        }
      })
      .catch((error) => {
        console.error(`Error adding IP to ${type}:`, error);
        alert(`Failed to add IP to ${type}. It may already exist.`);
      });
  };

  const handleRemoveIP = (type, ip) => {
    const endpoint =
      type === "blacklist" ? `${BLACKLIST_API}/${ip}` : `${WHITELIST_API}/${ip}`;

    const params = {
      agent_id: AGENT,
      hostname: HOSTNAME,
    };

    axios
      .delete(endpoint, { params })
      .then(() => {
        if (type === "blacklist") {
          setMaliciousIPs((prev) => prev.filter((x) => x !== ip));
        } else {
          setWhitelistIPs((prev) => prev.filter((x) => x !== ip));
        }
        alert(`IP removed from ${type} successfully.`);
      })
      .catch((error) => {
        console.error(`Error removing IP from ${type}:`, error);
        alert(`Failed to remove IP from ${type}.`);
      });
  };

  const handlePageChange = (_, newPage) => {
    setCurrentPage(newPage);
  };

  const handleRowsPerPageChange = (event) => {
    const value =
      event.target.value === "All"
        ? maliciousIPs.length
        : parseInt(event.target.value, 10);
    setRowsPerPage(value);
    setCurrentPage(0);
  };

  useEffect(() => {
    fetchIPs();
    let interval;
    if (realTimeEnabled) {
      interval = setInterval(() => {
        fetchIPs();
      }, 5000);
    }
    return () => clearInterval(interval);
  }, [realTimeEnabled]);

  const renderTable = (data, type) => {
    const paginatedIPs =
      rowsPerPage === data.length
        ? data
        : data.slice(currentPage * rowsPerPage, currentPage * rowsPerPage + rowsPerPage);
    return (
      <>
        {paginatedIPs.map((ip, index) => (
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
              {ip}
            </Typography>
            {role === "admin" && (
  <Button
    variant="contained"
    color="success"
    onClick={() => handleRemoveIP(type, ip)}
  >
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

      <Tabs
        value={currentTab}
        onChange={(_, newValue) => setCurrentTab(newValue)}
        centered
        sx={{ marginBottom: 3 }}
      >
        <Tab label="Blacklist" />
        <Tab label="Whitelist" />
      </Tabs>

      {role === "admin" && (
  <Box
    mb={3}
    display="flex"
    justifyContent="center"
    alignItems="center"
    gap={2}
  >
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
      onClick={() =>
        handleAddIP(currentTab === 0 ? "blacklist" : "whitelist")
      }
    >
      Add to {currentTab === 0 ? "Blacklist" : "Whitelist"}
    </Button>
  </Box>
)}


      {loading ? (
        <CircularProgress
          color="primary"
          size={50}
          sx={{ display: "block", margin: "0 auto" }}
        />
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
