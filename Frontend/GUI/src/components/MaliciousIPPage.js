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
} from "@mui/material";
import axios from "axios";

const MaliciousIPPage = () => {
  const [maliciousIPs, setMaliciousIPs] = useState([]); // List of malicious IPs
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [newIP, setNewIP] = useState(""); // New IP to add
  const [realTimeEnabled, setRealTimeEnabled] = useState(false); // Toggle for real-time updates
  const [rowsPerPage, setRowsPerPage] = useState(10); // Rows per page
  const [currentPage, setCurrentPage] = useState(0); // Current page index

  // Fetch malicious IPs from the backend
  const fetchMaliciousIPs = () => {
    axios
      .get("http://127.0.0.1:5000/api/malicious_ips") // Backend API endpoint
      .then((response) => {
        setMaliciousIPs(response.data);
        setLoading(false);
      })
      .catch((error) => {
        console.error("Error fetching malicious IPs:", error);
        setError("Failed to load malicious IPs.");
        setLoading(false);
      });
  };

  // Add a new malicious IP
  const handleAddIP = () => {
    if (!newIP) {
      alert("Please enter an IP address.");
      return;
    }

    axios
      .post("http://127.0.0.1:5000/api/malicious_ips", { IP: newIP }) // POST API endpoint
      .then(() => {
        setMaliciousIPs((prevIPs) => [...prevIPs, { IP: newIP }]); // Update state
        setNewIP(""); // Clear input
        alert("IP blocked successfully.");
      })
      .catch((error) => {
        console.error("Error adding IP:", error);
        alert("Failed to block the IP. It may already exist.");
      });
  };

  // Unblock an IP
  const handleUnblock = (ip) => {
    axios
      .delete(`http://127.0.0.1:5000/api/malicious_ips/${ip}`) // Correct DELETE API endpoint
      .then(() => {
        setMaliciousIPs((prevIPs) => prevIPs.filter((ipData) => ipData.IP !== ip));
      })
      .catch((error) => {
        console.error("Error unblocking IP:", error);
        alert("Failed to unblock the IP.");
      });
  };

  // Handle page change
  const handlePageChange = (_, newPage) => {
    setCurrentPage(newPage);
  };

  // Handle rows per page change
  const handleRowsPerPageChange = (event) => {
    const value = event.target.value === "All" ? maliciousIPs.length : parseInt(event.target.value, 10);
    setRowsPerPage(value);
    setCurrentPage(0); // Reset to the first page
  };

  useEffect(() => {
    fetchMaliciousIPs(); // Fetch data on component mount

    // Real-time updates
    let interval;
    if (realTimeEnabled) {
      interval = setInterval(() => {
        fetchMaliciousIPs();
      }, 5000); // Refresh every 5 seconds
    }
    return () => clearInterval(interval); // Cleanup interval on unmount or toggle off
  }, [realTimeEnabled]);

  // Get paginated malicious IPs
  const paginatedIPs =
    rowsPerPage === maliciousIPs.length
      ? maliciousIPs
      : maliciousIPs.slice(currentPage * rowsPerPage, currentPage * rowsPerPage + rowsPerPage);

  return (
    <Box p={3} bgcolor="#f4f6f8" minHeight="100vh">
      <Typography variant="h4" mb={3} fontWeight="bold" textAlign="center">
        Malicious IPs
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

      {/* Add IP Form */}
      <Box mb={3} display="flex" justifyContent="center" alignItems="center" gap={2}>
        <TextField
          label="Enter IP Address"
          variant="outlined"
          value={newIP}
          onChange={(e) => setNewIP(e.target.value)}
          sx={{ width: "40%" }}
        />
        <Button variant="contained" color="error" onClick={handleAddIP}>
          Block IP
        </Button>
      </Box>

      {loading ? (
        <CircularProgress color="primary" size={50} sx={{ display: "block", margin: "0 auto" }} />
      ) : error ? (
        <Typography color="error" textAlign="center">
          {error}
        </Typography>
      ) : maliciousIPs.length > 0 ? (
        <>
          {/* Paginated IPs */}
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
                color="success" // Green unblock button
                onClick={() => handleUnblock(ipData.IP)}
              >
                Unblock
              </Button>
            </Paper>
          ))}

          {/* Pagination Controls */}
          <Box display="flex" justifyContent="center" mt={3}>
            <TablePagination
              rowsPerPageOptions={[5, 10, 25, "All"]}
              count={maliciousIPs.length} // Total malicious IPs
              rowsPerPage={rowsPerPage} // Current rows per page
              page={currentPage} // Current page index
              onPageChange={handlePageChange} // Page change handler
              onRowsPerPageChange={handleRowsPerPageChange} // Rows per page change handler
            />
          </Box>
        </>
      ) : (
        <Typography variant="body2" color="textSecondary" textAlign="center">
          No malicious IPs recorded.
        </Typography>
      )}
    </Box>
  );
};

export default MaliciousIPPage;
