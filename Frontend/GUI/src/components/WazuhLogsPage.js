import React, { useEffect, useState } from "react";
import {
  Box,
  Typography,
  CircularProgress,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Paper,
  TextField,
  Button,
  MenuItem,
  Select,
  FormControl,
  InputLabel,
  TableFooter,
  TablePagination,
  Switch,
  FormControlLabel,
} from "@mui/material";
import axios from "axios";

const WazuhLogsPage = () => {
  const [logs, setLogs] = useState([]);
  const [filteredLogs, setFilteredLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [tempQuery, setTempQuery] = useState("");
  const [selectedColumn, setSelectedColumn] = useState("All");
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [currentPage, setCurrentPage] = useState(0);
  const [realTimeEnabled, setRealTimeEnabled] = useState(true);

  // Backend endpoint
  const SERVER_URL = "http://192.168.1.24:5000";
  const WAZUH_API = `${SERVER_URL}/api/wazuh/logs`;

  // Fetch Wazuh logs
  const fetchLogs = () => {
    axios
      .get(WAZUH_API)
      .then((response) => {
        // Reverse so latest first
        const reversed = [...response.data].reverse().map((log) => {
          const dt = new Date(log.timestamp);
          return {
            ...log,
            Date: dt.toLocaleDateString(),
            Time: dt.toLocaleTimeString(),
          };
        });
        setLogs(reversed);
        setFilteredLogs(reversed);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Error fetching Wazuh logs:", err);
        setError("Failed to load Wazuh logs.");
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchLogs();
    let interval;
    if (realTimeEnabled) {
      interval = setInterval(fetchLogs, 5000);
    }
    return () => clearInterval(interval);
  }, [realTimeEnabled]);

  const handleSearch = () => {
    if (!tempQuery) {
      setFilteredLogs(logs);
      return;
    }
    const filtered = logs.filter((log) => {
      const valueToSearch =
        selectedColumn === "All"
          ? Object.values(log).join(" ")
          : log[selectedColumn] || "";
      return String(valueToSearch)
        .toLowerCase()
        .includes(tempQuery.toLowerCase());
    });
    setFilteredLogs(filtered);
    setCurrentPage(0);
  };

  const handlePageChange = (_, newPage) => {
    setCurrentPage(newPage);
  };

  const handleRowsPerPageChange = (event) => {
    const val = event.target.value === "All" ? filteredLogs.length : parseInt(event.target.value, 10);
    setRowsPerPage(val);
    setCurrentPage(0);
  };

  const paginatedLogs =
    rowsPerPage === filteredLogs.length
      ? filteredLogs
      : filteredLogs.slice(currentPage * rowsPerPage, currentPage * rowsPerPage + rowsPerPage);

  return (
    <Box p={3} bgcolor="#f4f6f8" minHeight="100vh">
      <Typography variant="h4" mb={3} fontWeight="bold" textAlign="center">
        Wazuh Alert Logs
      </Typography>

      {loading ? (
        <CircularProgress size={50} sx={{ display: "block", margin: "0 auto" }} />
      ) : error ? (
        <Typography color="error" textAlign="center">
          {error}
        </Typography>
      ) : (
        <>
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

          {/* Search Controls */}
          <Box mb={3} display="flex" justifyContent="center" gap={2}>
            <FormControl sx={{ width: "20%" }}>
              <InputLabel id="search-column-label">Search Column</InputLabel>
              <Select
                labelId="search-column-label"
                value={selectedColumn}
                onChange={(e) => setSelectedColumn(e.target.value)}
                label="Search Column"
              >
                <MenuItem value="All">All</MenuItem>
                <MenuItem value="Date">Date</MenuItem>
                <MenuItem value="Time">Time</MenuItem>
                <MenuItem value="agent">Agent</MenuItem>
                <MenuItem value="rule_id">Rule ID</MenuItem>
                <MenuItem value="rule_level">Level</MenuItem>
                <MenuItem value="rule_desc">Description</MenuItem>
                <MenuItem value="location">Location</MenuItem>
              </Select>
            </FormControl>

            <TextField
              label="Search Query"
              variant="outlined"
              value={tempQuery}
              onChange={(e) => setTempQuery(e.target.value)}
              sx={{ width: "50%" }}
            />

            <Button variant="contained" color="primary" onClick={handleSearch}>
              Search
            </Button>
          </Box>

          <TableContainer component={Paper} sx={{ maxWidth: "95%", margin: "0 auto" }}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell><strong>Date</strong></TableCell>
                  <TableCell><strong>Time</strong></TableCell>
                  <TableCell><strong>Agent</strong></TableCell>
                  <TableCell><strong>Rule ID</strong></TableCell>
                  <TableCell><strong>Level</strong></TableCell>
                  <TableCell><strong>Description</strong></TableCell>
                  <TableCell><strong>Location</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {paginatedLogs.length > 0 ? (
                  paginatedLogs.map((log, idx) => (
                    <TableRow
                      key={idx}
                      sx={{
                        backgroundColor: log.rule_level >= 7 ? "#FFCCCC" : "inherit",
                      }}
                    >
                      <TableCell>{log.Date}</TableCell>
                      <TableCell>{log.Time}</TableCell>
                      <TableCell>{log.agent}</TableCell>
                      <TableCell>{log.rule_id}</TableCell>
                      <TableCell>{log.rule_level}</TableCell>
                      <TableCell>{log.rule_desc}</TableCell>
                      <TableCell>{log.location}</TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={7} align="center">
                      No logs match your search query.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
              <TableFooter>
                <TableRow>
                  <TablePagination
                    rowsPerPageOptions={[5, 10, 25, "All"]}
                    count={filteredLogs.length}
                    rowsPerPage={rowsPerPage}
                    page={currentPage}
                    onPageChange={handlePageChange}
                    onRowsPerPageChange={handleRowsPerPageChange}
                  />
                </TableRow>
              </TableFooter>
            </Table>
          </TableContainer>
        </>
      )}
    </Box>
  );
};

export default WazuhLogsPage;
