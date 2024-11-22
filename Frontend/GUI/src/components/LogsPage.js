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

const LogsPage = () => {
  const [logs, setLogs] = useState([]); // Original logs
  const [filteredLogs, setFilteredLogs] = useState([]); // Filtered logs
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [searchQuery, setSearchQuery] = useState(""); // Current query in search bar
  const [tempQuery, setTempQuery] = useState(""); // Temporary input query
  const [selectedColumn, setSelectedColumn] = useState("All"); // Selected column for filtering
  const [rowsPerPage, setRowsPerPage] = useState(10); // Rows per page
  const [currentPage, setCurrentPage] = useState(0); // Current page index
  const [realTimeEnabled, setRealTimeEnabled] = useState(false); // Toggle for real-time updates

  // Fetch logs
  const fetchLogs = () => {
    axios
      .get("http://127.0.0.1:5000/api/logs")
      .then((response) => {
        const reversedLogs = response.data.reverse(); // Reverse order: latest to oldest
        setLogs(reversedLogs);
        setFilteredLogs(reversedLogs); // Display all logs initially
        setLoading(false);
      })
      .catch((error) => {
        console.error("Error fetching logs:", error);
        setError("Failed to load logs.");
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchLogs(); // Initial fetch

    // Real-time updates
    let interval;
    if (realTimeEnabled) {
      interval = setInterval(() => {
        fetchLogs();
      }, 5000); // Refresh every 5 seconds
    }
    return () => clearInterval(interval); // Cleanup interval on unmount or toggle off
  }, [realTimeEnabled]);

  // Perform filtering when the search button is clicked
  const handleSearch = () => {
    if (!tempQuery) {
      setFilteredLogs(logs); // Reset to original logs if query is empty
      return;
    }

    const filtered = logs.filter((log) => {
      const valueToSearch =
        selectedColumn === "All"
          ? Object.values(log).join(" ") // Search across all columns
          : log[selectedColumn] || ""; // Search in specific column

      return String(valueToSearch) // Ensure it's a string
        .toLowerCase() // Convert to lowercase for case-insensitive matching
        .includes(tempQuery.toLowerCase());
    });

    setFilteredLogs(filtered); // Update filtered logs
    setCurrentPage(0); // Reset to the first page
  };

  // Handle page change
  const handlePageChange = (_, newPage) => {
    setCurrentPage(newPage);
  };

  // Handle rows per page change
  const handleRowsPerPageChange = (event) => {
    const value = event.target.value === "All" ? filteredLogs.length : parseInt(event.target.value, 10);
    setRowsPerPage(value);
    setCurrentPage(0); // Reset to the first page
  };

  // Get paginated logs
  const paginatedLogs =
    rowsPerPage === filteredLogs.length
      ? filteredLogs
      : filteredLogs.slice(currentPage * rowsPerPage, currentPage * rowsPerPage + rowsPerPage);

  return (
    <Box p={3} bgcolor="#f4f6f8" minHeight="100vh">
      <Typography variant="h4" mb={3} fontWeight="bold" textAlign="center">
        Network Packet Logs
      </Typography>

      {loading ? (
        <CircularProgress color="primary" size={50} sx={{ display: "block", margin: "0 auto" }} />
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
                <MenuItem value="Src IP">Src IP</MenuItem>
                <MenuItem value="Src Port">Src Port</MenuItem>
                <MenuItem value="Dst IP">Dst IP</MenuItem>
                <MenuItem value="Dst Port">Dst Port</MenuItem>
                <MenuItem value="Protocol">Protocol</MenuItem>
              </Select>
            </FormControl>

            <TextField
              label="Search Query"
              variant="outlined"
              value={tempQuery} // Bind to tempQuery
              onChange={(e) => setTempQuery(e.target.value)} // Update tempQuery
              sx={{ width: "50%" }}
            />

            <Button variant="contained" color="primary" onClick={handleSearch}>
              Search
            </Button>
          </Box>

          <TableContainer component={Paper} sx={{ maxWidth: "90%", margin: "0 auto" }}>
            <Table>
              <TableHead>
                <TableRow>
                  <TableCell><strong>Date</strong></TableCell>
                  <TableCell><strong>Time</strong></TableCell>
                  <TableCell><strong>Src IP</strong></TableCell>
                  <TableCell><strong>Src Port</strong></TableCell>
                  <TableCell><strong>Dst IP</strong></TableCell>
                  <TableCell><strong>Dst Port</strong></TableCell>
                  <TableCell><strong>Protocol</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {paginatedLogs.length > 0 ? (
                  paginatedLogs.map((log, index) => (
                    <TableRow
                      key={index}
                      sx={{
                        backgroundColor: log.Label === "Malicious" ? "#FFCCCC" : "inherit", // Red for malicious
                      }}
                    >
                      <TableCell>{log.Date || "N/A"}</TableCell>
                      <TableCell>{log.Time || "N/A"}</TableCell>
                      <TableCell>{log["Src IP"] || "N/A"}</TableCell>
                      <TableCell>{log["Src Port"] || "N/A"}</TableCell>
                      <TableCell>{log["Dst IP"] || "N/A"}</TableCell>
                      <TableCell>{log["Dst Port"] || "N/A"}</TableCell>
                      <TableCell>{log.Protocol || "N/A"}</TableCell>
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
                    rowsPerPageOptions={[5, 10, 25, "All"]} // Include "All" option
                    count={filteredLogs.length} // Total filtered logs
                    rowsPerPage={rowsPerPage} // Current rows per page
                    page={currentPage} // Current page index
                    onPageChange={handlePageChange} // Page change handler
                    onRowsPerPageChange={handleRowsPerPageChange} // Rows per page change handler
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

export default LogsPage;