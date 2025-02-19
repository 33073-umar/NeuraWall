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

  // --- Backend API Endpoint ---
  const SERVER_URL = process.env.REACT_APP_SERVER_URL;
  const LOGS_API = `${SERVER_URL}/api/logs`;

  // --- Fetch logs ---
  const fetchLogs = () => {
    axios
      .get(LOGS_API)
      .then((response) => {
        const reversedLogs = response.data.reverse();
        setLogs(reversedLogs);
        setFilteredLogs(reversedLogs);
        setLoading(false);
      })
      .catch((error) => {
        console.error("Error fetching logs:", error);
        setError("Failed to load logs.");
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
    const value =
      event.target.value === "All"
        ? filteredLogs.length
        : parseInt(event.target.value, 10);
    setRowsPerPage(value);
    setCurrentPage(0);
  };

  const paginatedLogs =
    rowsPerPage === filteredLogs.length
      ? filteredLogs
      : filteredLogs.slice(
          currentPage * rowsPerPage,
          currentPage * rowsPerPage + rowsPerPage
        );

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
                <MenuItem value="Agent">Agent</MenuItem>
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
              value={tempQuery}
              onChange={(e) => setTempQuery(e.target.value)}
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
                  <TableCell><strong>Agent</strong></TableCell>
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
                        backgroundColor: log.Label === "Malicious" ? "#FFCCCC" : "inherit",
                      }}
                    >
                      <TableCell>{log.Date || "N/A"}</TableCell>
                      <TableCell>{log.Time || "N/A"}</TableCell>
                      <TableCell>{log.Agent || "N/A"}</TableCell>
                      <TableCell>{log["Src IP"] || "N/A"}</TableCell>
                      <TableCell>{log["Src Port"] || "N/A"}</TableCell>
                      <TableCell>{log["Dst IP"] || "N/A"}</TableCell>
                      <TableCell>{log["Dst Port"] || "N/A"}</TableCell>
                      <TableCell>{log.Protocol || "N/A"}</TableCell>
                    </TableRow>
                  ))
                ) : (
                  <TableRow>
                    <TableCell colSpan={8} align="center">
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

export default LogsPage;
