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
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Switch,
  FormControlLabel,
  Button,
} from "@mui/material";
import axios from "axios";

const AgentsPage = () => {
  const [agents, setAgents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState("All");
  const [realTime, setRealTime] = useState(true);

  const SERVER_URL = process.env.REACT_APP_SERVER_URL;
  const AGENTS_API = `${SERVER_URL}/api/agents`;
  const TOGGLE_API = (id) => `${SERVER_URL}/api/agents/${id}/active`;

  const fetchAgents = () => {
    axios
      .get(AGENTS_API)
      .then((res) => {
        setAgents(res.data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Error fetching agents:", err);
        setError("Failed to load agents.");
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchAgents();
    let interval;
    if (realTime) {
      interval = setInterval(fetchAgents, 5000);
    }
    return () => clearInterval(interval);
  }, [realTime]);

  const total = agents.length;
  const onlineCount = agents.filter((a) => a.status === "online").length;
  const offlineCount = total - onlineCount;

  const displayed =
    filter === "All"
      ? agents
      : agents.filter((a) => a.status === filter.toLowerCase());

  const toggleActive = (agent_id, current) => {
    axios
      .patch(TOGGLE_API(agent_id), { is_active: !current })
      .then(() => fetchAgents())
      .catch((err) => console.error("Failed to toggle active:", err));
  };

  return (
    <Box p={3} bgcolor="#f4f6f8" minHeight="100vh">
      <Typography variant="h4" mb={3} fontWeight="bold" textAlign="center">
        Agents Dashboard
      </Typography>

      {loading ? (
        <CircularProgress size={50} sx={{ display: "block", mx: "auto", my: 5 }} />
      ) : error ? (
        <Typography color="error" textAlign="center">
          {error}
        </Typography>
      ) : (
        <>
          {/* Summary */}
          <Box display="flex" justifyContent="space-around" mb={3}>
            <Box textAlign="center">
              <Typography variant="h6">Total Agents</Typography>
              <Typography variant="h5" fontWeight="bold">{total}</Typography>
            </Box>
            <Box textAlign="center">
              <Typography variant="h6">Online</Typography>
              <Typography variant="h5" fontWeight="bold" color="green">{onlineCount}</Typography>
            </Box>
            <Box textAlign="center">
              <Typography variant="h6">Offline</Typography>
              <Typography variant="h5" fontWeight="bold" color="red">{offlineCount}</Typography>
            </Box>
          </Box>

          {/* Controls */}
          <Box mb={3} display="flex" justifyContent="space-between" alignItems="center" px={5}>
            <FormControl sx={{ width: 200 }}>
              <InputLabel id="filter-label">Filter Status</InputLabel>
              <Select
                labelId="filter-label"
                value={filter}
                label="Filter Status"
                onChange={(e) => setFilter(e.target.value)}
              >
                <MenuItem value="All">All</MenuItem>
                <MenuItem value="Online">Online</MenuItem>
                <MenuItem value="Offline">Offline</MenuItem>
              </Select>
            </FormControl>

            <FormControlLabel
              control={
                <Switch
                  checked={realTime}
                  onChange={(e) => setRealTime(e.target.checked)}
                />
              }
              label="Real-Time"
            />
          </Box>

          {/* Agents Table */}
          <TableContainer component={Paper} sx={{ maxWidth: "95%", mx: "auto" }}>
            <Table size="small">
              <TableHead>
                <TableRow>
                  <TableCell><strong>Agent ID</strong></TableCell>
                  <TableCell><strong>Hostname</strong></TableCell>
                  <TableCell><strong>Status</strong></TableCell>
                  <TableCell><strong>Last Seen</strong></TableCell>
                  <TableCell><strong>OS</strong></TableCell>
                  <TableCell><strong>IP</strong></TableCell>
                  <TableCell><strong>MAC</strong></TableCell>
                  <TableCell><strong>Processor</strong></TableCell>
                  <TableCell><strong>CPU Cores</strong></TableCell>
                  <TableCell><strong>Active</strong></TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {displayed.map((agent) => (
                  <TableRow key={agent.agent_id}>
                    <TableCell>{agent.agent_id}</TableCell>
                    <TableCell>{agent.hostname}</TableCell>
                    <TableCell sx={{ textTransform: "capitalize" }}>{agent.status}</TableCell>
                    <TableCell>{new Date(agent.last_seen).toLocaleString()}</TableCell>
                    <TableCell>{agent.os} {agent.os_version}</TableCell>
                    <TableCell>{agent.ip_address}</TableCell>
                    <TableCell>{agent.mac_address}</TableCell>
                    <TableCell>{agent.processor}</TableCell>
                    <TableCell>{agent.cpu_count} cores</TableCell>
                    <TableCell>
                      <Button
                        variant="contained"
                        size="small"
                        onClick={() => toggleActive(agent.agent_id, agent.is_active)}
                        color={agent.is_active ? "success" : "error"}
                      >
                        {agent.is_active ? "Deactivate" : "Activate"}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
                {displayed.length === 0 && (
                  <TableRow>
                    <TableCell colSpan={10} align="center">
                      No agents to display.
                    </TableCell>
                  </TableRow>
                )}
              </TableBody>
            </Table>
          </TableContainer>
        </>
      )}
    </Box>
  );
};

export default AgentsPage;
