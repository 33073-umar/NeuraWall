import React, { useEffect, useState } from "react";
import {
  Box,
  Typography,
  CircularProgress,
  Switch,
  FormControlLabel,
} from "@mui/material";
import { Line } from "react-chartjs-2";
import { Pie } from "react-chartjs-2";
import axios from "axios";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  LineElement,
  ArcElement,
  Tooltip,
  Legend,
} from "chart.js";

ChartJS.register(CategoryScale, LinearScale, PointElement, LineElement, ArcElement, Tooltip, Legend);

const AnalyticsPage = () => {
  const [logs, setLogs] = useState([]); // Original logs
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [realTimeEnabled, setRealTimeEnabled] = useState(true); // Toggle for real-time updates

  const [totalPackets, setTotalPackets] = useState(0);
  const [maliciousPackets, setMaliciousPackets] = useState(0);
  const [benignPackets, setBenignPackets] = useState(0);

  const [protocolData, setProtocolData] = useState({});
  const [trafficTrends, setTrafficTrends] = useState({ labels: [], data: [] });

  const fetchLogs = () => {
    axios
      .get("http://127.0.0.1:5000/api/logs")
      .then((response) => {
        const reversedLogs = response.data.reverse(); // Reverse order: latest to oldest
        setLogs(reversedLogs);
        setLoading(false);

        // Update stats
        updateStats(reversedLogs);
      })
      .catch((error) => {
        console.error("Error fetching logs:", error);
        setError("Failed to load logs.");
        setLoading(false);
      });
  };

  const updateStats = (logs) => {
    const total = logs.length;
    const malicious = logs.filter((log) => log.Label === "Malicious").length;
    const benign = total - malicious;

    setTotalPackets(total);
    setMaliciousPackets(malicious);
    setBenignPackets(benign);

    const protocolCounts = logs.reduce((acc, log) => {
      const protocol = log.Protocol || "Unknown";
      acc[protocol] = (acc[protocol] || 0) + 1;
      return acc;
    }, {});
    setProtocolData(protocolCounts);

    const timeGrouped = logs.reduce((acc, log) => {
      const time = log.Time.split(":")[0]; // Group by hour
      acc[time] = (acc[time] || 0) + 1;
      return acc;
    }, {});

    setTrafficTrends({
      labels: Object.keys(timeGrouped),
      data: Object.values(timeGrouped),
    });
  };

  useEffect(() => {
    fetchLogs(); // Fetch data on component mount

    // Real-time updates
    let interval;
    if (realTimeEnabled) {
      interval = setInterval(() => {
        fetchLogs();
      }, 5000); // Refresh every 5 seconds
    }
    return () => clearInterval(interval); // Cleanup interval on unmount or toggle off
  }, [realTimeEnabled]);

  const protocolChartData = {
    labels: Object.keys(protocolData),
    datasets: [
      {
        label: "Protocol Distribution",
        data: Object.values(protocolData),
        backgroundColor: ["#FF6384", "#36A2EB", "#FFCE56", "#4BC0C0"],
      },
    ],
  };

  const trafficTrendData = {
    labels: trafficTrends.labels,
    datasets: [
      {
        label: "Traffic Trends",
        data: trafficTrends.data,
        fill: false,
        borderColor: "#36A2EB",
      },
    ],
  };

  const maliciousBenignData = {
    labels: ["Malicious", "Benign"],
    datasets: [
      {
        label: "Packet Breakdown",
        data: [maliciousPackets, benignPackets],
        backgroundColor: ["#FF6384", "#4BC0C0"],
      },
    ],
  };

  return (
    <Box p={3} bgcolor="#f4f6f8" minHeight="100vh">
      <Typography variant="h4" mb={3} fontWeight="bold" textAlign="center">
        Network Traffic Analytics
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

          {/* Stats and Charts */}
          <Box mb={5} display="flex" justifyContent="space-around" flexWrap="wrap">
            <Box textAlign="center" mb={3} sx={{ width: "30%" }}>
              <Typography variant="h6">Total Packets</Typography>
              <Typography variant="h4" color="primary">
                {totalPackets}
              </Typography>
            </Box>
            <Box textAlign="center" mb={3} sx={{ width: "30%" }}>
              <Typography variant="h6">Malicious Packets</Typography>
              <Typography variant="h4" color="error">
                {maliciousPackets}
              </Typography>
            </Box>
            <Box textAlign="center" mb={3} sx={{ width: "30%" }}>
              <Typography variant="h6">Benign Packets</Typography>
              <Typography variant="h4" color="green">
                {benignPackets}
              </Typography>
            </Box>
          </Box>

          {/* Charts */}
          <Box mb={5} display="flex" justifyContent="space-around" flexWrap="wrap">
            <Box sx={{ width: "45%", minWidth: 300 }}>
              <Typography variant="h6" mb={2} textAlign="center">
                Protocol Breakdown
              </Typography>
              <Pie data={protocolChartData} />
            </Box>
            <Box sx={{ width: "45%", minWidth: 300 }}>
              <Typography variant="h6" mb={2} textAlign="center">
                Malicious vs Benign
              </Typography>
              <Pie data={maliciousBenignData} />
            </Box>
            <Box sx={{ width: "90%", minWidth: 300 }}>
              <Typography variant="h6" mb={2} textAlign="center">
                Traffic Trends
              </Typography>
              <Line data={trafficTrendData} />
            </Box>
          </Box>
        </>
      )}
    </Box>
  );
};

export default AnalyticsPage;
