import React, { useEffect, useState } from "react";
import {
  Box,
  Typography,
  CircularProgress,
  Switch,
  FormControlLabel,
  Card,
  CardContent,
  Grid,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
} from "@mui/material";
import { Line, Pie, Bar } from "react-chartjs-2";
import axios from "axios";
import {
  Chart as ChartJS,
  CategoryScale,
  LinearScale,
  PointElement,
  BarElement,
  LineElement,
  ArcElement,
  Tooltip,
  Legend,
} from "chart.js";

ChartJS.register(
  CategoryScale,
  LinearScale,
  PointElement,
  BarElement,
  LineElement,
  ArcElement,
  Tooltip,
  Legend
);

const SERVER_URL = process.env.REACT_APP_SERVER_URL;
const colorPalette = [
  "#4BC0C0",
  "#FF6384",
  "#36A2EB",
  "#FFCE56",
  "#9966FF",
  "#FF9F40",
];
const numberFormatter = new Intl.NumberFormat();

const AnalyticsPage = () => {
  const [logs, setLogs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [realTimeEnabled, setRealTimeEnabled] = useState(true);
  const [intervalUnit, setIntervalUnit] = useState("hour");

  const [totalFlows, setTotalFlows] = useState(0);
  const [maliciousFlows, setMaliciousFlows] = useState(0);
  const [benignFlows, setBenignFlows] = useState(0);
  const [avgDuration, setAvgDuration] = useState(0);
  const [avgFwdLen, setAvgFwdLen] = useState(0);
  const [avgBwdLen, setAvgBwdLen] = useState(0);

  const [topSrcIps, setTopSrcIps] = useState({ labels: [], counts: [] });
  const [protocolData, setProtocolData] = useState({ labels: [], counts: [] });
  const [trafficTrends, setTrafficTrends] = useState({ labels: [], counts: [] });
  const [topAgents, setTopAgents] = useState({ labels: [], counts: [] });

  const fmtNumber = (num) => numberFormatter.format(Math.round(num));
  const fmtDuration = (us) => (us / 1_000_000).toFixed(2);

  const fetchLogs = async () => {
    try {
      setLoading(true);
      const { data } = await axios.get(`${SERVER_URL}/api/logs_full`);
      const reversed = Array.isArray(data) ? data.reverse() : [];
      setLogs(reversed);
      updateStats(reversed);
    } catch (e) {
      console.error(e);
      setError("Failed to load logs.");
    } finally {
      setLoading(false);
    }
  };

  const updateStats = (list) => {
    const total = list.length;
    const malicious = list.filter((l) => l.label === "Malicious").length;
    const benign = total - malicious;
    const durations = list.map((l) => Number(l.flow_duration) || 0);
    const fwdLens = list.map((l) => Number(l.fwd_pkt_len_mean) || 0);
    const bwdLens = list.map((l) => Number(l.bwd_pkt_len_mean) || 0);
    const sum = (arr) => arr.reduce((a, b) => a + b, 0);

    setTotalFlows(total);
    setMaliciousFlows(malicious);
    setBenignFlows(benign);
    setAvgDuration(total ? sum(durations) / total : 0);
    setAvgFwdLen(total ? sum(fwdLens) / total : 0);
    setAvgBwdLen(total ? sum(bwdLens) / total : 0);

    // Protocol distribution
    const protoCount = list.reduce((acc, l) => {
      const p = l.protocol || "Unknown";
      acc[p] = (acc[p] || 0) + 1;
      return acc;
    }, {});
    setProtocolData({
      labels: Object.keys(protoCount),
      counts: Object.values(protoCount),
    });

    // Traffic trends
    const bucket = (dt) => {
      const d = new Date(dt);
      if (intervalUnit === "minute")
        return `${d.getHours()}:${String(d.getMinutes()).padStart(2, "0")}`;
      if (intervalUnit === "second")
        return `${d.getHours()}:${String(d.getMinutes()).padStart(
          2,
          "0"
        )}:${String(d.getSeconds()).padStart(2, "0")}`;
      return `${d.getHours()}:00`;
    };
    const trendCount = list.reduce((acc, l) => {
      const key = bucket(l.timestamp);
      acc[key] = (acc[key] || 0) + 1;
      return acc;
    }, {});
    const sortedLabels = Object.keys(trendCount).sort();
    setTrafficTrends({
      labels: sortedLabels,
      counts: sortedLabels.map((k) => trendCount[k]),
    });

    // Top source IPs
    const srcCount = list.reduce((acc, l) => {
      const ip = l.src_ip || "Unknown";
      acc[ip] = (acc[ip] || 0) + 1;
      return acc;
    }, {});
    const topIps = Object.entries(srcCount)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5);
    setTopSrcIps({
      labels: topIps.map((t) => t[0]),
      counts: topIps.map((t) => t[1]),
    });

    // Top agents by hostname
    const hostCount = list.reduce((acc, l) => {
      const host = l.hostname || "Unknown";
      acc[host] = (acc[host] || 0) + 1;
      return acc;
    }, {});
    const topHosts = Object.entries(hostCount)
      .sort(([, a], [, b]) => b - a)
      .slice(0, 5);
    setTopAgents({
      labels: topHosts.map((t) => t[0]),
      counts: topHosts.map((t) => t[1]),
    });
  };

  useEffect(() => {
    fetchLogs();
    let timer;
    if (realTimeEnabled) timer = setInterval(fetchLogs, 5000);
    return () => clearInterval(timer);
  }, [realTimeEnabled, intervalUnit]);

  const pieOpts = { responsive: true, maintainAspectRatio: false };
  const barOpts = { responsive: true, maintainAspectRatio: false };
  const lineOpts = {
    responsive: true,
    maintainAspectRatio: false,
    elements: { line: { tension: 0.3 }, point: { radius: 3 } },
    scales: { y: { beginAtZero: true } },
  };

  return (
    <Box p={3} bgcolor="#f4f6f8" minHeight="100vh">
      <Typography variant="h4" mb={3} fontWeight="bold" textAlign="center">
        Network Traffic Analytics
      </Typography>

      {loading ? (
        <CircularProgress size={60} sx={{ display: "block", mx: "auto" }} />
      ) : error ? (
        <Typography color="error" textAlign="center">
          {error}
        </Typography>
      ) : (
        <>
          <Box mb={3} display="flex" justifyContent="flex-end">
            <FormControlLabel
              control={
                <Switch
                  checked={realTimeEnabled}
                  onChange={(e) => setRealTimeEnabled(e.target.checked)}
                  color="primary"
                />
              }
              label="Real-Time"
            />
          </Box>

          {/* Stats Cards */}
          <Grid container spacing={3} mb={5}>
            {[
              {
                title: "Total Flows",
                value: fmtNumber(totalFlows),
                color: "primary",
              },
              {
                title: "Malicious",
                value: fmtNumber(maliciousFlows),
                color: "error",
              },
              {
                title: "Benign",
                value: fmtNumber(benignFlows),
                color: "success",
              },
            ].map((stat) => (
              <Grid item xs={12} sm={4} key={stat.title}>
                <Card sx={{ borderRadius: 2, boxShadow: 3 }}>
                  <CardContent sx={{ textAlign: "center" }}>
                    <Typography variant="subtitle1" gutterBottom>
                      {stat.title}
                    </Typography>
                    <Typography variant="h4" color={stat.color}>
                      {stat.value}
                    </Typography>
                  </CardContent>
                </Card>
              </Grid>
            ))}
          </Grid>

          {/* Charts */}
          <Grid container spacing={4}>
            <Grid item xs={12} md={6}>
              <Card sx={{ p: 2, height: 350, borderRadius: 2, boxShadow: 3 }}>
                <Typography variant="subtitle1" textAlign="center" mb={1}>
                  Protocol Distribution
                </Typography>
                <Pie
                  data={{
                    labels: protocolData.labels,
                    datasets: [
                      {
                        data: protocolData.counts,
                        backgroundColor: colorPalette.slice(
                          0,
                          protocolData.labels.length
                        ),
                      },
                    ],
                  }}
                  options={pieOpts}
                />
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card sx={{ p: 2, height: 350, borderRadius: 2, boxShadow: 3 }}>
                <Typography variant="subtitle1" textAlign="center" mb={1}>
                  Malicious vs Benign
                </Typography>
                <Pie
                  data={{
                    labels: ["Malicious", "Benign"],
                    datasets: [
                      {
                        data: [maliciousFlows, benignFlows],
                        backgroundColor: ["#FF6384", "#4BC0C0"],
                      },
                    ],
                  }}
                  options={pieOpts}
                />
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card sx={{ p: 2, height: 350, borderRadius: 2, boxShadow: 3 }}>
                <Typography variant="subtitle1" textAlign="center" mb={1}>
                  Avg Duration & Packet Lengths
                </Typography>
                <Bar
                  data={{
                    labels: ["Duration (s)", "Avg Fwd Len", "Avg Bwd Len"],
                    datasets: [
                      {
                        label: "Value",
                        data: [
                          fmtDuration(avgDuration),
                          avgFwdLen,
                          avgBwdLen,
                        ],
                        backgroundColor: ["#36A2EB", "#4BC0C0", "#FFCE56"],
                      },
                    ],
                  }}
                  options={barOpts}
                />
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card sx={{ p: 2, height: 350, borderRadius: 2, boxShadow: 3 }}>
                <Typography variant="subtitle1" textAlign="center" mb={1}>
                  Top 5 Source IPs
                </Typography>
                <Bar
                  data={{
                    labels: topSrcIps.labels,
                    datasets: [
                      {
                        label: "Flows",
                        data: topSrcIps.counts,
                        backgroundColor: colorPalette.slice(
                          0,
                          topSrcIps.labels.length
                        ),
                      },
                    ],
                  }}
                  options={barOpts}
                />
              </Card>
            </Grid>

            <Grid item xs={12} md={6}>
              <Card sx={{ p: 2, height: 350, borderRadius: 2, boxShadow: 3 }}>
                <Typography variant="subtitle1" textAlign="center" mb={1}>
                  Top 5 Agents
                </Typography>
                <Bar
                  data={{
                    labels: topAgents.labels,
                    datasets: [
                      {
                        label: "Flows",
                        data: topAgents.counts,
                        backgroundColor: colorPalette.slice(
                          0,
                          topAgents.labels.length
                        ),
                      },
                    ],
                  }}
                  options={barOpts}
                />
              </Card>
            </Grid>

            <Grid item xs={12}>
              <Card sx={{ p: 2, height: 400, borderRadius: 2, boxShadow: 3 }}>
                <Box
                  display="flex"
                  justifyContent="space-between"
                  alignItems="center"
                  mb={2}
                >
                  <Typography variant="subtitle1">
                    Traffic Trends ({intervalUnit})
                  </Typography>
                  <FormControl size="small">
                    <InputLabel>Interval</InputLabel>
                    <Select
                      value={intervalUnit}
                      onChange={(e) => setIntervalUnit(e.target.value)}
                      label="Interval"
                    >
                      <MenuItem value="hour">Hourly</MenuItem>
                      <MenuItem value="minute">Per Minute</MenuItem>
                      <MenuItem value="second">Per Second</MenuItem>
                    </Select>
                  </FormControl>
                </Box>
                <Line
                  data={{
                    labels: trafficTrends.labels,
                    datasets: [
                      {
                        label: "Flows",
                        data: trafficTrends.counts,
                        borderColor: "#36A2EB",
                        backgroundColor: "rgba(54,162,235,0.2)",
                        fill: true,
                      },
                    ],
                  }}
                  options={lineOpts}
                />
              </Card>
            </Grid>
          </Grid>
        </>
      )}
    </Box>
  );
};

export default AnalyticsPage;
