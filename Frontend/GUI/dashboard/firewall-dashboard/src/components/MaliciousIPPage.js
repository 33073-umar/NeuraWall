import React, { useState } from "react";
import { Box, Typography, Paper, Button, Divider, Grid } from "@mui/material";

const MaliciousIPPage = () => {
  const maliciousIPs = [
    { ip: "192.168.100.1", activity: [{ timestamp: "2024-11-18 10:00:00", request: "GET /api/data" }] },
    { ip: "10.0.0.5", activity: [{ timestamp: "2024-11-18 10:05:00", request: "POST /api/login" }] },
    { ip: "172.16.0.3", activity: [{ timestamp: "2024-11-18 10:10:00", request: "GET /api/info" }] },
  ];

  const [selectedIP, setSelectedIP] = useState(null);

  const handleIPClick = (ip) => {
    setSelectedIP(ip);
  };

  return (
    <Box p={3} bgcolor="#f4f6f8" height="100vh">
      <Typography variant="h4" mb={3} fontWeight="bold" textAlign="center">
        Malicious IPs
      </Typography>

      {/* List of Malicious IPs */}
      {maliciousIPs.map((ipData, index) => (
        <Paper
          key={index}
          elevation={3}
          sx={{
            p: 2,
            mb: 2,
            cursor: "pointer",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            "&:hover": { backgroundColor: "#e8f5e9" },
          }}
          onClick={() => handleIPClick(ipData)}
        >
          <Typography variant="body1" sx={{ fontWeight: "bold" }}>
            {ipData.ip}
          </Typography>
          <Button variant="contained" color="success">
            Allow
          </Button>
        </Paper>
      ))}

      <Divider sx={{ my: 3 }} />

      {/* Display IP Activity Details */}
      {selectedIP ? (
        <Box>
          <Typography variant="h5" mb={2}>
            Activity for IP: {selectedIP.ip}
          </Typography>
          {selectedIP.activity.length > 0 ? (
            <Grid container spacing={2}>
              <Grid item xs={4}>
                <Typography variant="h6" sx={{ fontWeight: "bold" }}>
                  Timestamp
                </Typography>
              </Grid>
              <Grid item xs={8}>
                <Typography variant="h6" sx={{ fontWeight: "bold" }}>
                  Request
                </Typography>
              </Grid>

              {selectedIP.activity.map((entry, index) => (
                <React.Fragment key={index}>
                  <Grid item xs={4}>
                    <Typography variant="body2">{entry.timestamp}</Typography>
                  </Grid>
                  <Grid item xs={8}>
                    <Typography variant="body2">{entry.request}</Typography>
                  </Grid>
                </React.Fragment>
              ))}
            </Grid>
          ) : (
            <Typography variant="body2" color="textSecondary">
              No activity recorded for this IP.
            </Typography>
          )}
        </Box>
      ) : (
        <Typography variant="body2" color="textSecondary" textAlign="center">
          Click on an IP to view its activity.
        </Typography>
      )}
    </Box>
  );
};

export default MaliciousIPPage;
