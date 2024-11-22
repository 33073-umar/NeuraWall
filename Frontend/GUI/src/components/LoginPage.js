import React, { useState } from "react";
import { Box, Typography, TextField, Button } from "@mui/material";
import { useNavigate } from "react-router-dom";

const LoginPage = ({ setIsLoggedIn }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const navigate = useNavigate();

  const handleLogin = () => {
    // Here you would perform real authentication
    if (username === "admin" && password === "admin") {
      setIsLoggedIn(true);
      navigate("/logs"); // Redirect to logs page after successful login
    } else {
      alert("Invalid credentials");
    }
  };

  return (
    <Box
      display="flex"
      flexDirection="column"
      alignItems="center"
      justifyContent="center"
      height="100vh"
      bgcolor="#f4f6f8"
    >
      <Typography variant="h4" mb={4}>
        NeuraWall
      </Typography>
      <TextField
        label="Username"
        variant="outlined"
        sx={{ mb: 2, width: "300px" }}
        value={username}
        onChange={(e) => setUsername(e.target.value)}
      />
      <TextField
        label="Password"
        type="password"
        variant="outlined"
        sx={{ mb: 4, width: "300px" }}
        value={password}
        onChange={(e) => setPassword(e.target.value)}
      />
      <Button variant="contained" color="primary" onClick={handleLogin}>
        Login
      </Button>
    </Box>
  );
};

export default LoginPage;
