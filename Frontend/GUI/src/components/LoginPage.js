import React, { useState } from "react";
import { Box, Typography, TextField, Button } from "@mui/material";
import { useNavigate } from "react-router-dom";
import axios from "axios";

const LoginPage = ({ setIsLoggedIn }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const navigate = useNavigate();

  const handleLogin = () => {
    axios
      .post(`${process.env.REACT_APP_SERVER_URL}/api/login`, { username, password })
      .then((res) => {
        const { username: user, role } = res.data;
        // Save user info for later
        localStorage.setItem("username", user);
        localStorage.setItem("role", role);

        // Set basic auth header for future requests
        const token = btoa(`${username}:${password}`);
        axios.defaults.headers.common["Authorization"] = `Basic ${token}`;
        localStorage.setItem("authToken", token);
        setIsLoggedIn(true);
        navigate("/logs");
      })
      .catch((err) => {
        console.error("Login failed", err);
        alert("Invalid credentials");
      });
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
