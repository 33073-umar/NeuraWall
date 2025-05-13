import React, { useState } from "react";
import { Box, Typography, TextField, Button, Alert } from "@mui/material";
import { useNavigate } from "react-router-dom";
import axios from "axios";

// Simple sanitization: encode &, <, >, ", ' to prevent XSS
const sanitizeInput = (input) => {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
};

const LoginPage = ({ setIsLoggedIn }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [errors, setErrors] = useState({ username: "", password: "" });
  const [serverError, setServerError] = useState("");
  const navigate = useNavigate();

  const validateUsername = (value) => {
    if (!value) return "Username is required.";
    if (value.length < 3 || value.length > 20) return "Username must be between 3 and 20 characters.";
    if (!/^[A-Za-z0-9_]+$/.test(value)) return "Username may only contain letters, numbers, and underscores.";
    return "";
  };

  const validatePassword = (value) => {
    if (!value) return "Password is required.";
    if (value.length < 8) return "Password must be at least 8 characters.";
    return "";
  };

  const handleLogin = () => {
    setServerError("");
    // Trim and sanitize inputs
    const rawUsername = username.trim();
    const rawPassword = password;
    const usernameError = validateUsername(rawUsername);
    const passwordError = validatePassword(rawPassword);
    setErrors({ username: usernameError, password: passwordError });
    if (usernameError || passwordError) return;

    const safeUsername = sanitizeInput(rawUsername);
    const safePassword = sanitizeInput(rawPassword);

    axios
      .post(
        `${process.env.REACT_APP_SERVER_URL}/api/login`,
        { username: safeUsername, password: safePassword }
      )
      .then((res) => {
        const { username: user, role } = res.data;
        localStorage.setItem("username", user);
        localStorage.setItem("role", role);

        const token = btoa(`${rawUsername}:${rawPassword}`);
        axios.defaults.headers.common["Authorization"] = `Basic ${token}`;
        localStorage.setItem("authToken", token);
        setIsLoggedIn(true);
        navigate("/logs");
      })
      .catch((err) => {
        console.error("Login failed", err);
        setServerError("Invalid username or password.");
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
        onChange={(e) => {
          const val = e.target.value;
          setUsername(val);
          if (errors.username) setErrors((prev) => ({ ...prev, username: validateUsername(val) }));
        }}
        onBlur={() => setErrors((prev) => ({ ...prev, username: validateUsername(username) }))}
        error={Boolean(errors.username)}
        helperText={errors.username}
        inputProps={{
          maxLength: 20,
          pattern: "[A-Za-z0-9_]+",
          title: "Letters, numbers, and underscores only"
        }}
      />

      <TextField
        label="Password"
        type="password"
        variant="outlined"
        sx={{ mb: 4, width: "300px" }}
        value={password}
        onChange={(e) => {
          const val = e.target.value;
          setPassword(val);
          if (errors.password) setErrors((prev) => ({ ...prev, password: validatePassword(val) }));
        }}
        onBlur={() => setErrors((prev) => ({ ...prev, password: validatePassword(password) }))}
        error={Boolean(errors.password)}
        helperText={errors.password}
        inputProps={{
          minLength: 8,
        }}
      />

      {serverError && (
        <Alert severity="error" sx={{ mb: 2, width: "300px" }}>
          {serverError}
        </Alert>
      )}

      <Button
        variant="contained"
        color="primary"
        onClick={handleLogin}
        disabled={Boolean(errors.username) || Boolean(errors.password) || !username || !password}
      >
        Login
      </Button>
    </Box>
  );
};

export default LoginPage;
