import React, { useState } from "react";
import { Box, Typography, TextField, Button, Alert, Paper, Container } from "@mui/material";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import { Shield, Lock } from "lucide-react"; // Using lucide-react for the logo icons

// Simple sanitization: encode &, <, >, ", ' to prevent XSS
const sanitizeInput = (input) => {
  return input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");
};

// Logo component for NeuraWall
const NeuraWallLogo = () => {
  return (
    <Box
      display="flex"
      flexDirection="column"
      alignItems="center"
      justifyContent="center"
      mb={2}
    >
      <Box

  sx={{

    display: "flex",

    alignItems: "center",

    justifyContent: "center",

    position: "relative",

    mb: 2

  }}

>

  <img 

    src="/logo.png" 

    alt="Logo" 

    style={{ 

      width: 64, 

      height: 64, 

      objectFit: "contain" 

    }} 

  />

</Box>
      <Typography 
        variant="h4" 
        component="div" 
        sx={{ 
          fontWeight: 700, 
          letterSpacing: 1,
          background: "linear-gradient(45deg, #2196F3 30%, #21CBF3 90%)",
          WebkitBackgroundClip: "text",
          WebkitTextFillColor: "transparent"
        }}
      >
        NeuraWall
      </Typography>
      <Typography 
        variant="subtitle2" 
        color="text.secondary" 
        sx={{ mt: 0.5 }}
      >
        Advanced Security Platform
      </Typography>
    </Box>
  );
};

const LoginPage = ({ setIsLoggedIn }) => {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [errors, setErrors] = useState({ username: "", password: "" });
  const [serverError, setServerError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
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
    setIsLoading(true);
    
    // Trim and sanitize inputs
    const rawUsername = username.trim();
    const rawPassword = password;
    const usernameError = validateUsername(rawUsername);
    const passwordError = validatePassword(rawPassword);
    setErrors({ username: usernameError, password: passwordError });
    
    if (usernameError || passwordError) {
      setIsLoading(false);
      return;
    }

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
        setIsLoading(false);
      });
  };

  const handleKeyPress = (e) => {
    if (e.key === 'Enter') {
      handleLogin();
    }
  };

  return (
    <Box
      display="flex"
      flexDirection="column"
      alignItems="center"
      justifyContent="center"
      height="100vh"
      bgcolor="#f7f9fc"
    >
      <Container maxWidth="sm">
        <Paper
          elevation={3}
          sx={{
            padding: 4,
            borderRadius: 2,
            display: "flex",
            flexDirection: "column",
            alignItems: "center",
          }}
        >
          <NeuraWallLogo />
          
          <TextField
            label="Username"
            variant="outlined"
            fullWidth
            sx={{ mb: 2 }}
            value={username}
            onChange={(e) => {
              const val = e.target.value;
              setUsername(val);
              if (errors.username) setErrors((prev) => ({ ...prev, username: validateUsername(val) }));
            }}
            onBlur={() => setErrors((prev) => ({ ...prev, username: validateUsername(username) }))}
            error={Boolean(errors.username)}
            helperText={errors.username}
            onKeyPress={handleKeyPress}
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
            fullWidth
            sx={{ mb: 3 }}
            value={password}
            onChange={(e) => {
              const val = e.target.value;
              setPassword(val);
              if (errors.password) setErrors((prev) => ({ ...prev, password: validatePassword(val) }));
            }}
            onBlur={() => setErrors((prev) => ({ ...prev, password: validatePassword(password) }))}
            error={Boolean(errors.password)}
            helperText={errors.password}
            onKeyPress={handleKeyPress}
            inputProps={{
              minLength: 8,
            }}
          />

          {serverError && (
            <Alert severity="error" sx={{ mb: 2, width: "100%" }}>
              {serverError}
            </Alert>
          )}

          <Button
            variant="contained"
            color="primary"
            fullWidth
            onClick={handleLogin}
            disabled={Boolean(errors.username) || Boolean(errors.password) || !username || !password || isLoading}
            sx={{ 
              py: 1.2,
              background: "linear-gradient(45deg, #2196F3 30%, #21CBF3 90%)",
              boxShadow: "0 3px 5px 2px rgba(33, 203, 243, .3)",
              transition: "all 0.3s ease",
              "&:hover": {
                background: "linear-gradient(45deg, #1976d2 30%, #2196F3 90%)",
                boxShadow: "0 4px 6px 2px rgba(33, 150, 243, .3)",
              }
            }}
          >
            {isLoading ? "Authenticating..." : "Login"}
          </Button>
          
          <Typography variant="body2" color="text.secondary" sx={{ mt: 4, textAlign: "center" }}>
            Secure access to NeuraWall's advanced security platform.
            <br />
            Contact your administrator if you need assistance.
          </Typography>
        </Paper>
      </Container>
    </Box>
  );
};

export default LoginPage;
