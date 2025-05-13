import React, { useEffect, useState } from "react";
import {
  Box,
  Typography,
  Paper,
  CircularProgress,
  Button,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  TablePagination,
  Tabs,
  Tab,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
  Alert,
  IconButton,
  InputAdornment,
} from "@mui/material";
import { Visibility, VisibilityOff } from "@mui/icons-material";
import axios from "axios";

// Simple sanitization for XSS
const sanitizeInput = (input) =>
  input
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#x27;");

// Username rules: 3–20 chars, alphanumeric + underscore
const isValidUsername = (u) => /^[A-Za-z0-9_]{3,20}$/.test(u.trim());

// Password minimum 8 chars
const isValidPassword = (p) => p.length >= 8;

const UserManagementPage = () => {
  const SERVER_URL = process.env.REACT_APP_SERVER_URL;
  const LIST_USERS_API = `${SERVER_URL}/api/users`;
  const CREATE_USER_API = `${SERVER_URL}/api/users`;

  const [currentTab, setCurrentTab] = useState(0);

  // Create User states
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("watcher");
  const [showNewPassword, setShowNewPassword] = useState(false);

  // Manage Users states
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [currentPage, setCurrentPage] = useState(0);

  // Edit Dialog states
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [editUsername, setEditUsername] = useState("");
  const [editPassword, setEditPassword] = useState("");
  const [editRole, setEditRole] = useState("");
  const [showEditPassword, setShowEditPassword] = useState(false);

  // UI message state
  const [uiMessage, setUIMessage] = useState({ text: "", severity: "" });

  // Confirmation dialog for delete
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [toDeleteUser, setToDeleteUser] = useState("");

  useEffect(() => {
    const token = localStorage.getItem("authToken");
    if (token) {
      axios.defaults.headers.common["Authorization"] = `Basic ${token}`;
    }
  }, []);

  const fetchUsers = () => {
    setLoading(true);
    setError(null);
    axios
      .get(LIST_USERS_API)
      .then((res) => {
        setUsers(res.data);
        setLoading(false);
      })
      .catch((err) => {
        console.error("Error fetching users:", err);
        setError("Failed to load users.");
        setLoading(false);
      });
  };

  useEffect(() => {
    if (currentTab === 1) {
      fetchUsers();
    }
  }, [currentTab]);

  const handleCreateUser = () => {
    setUIMessage({ text: "", severity: "" });

    if (!isValidUsername(newUsername)) {
      setUIMessage({
        text: "Username must be 3–20 chars (letters, numbers, underscore).",
        severity: "warning",
      });
      return;
    }
    if (!isValidPassword(newPassword)) {
      setUIMessage({
        text: "Password must be at least 8 characters.",
        severity: "warning",
      });
      return;
    }

    const body = {
      username: sanitizeInput(newUsername.trim()),
      password: sanitizeInput(newPassword),
      role: sanitizeInput(newRole),
    };

    axios
      .post(CREATE_USER_API, body)
      .then((res) => {
        setUIMessage({
          text: res.data.message || "User created successfully.",
          severity: "success",
        });
        setNewUsername("");
        setNewPassword("");
        setNewRole("watcher");
        setShowNewPassword(false);
      })
      .catch((err) => {
        console.error("Error creating user:", err);
        setUIMessage({
          text: err.response?.data?.error || "Failed to create user.",
          severity: "error",
        });
      });
  };

  const handleDeleteConfirm = (username) => {
    setToDeleteUser(username);
    setConfirmOpen(true);
  };

  const handleDeleteUser = () => {
    setConfirmOpen(false);
    axios
      .delete(`${LIST_USERS_API}/${encodeURIComponent(toDeleteUser)}`)
      .then((res) => {
        setUsers((prev) => prev.filter((u) => u.username !== toDeleteUser));
        setUIMessage({
          text: res.data.message || "User deleted successfully.",
          severity: "info",
        });
      })
      .catch((err) => {
        console.error("Error deleting user:", err);
        setUIMessage({
          text: err.response?.data?.error || "Failed to delete user.",
          severity: "error",
        });
      });
  };

  const handleEditClick = (username, role) => {
    setEditUsername(username);
    setEditPassword("");
    setEditRole(role);
    setShowEditPassword(false);
    setEditDialogOpen(true);
  };

  const handleUpdateUser = () => {
    setUIMessage({ text: "", severity: "" });

    const body = {};
    if (editPassword) {
      if (!isValidPassword(editPassword)) {
        setUIMessage({
          text: "Password must be at least 8 characters.",
          severity: "warning",
        });
        return;
      }
      body.password = sanitizeInput(editPassword);
    }
    if (editRole) {
      body.role = sanitizeInput(editRole);
    }

    axios
      .put(`${LIST_USERS_API}/${encodeURIComponent(editUsername)}`, body)
      .then((res) => {
        setUIMessage({
          text: res.data.message || "User updated successfully.",
          severity: "success",
        });
        setEditDialogOpen(false);
        fetchUsers();
      })
      .catch((err) => {
        console.error("Error updating user:", err);
        setUIMessage({
          text: err.response?.data?.error || "Failed to update user.",
          severity: "error",
        });
      });
  };

  const handlePageChange = (_, newPage) => setCurrentPage(newPage);
  const handleRowsPerPageChange = (e) => {
    const value =
      e.target.value === "All" ? users.length : parseInt(e.target.value, 10);
    setRowsPerPage(value);
    setCurrentPage(0);
  };

  const renderUsersTable = () => {
    const paginated =
      rowsPerPage === users.length
        ? users
        : users.slice(
            currentPage * rowsPerPage,
            currentPage * rowsPerPage + rowsPerPage
          );
    return (
      <>
        {paginated.map((user, idx) => (
          <Paper
            key={idx}
            elevation={2}
            sx={{
              p: 2,
              mb: 2,
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
            }}
          >
            <Box>
              <Typography variant="body1">
                <strong>{user.username}</strong>
              </Typography>
              <Typography variant="body2">Role: {user.role}</Typography>
            </Box>
            <Box>
              <Button
                variant="outlined"
                sx={{ mr: 1 }}
                onClick={() => handleEditClick(user.username, user.role)}
              >
                Edit
              </Button>
              <Button
                variant="contained"
                color="error"
                onClick={() => handleDeleteConfirm(user.username)}
              >
                Delete
              </Button>
            </Box>
          </Paper>
        ))}
        <Box display="flex" justifyContent="center" mt={2}>
          <TablePagination
            rowsPerPageOptions={[5, 10, 25, "All"]}
            count={users.length}
            rowsPerPage={rowsPerPage}
            page={currentPage}
            onPageChange={handlePageChange}
            onRowsPerPageChange={handleRowsPerPageChange}
          />
        </Box>
      </>
    );
  };

  return (
    <Box p={3} bgcolor="#f4f6f8" minHeight="100vh">
      <Typography variant="h4" mb={3} fontWeight="bold" textAlign="center">
        User Management
      </Typography>

      {uiMessage.text && (
        <Alert severity={uiMessage.severity} sx={{ mb: 2 }}>
          {uiMessage.text}
        </Alert>
      )}

      <Tabs
        value={currentTab}
        onChange={(_, v) => setCurrentTab(v)}
        centered
        sx={{ mb: 3 }}
      >
        <Tab label="Create User" />
        <Tab label="Manage Users" />
      </Tabs>

      {currentTab === 0 ? (
        <Box sx={{ maxWidth: 400, mx: "auto" }}>
          <TextField
            label="Username"
            variant="outlined"
            fullWidth
            sx={{ mb: 2 }}
            value={newUsername}
            onChange={(e) => setNewUsername(e.target.value)}
            inputProps={{
              maxLength: 20,
              pattern: "[A-Za-z0-9_]{3,20}",
              title: "3–20 chars: letters, numbers, or underscore",
            }}
          />
          <TextField
            label="Password"
            type={showNewPassword ? "text" : "password"}
            variant="outlined"
            fullWidth
            sx={{ mb: 2 }}
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            inputProps={{ minLength: 8, title: "At least 8 characters" }}
            InputProps={{
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton
                    onClick={() => setShowNewPassword((prev) => !prev)}
                    edge="end"
                  >
                    {showNewPassword ? <VisibilityOff /> : <Visibility />}
                  </IconButton>
                </InputAdornment>
              ),
            }}
          />
          <FormControl fullWidth sx={{ mb: 2 }}>
            <InputLabel>Role</InputLabel>
            <Select
              value={newRole}
              label="Role"
              onChange={(e) => setNewRole(e.target.value)}
            >
              <MenuItem value="admin">Admin</MenuItem>
              <MenuItem value="watcher">Watcher</MenuItem>
            </Select>
          </FormControl>
          <Button
            variant="contained"
            color="primary"
            fullWidth
            onClick={handleCreateUser}
          >
            Create User
          </Button>
        </Box>
      ) : loading ? (
        <CircularProgress sx={{ display: "block", mx: "auto" }} />
      ) : error ? (
        <Typography color="error" textAlign="center">
          {error}
        </Typography>
      ) : users.length > 0 ? (
        renderUsersTable()
      ) : (
        <Typography textAlign="center">No users found.</Typography>
      )}

      {/* Delete Confirmation Dialog */}
      <Dialog open={confirmOpen} onClose={() => setConfirmOpen(false)}>
        <DialogTitle>Confirm Delete</DialogTitle>
        <DialogContent>
          Are you sure you want to delete user “{toDeleteUser}”?
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setConfirmOpen(false)}>Cancel</Button>
          <Button variant="contained" color="error" onClick={handleDeleteUser}>
            Delete
          </Button>
        </DialogActions>
      </Dialog>

      {/* Edit User Dialog */}
      <Dialog open={editDialogOpen} onClose={() => setEditDialogOpen(false)}>
        <DialogTitle>Edit User: {editUsername}</DialogTitle>
        <DialogContent>
          <TextField
            label="New Password"
            type={showEditPassword ? "text" : "password"}
            fullWidth
            sx={{ mt: 2 }}
            value={editPassword}
            onChange={(e) => setEditPassword(e.target.value)}
            placeholder="Leave blank to keep unchanged"
            inputProps={{ minLength: 8, title: "At least 8 characters" }}
            InputProps={{
              endAdornment: (
                <InputAdornment position="end">
                  <IconButton
                    onClick={() => setShowEditPassword((prev) => !prev)}
                    edge="end"
                  >
                    {showEditPassword ? <VisibilityOff /> : <Visibility />}
                  </IconButton>
                </InputAdornment>
              ),
            }}
          />
          <FormControl fullWidth sx={{ mt: 2 }}>
            <InputLabel>Role</InputLabel>
            <Select
              value={editRole}
              label="Role"
              onChange={(e) => setEditRole(e.target.value)}
            >
              <MenuItem value="admin">Admin</MenuItem>
              <MenuItem value="watcher">Watcher</MenuItem>
            </Select>
          </FormControl>
        </DialogContent>
        <DialogActions>
          <Button onClick={() => setEditDialogOpen(false)}>Cancel</Button>
          <Button variant="contained" onClick={handleUpdateUser}>
            Save
          </Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default UserManagementPage;
