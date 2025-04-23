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
} from "@mui/material";
import axios from "axios";

const UserManagementPage = () => {
  const SERVER_URL = process.env.REACT_APP_SERVER_URL;
  const LIST_USERS_API = `${SERVER_URL}/api/users`;
  const CREATE_USER_API = `${SERVER_URL}/api/users`;

  const [currentTab, setCurrentTab] = useState(0);

  // Create User states
  const [newUsername, setNewUsername] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("watcher");

  // Manage Users states
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [rowsPerPage, setRowsPerPage] = useState(10);
  const [currentPage, setCurrentPage] = useState(0);

  // Edit User dialog states
  const [editDialogOpen, setEditDialogOpen] = useState(false);
  const [editUsername, setEditUsername] = useState("");
  const [editPassword, setEditPassword] = useState("");
  const [editRole, setEditRole] = useState("");

  useEffect(() => {
    const token = localStorage.getItem("authToken");
    if (token) {
      axios.defaults.headers.common["Authorization"] = `Basic ${token}`;
    }
  }, []);

  const fetchUsers = () => {
    setLoading(true);
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
    if (!newUsername || !newPassword) {
      alert("Please fill in all fields.");
      return;
    }
    const body = { username: newUsername, password: newPassword, role: newRole };
    axios
      .post(CREATE_USER_API, body)
      .then((res) => {
        alert(res.data.message || "User created successfully.");
        setNewUsername("");
        setNewPassword("");
        setNewRole("watcher");
      })
      .catch((err) => {
        console.error("Error creating user:", err);
        alert(err.response?.data?.error || "Failed to create user.");
      });
  };

  const handleDeleteUser = (username) => {
    if (!window.confirm(`Are you sure you want to delete user ${username}?`)) return;
    axios
      .delete(`${LIST_USERS_API}/${username}`)
      .then((res) => {
        setUsers((prev) => prev.filter((u) => u.username !== username));
        alert(res.data.message || "User deleted successfully.");
      })
      .catch((err) => {
        console.error("Error deleting user:", err);
        alert(err.response?.data?.error || "Failed to delete user.");
      });
  };

  const handleEditClick = (username, role) => {
    setEditUsername(username);
    setEditPassword("");
    setEditRole(role);
    setEditDialogOpen(true);
  };

  const handleUpdateUser = () => {
    const body = {};
    if (editPassword) body.password = editPassword;
    if (editRole) body.role = editRole;

    axios
      .put(`${LIST_USERS_API}/${editUsername}`, body)
      .then((res) => {
        alert(res.data.message || "User updated successfully.");
        setEditDialogOpen(false);
        fetchUsers();
      })
      .catch((err) => {
        console.error("Error updating user:", err);
        alert(err.response?.data?.error || "Failed to update user.");
      });
  };

  const handlePageChange = (_, newPage) => setCurrentPage(newPage);
  const handleRowsPerPageChange = (event) => {
    const value =
      event.target.value === "All"
        ? users.length
        : parseInt(event.target.value, 10);
    setRowsPerPage(value);
    setCurrentPage(0);
  };

  const renderUsersTable = () => {
    const paginated =
      rowsPerPage === users.length
        ? users
        : users.slice(currentPage * rowsPerPage, currentPage * rowsPerPage + rowsPerPage);
    return (
      <>
        {paginated.map((user, idx) => (
          <Paper
            key={idx}
            elevation={2}
            sx={{ p: 2, mb: 2, display: "flex", justifyContent: "space-between", alignItems: "center" }}
          >
            <Box>
              <Typography variant="body1"><strong>{user.username}</strong></Typography>
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
                onClick={() => handleDeleteUser(user.username)}
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
          />
          <TextField
            label="Password"
            type="password"
            variant="outlined"
            fullWidth
            sx={{ mb: 2 }}
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
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

      {/* Edit User Dialog */}
      <Dialog open={editDialogOpen} onClose={() => setEditDialogOpen(false)}>
        <DialogTitle>Edit User: {editUsername}</DialogTitle>
        <DialogContent>
          <TextField
            label="New Password"
            type="password"
            fullWidth
            sx={{ mt: 2 }}
            value={editPassword}
            onChange={(e) => setEditPassword(e.target.value)}
            placeholder="Leave blank to keep unchanged"
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
          <Button variant="contained" onClick={handleUpdateUser}>Save</Button>
        </DialogActions>
      </Dialog>
    </Box>
  );
};

export default UserManagementPage;
