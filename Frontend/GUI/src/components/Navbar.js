import React, { useState } from "react";
import { Link } from "react-router-dom";
import {
  AppBar,
  Toolbar,
  Typography,
  Box,
  Button,
  Dialog,
  DialogTitle,
  DialogContent,
  DialogActions,
} from "@mui/material";

const Navbar = ({ isLoggedIn, setIsLoggedIn }) => {
  const [openDialog, setOpenDialog] = useState(false);
  const role = localStorage.getItem("role"); // get lowercase role: "admin" or "watcher"

  const handleOpenDialog = () => {
    setOpenDialog(true);
  };

  const handleCancelSignOut = () => {
    setOpenDialog(false);
  };

  const handleConfirmSignOut = () => {
    setIsLoggedIn(false);
    setOpenDialog(false);
  };

  return (
    <AppBar position="sticky" sx={{ bgcolor: "#003366" }}>
      <Toolbar>
        <Typography variant="h6" sx={{ flexGrow: 1, color: "#fff" }}>
          NeuraWall
        </Typography>

        <Box display="flex" gap={2}>
          {isLoggedIn && (
            <>
              <Button component={Link} to="/logs" sx={navBtnStyle}>
                Logs
              </Button>
              <Button component={Link} to="/wazuh-logs" sx={navBtnStyle}>
                Wazuh Alerts
              </Button>
              <Button component={Link} to="/ip-management" sx={navBtnStyle}>
                IP Management
              </Button>
              <Button component={Link} to="/analytics" sx={navBtnStyle}>
                Analytics
              </Button>
              <Button component={Link} to="/agents" sx={navBtnStyle}>
                Agents
              </Button>

              {/* ✅ Only show this for "admin" */}
              {role === "admin" && (
                <Button component={Link} to="/user-management" sx={navBtnStyle}>
                  User Management
                </Button>
              )}

              <Button onClick={handleOpenDialog} sx={navBtnStyle}>
                Sign Out
              </Button>
            </>
          )}
        </Box>
      </Toolbar>

      <Dialog open={openDialog} onClose={handleCancelSignOut}>
        <DialogTitle>Are you sure?</DialogTitle>
        <DialogContent>
          <Typography>Do you want to sign out of your account?</Typography>
        </DialogContent>
        <DialogActions>
          <Button onClick={handleCancelSignOut} color="primary">
            No
          </Button>
          <Button onClick={handleConfirmSignOut} color="primary">
            Yes
          </Button>
        </DialogActions>
      </Dialog>
    </AppBar>
  );
};

const navBtnStyle = {
  color: "#fff",
  textTransform: "none",
  "&:hover": { bgcolor: "#f50057" },
};

export default Navbar;
