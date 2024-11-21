import React, { useState } from "react";
import { Link } from "react-router-dom";
import { AppBar, Toolbar, Typography, Box, Button, Dialog, DialogTitle, DialogContent, DialogActions } from "@mui/material";

const Navbar = ({ isLoggedIn, setIsLoggedIn }) => {
  // State to control dialog visibility
  const [openDialog, setOpenDialog] = useState(false);

  // Handle open dialog
  const handleOpenDialog = () => {
    setOpenDialog(true);
  };

  // Handle close dialog
  const handleCancelSignOut = () => {
    setOpenDialog(false); // Close dialog
  };

  // Handle confirm sign-out
  const handleConfirmSignOut = () => {
    setIsLoggedIn(false); // Set the login state to false when the user confirms sign-out
    console.log("User signed out");
    setOpenDialog(false); // Close dialog after sign-out
  };

  return (
    <AppBar position="sticky" sx={{ bgcolor: "#003366" }}>
      <Toolbar>
        {/* Logo on the left */}


        <Typography variant="h6" sx={{ flexGrow: 1, color: "#fff" }}>
          NeuraWall
        </Typography>

        <Box display="flex" gap={2}>
          {isLoggedIn && (
            <>
              <Button
                component={Link}
                to="/logs"
                sx={{ color: "#fff", textTransform: "none", "&:hover": { bgcolor: "#f50057" } }}
              >
                Logs
              </Button>
              <Button
                component={Link}
                to="/malicious-ip"
                sx={{ color: "#fff", textTransform: "none", "&:hover": { bgcolor: "#f50057" } }}
              >
                Malicious IPs
              </Button>
              <Button
                onClick={handleOpenDialog} // Open the confirmation dialog when user clicks "Sign Out"
                sx={{ color: "#fff", textTransform: "none", "&:hover": { bgcolor: "#f50057" } }}
              >
                Sign Out
              </Button>
            </>
          )}
        </Box>
      </Toolbar>

      {/* Confirmation Dialog */}
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

export default Navbar;
