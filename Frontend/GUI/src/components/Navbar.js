import React, { useState } from "react";
import { Link } from "react-router-dom";
import { AppBar, Toolbar, Typography, Box, Button, Dialog, DialogTitle, DialogContent, DialogActions } from "@mui/material";

const Navbar = ({ isLoggedIn, setIsLoggedIn }) => {
  const [openDialog, setOpenDialog] = useState(false);

  const handleOpenDialog = () => {
    setOpenDialog(true);
  };

  const handleCancelSignOut = () => {
    setOpenDialog(false);
  };

  const handleConfirmSignOut = () => {
    setIsLoggedIn(false); // Set the login state to false when the user confirms sign-out
    setOpenDialog(false); // Close dialog after sign-out
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
              <Button
                component={Link}
                to="/logs"
                sx={{ color: "#fff", textTransform: "none", "&:hover": { bgcolor: "#f50057" } }}
              >
                Logs
              </Button>
              <Button
                component={Link}
                to="/ip-management"
                sx={{ color: "#fff", textTransform: "none", "&:hover": { bgcolor: "#f50057" } }}
              >
                IP Management
              </Button>
              <Button
                component={Link}
                to="/analytics"
                sx={{ color: "#fff", textTransform: "none", "&:hover": { bgcolor: "#f50057" } }}
              >
                Analytics
              </Button>
              <Button
                onClick={handleOpenDialog}
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
