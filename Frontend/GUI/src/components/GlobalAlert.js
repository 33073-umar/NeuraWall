// src/components/GlobalAlert.js
import React, { useEffect, useRef, useState } from "react";
import { Snackbar, Alert } from "@mui/material";

const SERVER_URL    = "http://192.168.1.24:5000";  // your Flask host
const BLACKLIST_API = `${SERVER_URL}/api/ips/blacklist`;

export default function GlobalAlert() {
  const prevRef = useRef([]);   // last‐seen blacklist
  const [open, setOpen] = useState(false);
  const [msg, setMsg]   = useState("");

  useEffect(() => {
    let mounted = true;

    async function poll() {
      try {
        const res     = await fetch(BLACKLIST_API);
        const current = await res.json();
        if (!Array.isArray(current)) return;

        // first run: just prime
        if (prevRef.current.length === 0) {
          prevRef.current = current;
          return;
        }

        // if someone added a new IP:
        if (current.length > prevRef.current.length) {
          const newIp = current[current.length - 1];
          if (mounted) {
            setMsg(`Attack detected! IP ${newIp} was blocked.`);
            setOpen(true);
          }
        }

        // always update our ref to the latest state
        prevRef.current = current;
      } catch (e) {
        console.error("GlobalAlert poll error:", e);
      }
    }

    // start immediately, then every 5s
    poll();
    const id = setInterval(poll, 5000);

    return () => {
      mounted = false;
      clearInterval(id);
    };
  }, []);

  const handleClose = (_, reason) => {
    if (reason === "clickaway") return;
    setOpen(false);
  };

  return (
    <Snackbar
      anchorOrigin={{ vertical: "top", horizontal: "center" }}
      open={open}
      autoHideDuration={8000}
      onClose={handleClose}
    >
      <Alert onClose={handleClose} severity="error" variant="filled" sx={{ width: "100%" }}>
        {msg}
      </Alert>
    </Snackbar>
  );
}
