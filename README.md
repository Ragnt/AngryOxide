
![Screenshot](death.png)

# WPOxide

### A Rust WPA Attack tool.

WPOxide was developed as a way to learn rust, netlink, and kernel sockets all at once- with a focus on WiFi exploitation.

The engine behind the tool is primarily designed after the hcxdumptool attack engine.

## Features


- Active attack engine used to retrieve relevent messages from Access Points.
- "Smart Attack" - considers attack status, AP state, and AP capabilities before blindly (brute-force) attacking.
- EAPOL Capture & 4-Way-Handshake validation using Nonce Correction, Replay Counter validation, and Temporal validation.
- PMKID collection and validation (non-zeroed).

## Screenshots

![Screenshot](wpoxide.png)