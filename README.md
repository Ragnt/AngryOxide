# AngryOxide 😡

![Logo](death.png)

### A 802.11 Attack tool built in Rust 🦀

AngryOxide was developed as a way to learn Rust, netlink, kernel sockets, and WiFi exploitation all at once.

The overall goal of this tool is to provide a single-interface survey capability with advanced automated attacks that result in valid hashlines you can crack with [Hashcat](https://hashcat.net/hashcat/).

This tool is heavily inspired by [hcxdumptool](https://github.com/ZerBea/hcxdumptool) and development wouldn't have been possible without help from ZerBea.

## I wanna use it!

You can download pre-compiled binaries of AngryOxide in the [releases](https://github.com/Ragnt/AngryOxide/releases/latest).

More architectures will be added as I confirm there is no endianess-related issues associated with them.

## Features

- Active state-based attack engine used to retrieve relevent EAPOL messages from Access Points and clients.
- Target List option to limit attack scope.
- A Terminal-UI that presents all relevent data while still living in the terminal for easy usage over SSH.
- Avoids DEAUTHENTICATION frames that cause more damage than good to the authentication sequence.
- EAPOL 4-Way-Handshake validation using Nonce Correction, Replay Counter validation, and Temporal validation.
- Automatically elicits PMKID from access points where available.
- Utilizes GPSD with ability to set remote GPSD service address.
- Provides pcapng files with embedded GPS using the [Kismet Format](https://www.kismetwireless.net/docs/dev/pcapng_gps/).
- Provides a kismetdb file with all frames (with GPS) for post-processing.
- Wraps all output files in a gzipped tarball.

## Attacks

Will by default attack ALL access points in range, unless atleast one target is supplied, at which point the tool will only transmit against defined targets. (But will still passively collect on other access points).

- Attempts authentication/association sequence to produce EAPOL Message 1 (PMKID Collection)
- Attempts to retrieve hidden SSID's with undirected probe requests.
- Utilized Anonymous Reassociation to force Access Points to deauthenticate their own clients (MFP Bypass)
- Attempts to downgrade RSN modes to WPA2-CCMP (Probe Response Injection)
- Attempts to collect EAPOL M2 from stations based solely on Probe Requests (Rogue AP)
- Will send controlled deauthentication frames if told to do so (--deauth)

All of these attacks are rate-controlled both to prevent erroneous EAPOL timer resets and to maintain some level of OPSEC. 

## Help

```bash
Does awesome things... with wifi.

Usage: angry_oxide [OPTIONS] --interface <INTERFACE>

Options:
  -i, --interface <INTERFACE>  Interface to use
  -c, --channels <CHANNELS>    Optional list of channels to scan [default: 1 6 11]
  -t, --targets <TARGETS>      Optional list of targets to attack - will attack everything if excluded
  -o, --output <OUTPUT>        Optional output filename
  -r, --rogue <ROGUE>          Optional tx mac for rogue-based attacks - will randomize if excluded
      --gpsd <GPSD>            Optionally alter HOST:Port for GPSD connection. [default: 127.0.0.1:2947]
      --notransmit             Optional do not transmit, passive only
      --deauth                 Optional send deauths
  -h, --help                   Print help
  -V, --version                Print version
```

## Screenshots

![AccessPoints Page](screenshots/angry_oxide_demo.png)
![Handshakes Page](screenshots/handshakes.png)
![Status Page](screenshots/status_page.png)
