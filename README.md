
![Logo](death.png)

# AngryOxide 😡

### A Rust WPA2 Attack tool.

AngryOxide was developed as a way to learn Rust, netlink, kernel sockets, and WiFi exploitation all at once.

The overall goal of this tool is to provide a single-interface survey capability with advanced automated attacks that result in valid hashlines you can crack with [Hashcat](https://hashcat.net/hashcat/).

## Features

- Active state-based attack engine used to retrieve relevent EAPOL messages from Access Points and clients.
- Target List 
- Avoids DEAUTHENTICATION frames that cause more damage than good to the authentication sequence.
- EAPOL 4-Way-Handshake validation using Nonce Correction, Replay Counter validation, and Temporal validation.
- PMKID collection and validation.
- GPSD support.
- Provides pcapng files with embedded GPS using the [Kismet Format](https://www.kismetwireless.net/docs/dev/pcapng_gps/).
- Provides a kismetdb file with all frames+GPS for post-processing.
- Wraps all output files in a GZipped Tarball.

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
      --gpsd <GPSD>            Optional HOST:Port for GPSD connection. Default: 127.0.0.1:2947 [default: 127.0.0.1:2947]
      --notransmit             Optional do not transmit, passive only
      --deauth                 Optional send deauths
  -h, --help                   Print help
  -V, --version                Print version
```

## Screenshots

![AccessPoints Page](screenshots/angry_oxide_demo.png)
![Handshakes Page](screenshots/handshakes.png)
![Status Page](screenshots/status_page.png)