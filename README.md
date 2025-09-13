# AngryOxide 😡

![Logo](death.png)

### A 802.11 Attack tool built in Rust 🦀 - Now with macOS support! 🍎

[![Builds and Release](https://github.com/Ragnt/AngryOxide/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/Ragnt/AngryOxide/actions/workflows/ci.yml) ![GitHub commit activity](https://img.shields.io/github/commit-activity/m/Ragnt/AngryOxide) [![Discord](https://img.shields.io/discord/1194365883099922643)](https://discord.gg/QsEgaFndsQ)

**This tool is for research purposes only. I am not responsible for anything you do or damage you cause while using AngryOxide. Only use against networks that you have permission.**

AngryOxide was developed as a way to learn Rust, netlink, kernel sockets, and WiFi exploitation all at once.

You can get information about how to use AngryOxide in the [User Guide](https://github.com/Ragnt/AngryOxide/wiki/1.-User-Guide).

NOTE: This project is under HEAVY development and you can expect a very fast release cycle.

### Quick Compatibility Check

**Linux**: Full support on all distributions with nl80211 drivers
**macOS**: Supported with limitations - see [Platform Support](#platform-support) section
**Windows**: Not supported (use WSL2 with USB passthrough)

The overall goal of this tool is to provide a single-interface survey capability with advanced automated attacks that result in valid hashlines you can crack with [Hashcat](https://hashcat.net/hashcat/).

This tool is heavily inspired by [hcxdumptool](https://github.com/ZerBea/hcxdumptool) and development wouldn't have been possible without help from ZerBea.

If you have questions or any issues, you can reach me on the [AngryOxide Discord](https://discord.gg/QsEgaFndsQ)

## I wanna use it!

You can download pre-compiled binaries of AngryOxide in the [releases](https://github.com/Ragnt/AngryOxide/releases/latest).

### Linux Installation

```bash
tar -xf angryoxide-linux-x86_64.tar.gz # Untar
chmod +x install.sh # Make executable
sudo ./install.sh # Install (as root, including zsh/bash completions)
```

### macOS Installation

```bash
# For Intel Macs
tar -xf angryoxide-macos-x86_64.tar.gz

# For Apple Silicon (M1/M2/M3)
tar -xf angryoxide-macos-aarch64.tar.gz

# Or use the universal binary (works on all Macs)
tar -xf angryoxide-macos-universal.tar.gz

chmod +x install.sh
sudo ./install.sh # Install (as root, including zsh/bash completions)
```

**macOS Requirements:**
- macOS 10.14 (Mojave) or later
- Admin/root privileges for monitor mode
- Wireless Diagnostics or tcpdump (included with macOS)
- Optional: Disable SIP for some features (MAC spoofing)

You can get information about how to use AngryOxide in the [User Guide](https://github.com/Ragnt/AngryOxide/wiki/1.-User-Guide).

#### Uninstalling:

```bash
sudo ./install.sh uninstall # Uninstall
```

## Platform Support

| Platform | Architecture | Monitor Mode | Packet Injection | Status |
|----------|-------------|--------------|------------------|--------|
| Linux | x86_64, ARM, MIPS | ✅ Full | ✅ Full | Stable |
| macOS | Intel (x86_64) | ✅ Full | ✅ Hardware-dependent | Stable |
| macOS | Apple Silicon (M1/M2/M3) | ⚠️ Limited | ❌ Not supported | Beta |

## Features

- Active state-based attack engine used to retrieve relevent EAPOL messages from Access Points and clients.
- Target option that accepts MAC (aabbcc..., aa:bb:cc...) and SSID "Test_SSID" to limit attack scope.
- Whitelist option to protect specific networks from attacks. Useful if not using targets.
- Auto Hunt capability to find all target channels and hop between them.
- A Terminal-UI that presents all relevent data while still living in the terminal for easy usage over SSH.
- A grepable "Headless" operation mode that simply prints status output, ready to be redirected to a log file.
- Limits DEAUTHENTICATION frames that can cause more damage than good to the authentication sequence.
- EAPOL 4-Way-Handshake validation using Nonce Correction, Replay Counter validation, and Temporal validation.
- Automatically elicits PMKID from access points where available.
- Utilizes GPSD with ability to set remote GPSD service address.
- Ability to enable geo-fencing to force AO to only run when inside a geometric area specified by a latitude, longitude, and radius.
- Provides pcapng files with embedded GPS using the [Kismet Format](https://www.kismetwireless.net/docs/dev/pcapng_gps/).
- Provides a kismetdb file with all frames (with GPS) for post-processing.
- Wraps all output files in a gzipped tarball.
- Bash autocompletions for easy interface selection provided.

## Attacks

Will by default attack ALL access points in range, unless atleast one target is supplied, at which point the tool will only transmit against defined targets. (But will still passively collect on other access points).

- Attempts authentication/association sequence to produce EAPOL Message 1 (PMKID Collection)
- Attempts to retrieve hidden SSID's with direct probe requests.
- Utilizes Anonymous Reassociation to force Access Points to deauthenticate their own clients (MFP Bypass)
- Will attempt to send Channel Switch Announcement to send clients to adjacent channels.
- Attempts to downgrade RSN modes to WPA2-CCMP (Probe Response Injection via RogueM2)
- Attempts to collect EAPOL M2 from stations based solely on Probe Requests (RogueM2)
- Attempts to disassociate clients using WiFi 6e codes that prevent blacklisting
- All attacks can be manually disabled.

All of these attacks are rate-controlled both to prevent erroneous EAPOL timer resets and to maintain some level of operational security.

## Help

```
❯ angryoxide --help
Does awesome things... with wifi.

Usage: angryoxide [OPTIONS] --interface <INTERFACE>

Options:
  -i, --interface <INTERFACE>     Interface to use (e.g., wlan0 on Linux, en0 on macOS)
  -c, --channel <CHANNEL>         Optional - Channel to scan. Will use "-c 1,6,11" if none specified
  -b, --band <2 | 5 | 6 | 60>     Optional - Entire band to scan - will include all channels interface can support
  -o, --output <Output Filename>  Optional - Output filename
  -h, --help                      Print help
  -V, --version                   Print version

Targeting:
  -t, --target-entry <Target MAC/SSID>
          Optional - Target (MAC or SSID) to attack - will attack everything if none specified
  -w, --whitelist-entry <WhiteList MAC/SSID>
          Optional - Whitelist (MAC or SSID) to NOT attack
      --targetlist <Targets File>
          Optional - File to load target entries from
      --whitelist <Whitelist File>
          Optional - File to load whitelist entries from

Advanced Options:
  -r, --rate <Attack Rate>            Optional - Attack rate (1, 2, 3 || 3 is most aggressive) [default: 2]
      --combine                       Optional - Combine all hc22000 files into one large file for bulk processing
      --noactive                      Optional - Disable Active Monitor mode
      --rogue <MAC Address>           Optional - Tx MAC for rogue-based attacks - will randomize if excluded
      --gpsd <GPSD Host:Port>         Optional - Alter default HOST:Port for GPSD connection [default: 127.0.0.1:2947]
      --autohunt                      Optional - AO will auto-hunt all channels then lock in on the ones targets are on
      --headless                      Optional - Set the tool to headless mode without a UI. (useful with --autoexit)
      --autoexit                      Optional - AO will auto-exit when all targets have a valid hashline
      --notransmit                    Optional - Do not transmit - passive only
      --notar                         Optional - Do not tar output files
      --disablemouse                  Optional - Disable mouse capture (scroll wheel)
      --dwell <Dwell Time (seconds)>  Optional - Adjust channel hop dwell time [default: 2]

Geofencing:
      --geofence
          Optional - Enable geofencing using a specified latlng and distance
      --center <CENTER>
          Lat,Lng for geofencing (required if geofence is enabled)
      --distance <DISTANCE>
          Distance in meters from the center (required if geofence is enabled)
      --geofence-timeout <GEOFENCE_TIMEOUT>
          Timeout to disable geofence if GPS is lost. (default 300 seconds) [default: 300]

Attacks:
      --disable-deauth    Optional - Do NOT send deauthentication attacks
      --disable-pmkid     Optional - Do NOT attempt to associate for PMKID
      --disable-anon      Optional - Do NOT send anonymous reassociation attacks
      --disable-csa       Optional - Do NOT send Channel Switch Announcment attacks
      --disable-disassoc  Optional - Do NOT send disassociation attacks
      --disable-roguem2   Optional - Do NOT attempt rogue M2 collection
```

## Building from source

If you want to build from source instead of using precompiled binaries, these are the basic instructions:

### Linux

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Clone this repo
git clone --recurse-submodules https://github.com/Ragnt/AngryOxide.git

# Build/Install
cd AngryOxide
make
sudo make install
```

### macOS

```bash
# Install Rust (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install Xcode Command Line Tools (if not already installed)
xcode-select --install

# Clone this repo
git clone --recurse-submodules https://github.com/Ragnt/AngryOxide.git

# Build/Install
cd AngryOxide
cargo build --release
sudo cp target/release/angryoxide /usr/local/bin/
sudo cp completions/_angryoxide /usr/local/share/zsh/site-functions/ # Zsh completions
```

This will build from source, install into /usr/bin/angryoxide, and install the bash completions for you.

### Cross compiling:

I use [cross](https://github.com/cross-rs/cross) to cross compile to embedded architectures.

Here is MIPS (mips-unknown-linux-musl) as an example.

```
# make sure you have the nightly installed
rustup install nightly

# dynamically linked & soft-float
cross build +nightly --target mips-unknown-linux-musl --release -Zbuild-std
```


## macOS-Specific Notes

### Monitor Mode

AngryOxide supports multiple methods for monitor mode on macOS:

1. **Airport Utility** (older macOS versions)
   - Built-in support for monitor mode
   - Best compatibility on macOS 10.14-11.x

2. **tcpdump** (modern macOS versions)
   - Fallback method for macOS 12+
   - Automatically used when Airport is unavailable
   - Requires channel restart for switching

### Known Limitations on macOS

- **Apple Silicon (M1/M2/M3)**: Limited monitor mode support, no packet injection
- **Channel Hopping**: May be slower with tcpdump method
- **MAC Spoofing**: Requires SIP (System Integrity Protection) to be partially disabled
- **Active Monitor**: Not supported (cannot be associated while in monitor mode)

### Recommended Hardware for macOS

For best results on macOS, consider using:

1. **Intel-based Macs (pre-2020)** - Full monitor mode and injection support
2. **External USB WiFi Adapters** - Better compatibility:
   - Alfa AWUS036ACH (RTL8812AU chipset)
   - Alfa AWUS036ACM (MT7612U chipset)
   - Any adapter with RTL8812AU/BU or MT7612U chipset
3. **Older MacBooks (2012-2019)** - Native Broadcom chips with good support

### Troubleshooting macOS Issues

**"Operation not permitted" error:**
```bash
# Ensure you're running with sudo
sudo angryoxide -i en0
```

**Monitor mode not working:**
```bash
# Check if your hardware supports monitor mode
sudo tcpdump -I -i en0 -c 1

# Try using a different interface (en1, en2, etc.)
ifconfig -l  # List all interfaces
```

**Channel switching issues:**
```bash
# Manually disassociate first
sudo /System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -z
```

### Completions script:

These make using AngryOxide with bash and zsh a bit more fluid, automatically finding your wireless interfaces for you and showing you the arguments in a tab-completable way.

**Note for macOS users:** Completions work with both the default zsh shell and bash if installed via Homebrew.

## Screenshots!

![Access Points Page](screenshots/ap_tab.png)
![Handshakes Page](screenshots/handshakes_tab.png)
