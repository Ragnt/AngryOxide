Rust 802.11 project. Utilizes updated version of libwifi. 

Just started learning rust so this is about two days into the language - probably a lot of unsafe non-rust issues in this repo.

This project will currently attempt to setup a rx and tx socket on whichever wireless interface you pass as an argument, then read (and parse) a single packet.

╭─rage@rvm ~/dev/rust/wpaPwn  ‹master*›
╰─➤  sudo ./target/debug/wpa_pwn panda0
wlan0 (9C:EF:D5:FA:93:46) Index: 7
*panda0 (9C:EF:D5:FD:DF:88) Index: 5
Rx: 3
Tx: 4
Read packet of length: 229
Got a direct ProbeResponse: SpectrumSetup-80
