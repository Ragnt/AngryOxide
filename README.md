Rust 802.11 project. Utilizes updated version of libwifi. 

Just started learning rust so this is about two days into the language - probably a lot of unsafe non-rust issues in this repo.

This project will currently attempt to setup a rx and tx socket on whichever wireless interface you pass as an argument, then read (and parse) a single packet.

```
╭─rage@rvm ~/dev/rust/wpaPwn  ‹master*›
╰─➤  sudo ./target/debug/wpa_pwn panda0
Channel: 2.4GHz 1 | Frames Captured: 12539 | EAPOL Captured: 0 | Errors: 77 | APs: 88 | Unassoc Clients: 26
==================================================================================

                                 Access Points:
MAC Address     RSSI     Last Seen          SSID                                Clients
84238821b288    -54      0 seconds ago      MorgantonPark-6035                  0
84238861b288    -50      0 seconds ago      MorgantonPark-Guest                 0
842388211858    -74      0 seconds ago      MorgantonPark-6032                  2
8423880f1c48    -68      0 seconds ago      MorgantonPark-6034                  3
8423884f1c48    -66      0 seconds ago      MorgantonPark-Guest                 0
842388611708    -60      0 seconds ago      MorgantonPark-Guest                 0
84238821b4d8    -78      0 seconds ago      MorgantonPark-7527                  0
84238861b4d8    -76      0 seconds ago      MorgantonPark-Guest                 0
8423884f26b8    -80      0 seconds ago      MorgantonPark-Guest                 0
a8a795f36bef    -76      0 seconds ago      WIFIF36BEC                          0
8423880f26b8    -78      0 seconds ago      MorgantonPark-6022                  1
84238821b0d8    -82      0 seconds ago      MorgantonPark-6026                  0
84238861b0d8    -82      0 seconds ago      MorgantonPark-Guest                 0
1a180a7bb0be    -56      0 seconds ago      Legends ClubHouse WiFi              0
00180a6ff805    -72      0 seconds ago      Legends Apartments WiFi             0
84238821b1b8    -70      0 seconds ago      MorgantonPark-6023                  0
3a180a7bb0be    -56      0 seconds ago      Legends E                           0
8423886120e8    -76      0 seconds ago      MorgantonPark-Guest                 0
842388211ea8    -72      0 seconds ago      MorgantonPark-6013                  1
6c9961dbcb86    -56      0 seconds ago      SpectrumSetup-80                    0
00180a7bb0be    -64      0 seconds ago      Legends Apartments WiFi             0
842388611ea8    -72      0 seconds ago      MorgantonPark-Guest                 0
1a180a6ff805    -74      0 seconds ago      Legends ClubHouse WiFi              0
8423882261f8    -70      0 seconds ago      MorgantonPark-6017                  0
8423882261d8    -48      0 seconds ago      MorgantonPark-6033                  0
8423886261d8    -48      0 seconds ago      MorgantonPark-Guest                 0
842388a261d8    -48      0 seconds ago      IST Test                            0
842388611ca8    -70      0 seconds ago      MorgantonPark-Guest                 0
842388611858    -74      0 seconds ago      MorgantonPark-Guest                 0


==================================================================================

                              Unassociated Clients:
MAC Address     RSSI     Last Seen          Probes
04ea56df7262    -48      0 seconds ago
84238821b288    -54      0 seconds ago      MorgantonPark-6035
bcff4deaa72f    -74      3 seconds ago      E_0003_8687
84238821b178    -84      4 seconds ago      MorgantonPark-7531
8423882261f8    -62      4 seconds ago      MorgantonPark-6017
204ef6674ddb    -64      4 seconds ago
02182a7bb0be    -76      8 seconds ago
84238821b4d8    -80      10 seconds ago     MorgantonPark-7527
1059324403ac    -84      11 seconds ago     Galaxy S23 FACB
842388211948    -56      13 seconds ago
8423882120e8    -76      13 seconds ago
8423880f25b8    -62      18 seconds ago     MorgantonPark-6038
023608c6c76a    -58      20 seconds ago
4cfcaa682228    -70      21 seconds ago
842388211ca8    -70      21 seconds ago     MorgantonPark-6024


==================================================================================
```