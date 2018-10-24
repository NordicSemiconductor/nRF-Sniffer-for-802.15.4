# nRF 802.15.4 sniffer

This repository contains firmware and Wireshark extcap script that can be used with nRF52840 chip as an 802.15.4 sniffer.

__Note:__ this project is experimental.

The software provided has been tested with the nRF52840-DK board and the following operating systems:
* Ubuntu 18.04 (Wireshark 2.4.5 from the official package, Wireshark 2.6.4)
* Windows 10 (Wireshark 2.6.3)
* macOS Mojave (Wireshark 2.6.4)

## Dependencies
* Wireshark (Ubuntu package `wireshark`)
* pySerial (Ubuntu package `python-serial` or `python3-serial`)

## Quick start guide

To start using the sniffer, you must flash the firmware, install the script, and configure the sniffer in Wireshark.

### Flash firmware
1. Connect the nRF52840-DK to the PC with an USB cable by connecting it to the J2 USB port.
2. Flash the firmware with the following command:
```
nrfjprog -f nrf52 --program nrf802154_sniffer/nrf802154_sniffer.hex --chiperase -r
```

### Install extcap script

To find the correct installation path of the extcap utility on any system please see:
```
"Help" -> "About Wireshark" -> "Folders" -> "Extcap path"
```
Copy the provided `nrf802154_sniffer.py` script to the extcap directory.

__Note to Windows users:__ `nrf802154_sniffer.bat` has to be copied to the same directory as well.
Ensure that Python directory is included in your `PATH` system environment variable.

### Start sniffing
1. Run Wireshark.
2. Click the gear icon next to the 'nRF 802.15.4 sniffer'.
3. Select the 802.15.4 channel.
4. Select the serial port associated with the board that you flashed the firmware on.
5. Click 'Start'.

## Custom Wireshark dissector
Custom wireshark dissector can be used to obtain additional informations from sniffer. Channel, RSSI and LQI can be displayed for every packet.

### Install Lua dissector
Copy the provided script to the appropriate directory (it can be found in `About Wireshark -> Folders -> Personal Lua Plugins`):
```
sudo cp nrf802154_sniffer/nrf802154_sniffer.lua /usr/lib/x86_64-linux-gnu/wireshark/plugins/
```
### Modify extcap script
Modify `nrf802154_sniffer.py`:

`sudo nano /usr/lib/x86_64-linux-gnu/wireshark/extcap/nrf802154_sniffer.py`
- Uncomment line 64:
    ```python
    DLT='user'
    ```
- Comment line 65:
    ```python
    #DLT='802.15.4'
    ```
