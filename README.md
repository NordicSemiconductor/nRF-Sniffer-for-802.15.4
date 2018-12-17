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

#### nRF52840-DK
1. Connect the nRF52840-DK to the PC with an USB cable by connecting it to the J2 USB port.
2. Flash the firmware with the following command:
```
nrfjprog -f nrf52 --program nrf802154_sniffer/nrf802154_sniffer.hex --chiperase -r
```
3. J2 USB port can now be optionally disconnected.
4. Connect the nRF52840-DK to J3 nRF USB port.

__Note:__ Sniffer firmware can no longer transport captured packets over J2 USB port. Capture can be carried out using only the J3 nRF USB port.

#### nRF52840-Dongle

1. Download and install [nRF Connect for Desktop](https://www.nordicsemi.com/Software-and-Tools/Development-Tools/nRF-Connect-for-desktop).
2. Click `Add/remove apps` and install `Programmer` application.
3. Plug the dongle to USB port and click reset button to enter DFU mode. Red diode should start blinking.
4. Select `Nordic Semiconductor DFU Bootloader` device from the list.
5. Click `Add HEX file` and select `nrf802154_sniffer_dongle.hex` from `nrf802154_sniffer` directory.
6. Verify that the selected application begins at the `0x00001000` address to avoid overwriting the MBR section.
7. Click `Write` to flash the device.
8. Unplug the dongle from the USB port and plug it again. Do not click the reset button.

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

## Wireshark configuration

### Capturing Thread packets

In order to capture packets exchanged on the Thread network it is necessary to configure the Wireshark to use correct decryption keys.
To set decryption keys go to `Edit -> Preferences... -> Protocols -> IEEE 802.15.4 -> Decryption Keys`. The default decryption key used by nRF5 SDK for Thread and Zigbee examples is `00112233445566778899aabbccddeeff`. Set decryption key index to `0` and `Key hash` to `Thread hash` value.

### Custom Wireshark dissector
Custom wireshark dissector can be used to obtain additional informations from sniffer. Channel, RSSI and LQI can be displayed for every packet.

#### Install Lua dissector
Copy the provided script to the appropriate directory (it can be found in `About Wireshark -> Folders -> Personal Lua Plugins`):
```
sudo cp nrf802154_sniffer/nrf802154_sniffer.lua /usr/lib/x86_64-linux-gnu/wireshark/plugins/
```
#### Modify extcap script
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
