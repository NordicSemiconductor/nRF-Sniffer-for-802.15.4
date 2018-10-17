# nRF 802.15.4 sniffer

This repository contains firmware and Wireshark extcap script that can be used with nRF52840 chip as an 802.15.4 sniffer.

__Note:__ this project is experimental. There is __no Windows support__ in the current version.

The software provided has been tested with the nRF52840-DK board and Wireshark 2.4.5 from the official Ubuntu 18.04 package.

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
Copy the provided script to the appropriate directory:
```
sudo cp nrf802154_sniffer/nrf802154_sniffer.py /usr/lib/x86_64-linux-gnu/wireshark/extcap/
```

### Start sniffing
1. Run Wireshark.
2. Click the gear icon next to the 'nRF 802.15.4 sniffer'.
3. Select the 802.15.4 channel.
4. Select the serial port associated with the board that you flashed the firmware on.
5. Click 'Start'.
