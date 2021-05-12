# nRF Sniffer for 802.15.4

This repository contains firmware and Wireshark extcap plugin and Python script that can be used with the nRF52840 SoC for sniffing 802.15.4 packets.

The software provided has been tested with the nRF52840 DK and the nRF52840 Dongle and with the following operating systems:
* Ubuntu 18.04
* Windows 10
* macOS Mojave

## Dependencies
* Wireshark (Ubuntu package `wireshark`)
* pySerial (Ubuntu package `python-serial` or `python3-serial`)

## Quick start guide

To start using the nRF Sniffer, you must program the firmware, install Wireshark, and configure the nRF Sniffer capture plugin.
See Nordic Semiconductor's [nRF Sniffer for 802.15.4 user guide](https://infocenter.nordicsemi.com/topic/ug_sniffer_802154/UG/sniffer_802154/intro_802154.html) for detailed instructions and complete documentation.
