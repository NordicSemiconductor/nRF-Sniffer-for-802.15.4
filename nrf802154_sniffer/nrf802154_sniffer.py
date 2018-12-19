#!/usr/bin/env python

# Copyright 2018, Nordic Semiconductor ASA
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of Nordic Semiconductor ASA nor the names of its
#    contributors may be used to endorse or promote products derived from this
#    software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import sys
import os

is_standalone = __name__ == '__main__'

if sys.version[0] == '2':
    # py2 support
    import Queue as Queue
else:
    import queue as Queue

if __name__ == '__main__':
    sys.path.insert(0, os.getcwd())


import re
import signal
import struct
import threading
import time
import logging
from argparse import ArgumentParser
from binascii import a2b_hex
from distutils.sysconfig import get_python_lib
from serial import Serial, serialutil
from serial.tools.list_ports import comports


class Nrf802154Sniffer(object):

    # Various options for pcap files: http://www.tcpdump.org/linktypes.html
    #DLT='user'
    DLT='802.15.4'
    DLT_NO = 147 if DLT == 'user' else 230

    # helper for wireshark arg parsing
    CTRL_ARG_CHANNEL = 0

    # pattern for packets being printed over serial
    RCV_REGEX = 'received:\s+([0-9a-fA-F]+)\s+power:\s+(-?\d+)\s+lqi:\s+(\d+)\s+time:\s+(-?\d+)'

    def __init__(self):
        self.serial_queue = Queue.Queue()
        self.running = threading.Event()
        self.setup_done = threading.Event()
        self.setup_done.clear()
        self.logger = logging.getLogger(__name__)
        self.dev = None
        self.channel = None
        self.threads = []

    def stop_sig_handler(self, *args, **kwargs):
        """
        Function responsible for stopping the sniffer firmware and closing all threads.
        """
        # Let's wait with closing afer we're sure that the sniffer started. Protects us
        # from very short tests (NOTE: the serial_reader has a delayed started)
        while self.running.is_set() and not self.setup_done.is_set():
            time.sleep(1)

        if self.running.is_set():
            self.serial_queue.put(b'')
            self.serial_queue.put(b'sleep')
            self.running.clear()

            alive_threads = []
            
            for thread in self.threads:
                try:
                    thread.join(timeout=10)
                    if thread.is_alive() is True:
                        self.logger.error("Failed to stop a thread")
                        alive_threads.append(thread)
                except RuntimeError:
                    # TODO: This may be called from one of threads from thread list - architecture problem
                    pass

            self.threads = alive_threads
        else:
            self.logger.warning("Asked to stop {} while it was already stopped".format(self))

    @staticmethod
    def get_hex_path():
        """Helper method to get hex file path with nrf802154_sniffer firmware.
        :return path to hex file with nrf802154_sniffer firmware
        """

        return os.path.join(get_python_lib(), 'nrf802154_sniffer', 'nrf802154_sniffer.hex')

    @staticmethod
    def extcap_interfaces():
        """
        Wireshark-related method that returns configuration options
        :return: string with wireshark-compatible information
        """
        # TODO: Detect connected sniffers and print one interface per each sniffer
        res = []
        res.append("extcap {version=1.0}{help=https://github.com/NordicSemiconductor/nRF-IEEE-802.15.4-radio-driver}{display=nRF 802.15.4 sniffer}")
        res.append("interface {value=nrf802154}{display=nRF 802.15.4 sniffer}")
        res.append("control {number=%d}{type=selector}{display=Channel}{tooltip=IEEE 802.15.4 channel}" % Nrf802154Sniffer.CTRL_ARG_CHANNEL)

        for i in range(11, 27):
            res.append("value {control=%d}{value=%d}{display=%d}" % (Nrf802154Sniffer.CTRL_ARG_CHANNEL, i, i))
        return "\n".join(res)

    @staticmethod
    def extcap_dlts():
        """
        Wireshark-related method that returns configuration options
        :return: string with wireshark-compatible information
        """
        return "dlt {number=%d}{name=IEEE802_15_4_NOFCS}{display=IEEE 802.15.4 without FCS}" % Nrf802154Sniffer.DLT_NO

    @staticmethod
    def extcap_config(option):
        """
        Wireshark-related method that returns configuration options
        :return: string with wireshark-compatible information
        """
        def list_comports():
            result = []
            for port in comports():
                result.append ( (1, port[0], port[0], "false") )
            return result

        args = []
        values = []
        res =[]

        args.append ( (0, '--channel', 'Channel', 'IEEE 802.15.4 channel', 'selector', '{required=true}{default=11}') )
        # TODO: Instead of 'dev', 'interface' should define connected sniffer.
        args.append ( (1, '--dev', 'Device', 'Serial device connected to the sniffer', 'selector', '{required=true}{reload=true}{placeholder=Loading serial devices ...}'))

        if option == "dev":
            values = list_comports()

        if len(option) <= 0:
            for arg in args:
                res.append("arg {number=%d}{call=%s}{display=%s}{tooltip=%s}{type=%s}%s" % arg)

            values = values + [ (0, "%d" % i, "%d" % i, "true" if i == 11 else "false" ) for i in range(11,27) ]
            values = values + list_comports()

        for value in values:
            res.append("value {arg=%d}{value=%s}{display=%s}{default=%s}" % value)
        return "\n".join(res)

    def pcap_header(self):
        """
        Returns pcap header to be written into pcap file.
        """
        header = bytearray()
        header += struct.pack('<L', int ('a1b2c3d4', 16 ))
        header += struct.pack('<H', 2 ) # Pcap Major Version
        header += struct.pack('<H', 4 ) # Pcap Minor Version
        header += struct.pack('<I', int(0)) # Timezone
        header += struct.pack('<I', int(0)) # Accurancy of timestamps
        header += struct.pack('<L', int ('000000ff', 16 )) # Max Length of capture frame
        header += struct.pack('<L', self.DLT_NO) # DLT
        return header

    @staticmethod
    def pcap_packet(frame, channel, rssi, lqi, timestamp):
        """
        Creates pcap packet to be seved in pcap file.
        """
        pcap = bytearray()

        caplength = len(frame)

        if Nrf802154Sniffer.DLT == 'user':
            caplength += 6
        pcap += struct.pack('<L', timestamp // 1000000 ) # timestamp seconds
        pcap += struct.pack('<L', timestamp % 1000000 ) # timestamp nanoseconds
        pcap += struct.pack('<L', caplength ) # length captured
        pcap += struct.pack('<L', caplength ) # length in frame

        if Nrf802154Sniffer.DLT == 'user':
            pcap += struct.pack('<H', channel)
            pcap += struct.pack('<h', rssi)
            pcap += struct.pack('<H', lqi)

        pcap += frame

        return pcap

    @staticmethod
    def control_read(fn):
        """
        Method used for reading wireshark command.
        """
        try:
            header = fn.read(6)
            sp, _, length, arg, typ = struct.unpack('>sBHBB', header)
            if length > 2:
                payload = fn.read(length - 2)
            else:
                payload = ''
            return arg, typ, payload
        except:
            return None, None, None

    def control_reader(self, fifo):
        """
        Thread responsible for reading wireshark commands (read from fifo).
        Related to not-yet-implemented wireshark toolbar features.
        """
        with open(fifo, 'rb', 0 ) as fn:
            arg = 0
            while arg != None:
                arg, typ, payload = Nrf802154Sniffer.control_read(fn)
            self.stop_sig_handler()

    def control_writer(self, fifo, queue):
        """
        Thread responsible for sending wireshark commands (read from fifo).
        Related to not-yet-implemented wireshark toolbar features.
        """
        with open(fifo, 'wb', 0 ) as fn:
            while self.running.is_set():
                time.sleep(1)

    def serial_write(self, ser):
        """
        Function responsible for sending commands to serial port
        """
        command = self.serial_queue.get(block=True, timeout=1)
        try:
            ser.write(command + b'\r\n')
            ser.write(b'\r\n')
        except IOError:
            self.logger.error("Cannot write to {}".format(self))
            self.running.clear()

    def serial_writer(self, ser):
        """
        Thread responsible for sending commands to serial port
        """
        while self.running.is_set():
            try:
                self.serial_write(ser)
            except Queue.Empty:
                pass

        # Write final commands and break out
        while True:
            try:
                self.serial_write(ser)
            except Queue.Empty:
                break

    def serial_reader(self, dev, channel, queue):
        """
        Thread responsible for reading from serial port, parsing the output and storing parsed packets into queue.
        """
        # Wireshark needs this sleep for reset purposes
        time.sleep(2)
        try:
            with Serial(dev, timeout=1) as ser:
                ser.reset_input_buffer()
                ser.reset_output_buffer()

                writer_thread = threading.Thread(target=self.serial_writer, args=(ser,), name="writer_thread")
                writer_thread.start()

                buf = b''

                #TODO: Disable auto ack
                init_cmd = []
                init_cmd.append(b'')
                init_cmd.append(b'promiscuous on')
                init_cmd.append(b'channel ' + bytes(str(channel).encode()))
                for cmd in init_cmd:
                    self.serial_queue.put(cmd)

                # serial_write appends twice '\r\n' to each command, so we have to calculate that for the echo
                init_res = ser.read(len(b"".join(c + b"\r\n\r\n" for c in init_cmd)))

                if not all(cmd.decode() in init_res.decode() for cmd in init_cmd):
                    msg = "{} did not reply properly to setup commands. Is it flashed properly? " \
                          "Recieved: {}\n".format(self, init_res)
                    self.logger.error(msg)

                self.serial_queue.put(b'receive')
                self.setup_done.set()
                while self.running.is_set():
                    ch = ser.read()
                    if ch != b'\n':
                        buf += ch
                    else:
                        m = re.search(self.RCV_REGEX, str(buf))
                        if m:
                            packet = a2b_hex(m.group(1)[:-4])
                            rssi = int(m.group(2))
                            lqi = int(m.group(3))
                            timestamp = int(m.group(4)) & 0xffffffff
                            channel = int(channel)
                            queue.put(self.pcap_packet(packet, channel, rssi, lqi, timestamp))
                        buf = b''

                writer_thread.join()

                # Let's clear serial link buffer after writer_thread is finished.
                while ser.read():
                    pass
        except (serialutil.SerialException, serialutil.SerialTimeoutException):
            raise RuntimeError("Cannot communicate with '{}' serial device: {}".format(self, dev))
        finally:
            self.setup_done.set()  # in case it wasn't set before
            if self.running.is_set():  # another precaution
                self.stop_sig_handler()

    def fifo_writer(self, fifo, queue):
        """
        Thread responsible for writing packets into pcap file/fifo from queue.
        """
        with open(fifo, 'wb', 0 ) as fh:
            fh.write(self.pcap_header())
            fh.flush()

            while self.running.is_set():
                try:
                    packet = queue.get(block=True, timeout=1)
                    try:
                        if is_standalone:
                            sys.stdout.write('.')
                            sys.stdout.flush()
                        fh.write(packet)
                        fh.flush()
                    except IOError:
                        pass
                except Queue.Empty:
                    pass

    def extcap_capture(self, fifo, dev, channel, control_in=None, control_out=None):
        """
        Main method responsible for starting all other threads. In case of standalone execution this method will block
        until SIGTERM/SIGINT and/or stop_sig_handler disables the loop via self.running event.
        """

        if len(self.threads):
            raise RuntimeError("Old threads were not joined properly")

        packet_queue = Queue.Queue()
        self.channel = channel
        self.dev = dev
        self.running.set()

        # TODO: Add toolbar with channel selector (channel per interface?)
        if control_in:
            self.threads.append(threading.Thread(target=self.control_reader, args=(control_in,)))

        self.threads.append(threading.Thread(target=self.serial_reader, args=(self.dev, self.channel, packet_queue), name="serial_thread"))
        self.threads.append(threading.Thread(target=self.fifo_writer, args=(fifo, packet_queue), name="fifo_thread"))

        for thread in self.threads:
            thread.start()

        while is_standalone and self.running.is_set():
            time.sleep(1)

    @staticmethod
    def parse_args():
        """
        Helper methods to make the standalone script work in console and wireshark
        """
        parser = ArgumentParser(description="Extcap program for the nRF 802.15.4 sniffer")

        parser.add_argument("--extcap-interfaces", help="Provide a list of interfaces to capture from", action="store_true")
        parser.add_argument("--extcap-interface", help="Provide the interface to capture from")
        parser.add_argument("--extcap-dlts", help="Provide a list of dlts for the given interface", action="store_true")
        parser.add_argument("--extcap-config", help="Provide a list of configurations for the given interface", action="store_true")
        parser.add_argument("--extcap-reload-option", help="Reload elements for the given option")
        parser.add_argument("--capture", help="Start the capture routine", action="store_true" )
        parser.add_argument("--fifo", help="Use together with capture to provide the fifo to dump data to")
        parser.add_argument("--extcap-capture-filter", help="Used together with capture to provide a capture filter")
        parser.add_argument("--extcap-control-in", help="Used to get control messages from toolbar")
        parser.add_argument("--extcap-control-out", help="Used to send control messages to toolbar")

        parser.add_argument("--channel", help="IEEE 802.15.4 capture channel [11-26]")
        parser.add_argument("--dev", help="Serial device connected to the sniffer")

        result = parser.parse_args()

        if result.capture and not result.dev:
            parser.error("--dev is required if --capture is present")

        return result

    def __str__(self):
        return "{} ({}) channel {}".format(type(self).__name__, self.dev, self.channel)

    def __repr__(self):
        return self.__str__()


if is_standalone:
    args = Nrf802154Sniffer.parse_args()

    logging.basicConfig(format='%(asctime)s [%(levelname)s] %(message)s', level=logging.INFO)

    sniffer_comm = Nrf802154Sniffer()

    if args.extcap_interfaces:
        print(sniffer_comm.extcap_interfaces())
    
    if args.extcap_dlts:
        print(sniffer_comm.extcap_dlts())

    if args.extcap_config:
        if args.extcap_reload_option and len(args.extcap_reload_option) > 0:
            option = args.extcap_reload_option
        else:
            option = ''
        print(sniffer_comm.extcap_config(option))

    if args.capture and args.fifo:
        channel = args.channel if args.channel else 11
        signal.signal(signal.SIGINT, sniffer_comm.stop_sig_handler)
        signal.signal(signal.SIGTERM, sniffer_comm.stop_sig_handler)
        try:
            sniffer_comm.extcap_capture(args.fifo, args.dev, channel, args.extcap_control_in, args.extcap_control_out)
        except KeyboardInterrupt as e:
            sniffer_comm.stop_sig_handler()

