#!/usr/bin/env python3

"""

Read data from DSE NET-Connect, parse and print results.

"""
import errno
import fcntl
import os
import sys
import socket
import struct
import time

# Header size
HEADER_SIZE = 22

# Default socket receive size
BUF_SIZE = HEADER_SIZE


""""
Parse the DSE NET-Connect Measurement Datagram

<---------------------- HEADER 22 bytes -------------------->     <----- DATA ----->
_short   _short   _short    _int       _int      _long
2-bytes  2-bytes  2-bytes  4-bytes   4-bytes    8-bytes
ID  VERSION     TYPE   LENGTH  SEQUENCE  TIMESTAMP

- ID: Unique fingerprint for this kind of binary payload
- VERSION: To accommodate future changes
- TYPE: Error (1), Distance Sensor (11) or Profile Scanner (21 - 24)
- LENGTH: Size of datagram including header of 22 bytes
- SEQUENCE: Counter that wraps at MAX and starts over
- TIMESTAMP: Time in milliseconds (Unix Epoch) when measurement was received from device
- DATA: Depends on TYPE
- int (4-bytes) when ERROR and DISTANCE
- list (no. points in sweep) of 2 x double (8-bytes) for X & Y coordinates when PROFILE
"""
def parse(data):
    global BUF_SIZE

    ###
    ### Parse header
    ###

    _version = int.from_bytes(data[2:4])
    _type = int.from_bytes(data[4:6])
    _length = int.from_bytes(data[6:10])
    _sequence = int.from_bytes(data[10:14])
    _timestamp = int.from_bytes(data[14:22])

    # Adjust buffer size
    if(_length != BUF_SIZE):
        BUF_SIZE = _length
        print("Changing socket recv. buffer to: ", _length)


    ###
    ### Parse data
    ###

    # Type: error
    if(_type == 1):
        _error = int.from_bytes(data[22:26])
        print("version: %d, type: %d, length: %d, timestamp: %d, error: %d" % (_version, _type, _length, _timestamp, _error))

    # Type: distance
    if(_type == 11):
        _distance = int.from_bytes(data[22:26])
        print("version: %d, type: %d, length: %d, sequence: %d, timestamp: %d, distance: %d" % (_version, _type, _length, _sequence, _timestamp, _distance))

    # Type: profile
    if(_type >= 21 and _type <= 24):
        _profiles = []
        for i in range(22, _length, 16):
            x_bytes = data[i:i+8]
            y_bytes = data[i+8:i+16]
            if(len(x_bytes) == 8 and len(y_bytes) == 8):
                x = struct.unpack('d', data[i:i+8])
                y = struct.unpack('d', data[i+8:i+16])
                _profiles.append({x, y})
        print("version: %d, type: %d, length: %d, sequence: %d, timestamp: %d, profiles: %d" % (_version, _type, _length, _sequence, _timestamp, len(_profiles)))



"""
Main - Connect to DSE NET-Connect 
"""

host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 2730

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((host, port))
    fcntl.fcntl(s, fcntl.F_SETFL, os.O_NONBLOCK)

    # Send the 'start' command, terminated with a newline, to receive data
    s.send(b'start')
    s.send(b'\n')

    while True:
        try:
            msg = s.recv(BUF_SIZE)
        except socket.error as e:
            err = e.args[0]
            if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                time.sleep(0.1)
                continue
            else:
                # a "real" error occurred
                print(e)
                sys.exit(1)
        else:
            _magic = msg[:2]
            if(_magic == b'\x1b\x1e'):
                parse(msg)

