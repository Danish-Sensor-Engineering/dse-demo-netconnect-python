#!/usr/bin/env python3

"""

Read data from DSE NET-Connect, parse and print results.

"""

import sys
import socket
import struct


# Default socket receive size
BUF_SIZE = 4096


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

    # Check we have at least a full header
    if(len(data) < 22):
        print("invalid size of payload: ", len(data))
        return

    # Check the data begins with our known signature
    _magic = data[:2]
    if(_magic != b'\x1b\x1e'):
        print("invalid magic-id of payload: ", _magic)
        return


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
        _profiles = set()
        for i in range(22, _length - 16):
            x = float.from_bytes(data[i:i+8])
            y = float.from_bytes(data[i+8:i+16])
            _profiles.add(x, y)
        print("version: %d, type: %d, length: %d, sequence: %d, timestamp: %d, profiles: %d" % (_version, _type, _length, _sequence, _timestamp, len(_profiles)))



"""
Main - Connect to DSE NET-Connect 
"""

host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
port = int(sys.argv[2]) if len(sys.argv) > 2 else 2730

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((host, port))

    # Send the 'start' command, terminated with a newline, to receive data
    s.send(b'start')
    s.send(b'\n')

    while True:
        parse(s.recv(BUF_SIZE))

