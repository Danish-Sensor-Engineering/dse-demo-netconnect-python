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
import logging

# Header size
HEADER_SIZE = 22

# Default socket receive size
BUF_SIZE = HEADER_SIZE

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


""""
Parse the DSE NET-Connect Network Payload

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
"""
def parse(data):
    global BUF_SIZE

    # Validate data length
    if len(data) < HEADER_SIZE:
        logger.error("Received data too short: %d bytes", len(data))
        return

    ###
    ### Parse header
    ###

    try:
        _version = int.from_bytes(data[2:4])
        _type = int.from_bytes(data[4:6])
        _length = int.from_bytes(data[6:10])
        _sequence = int.from_bytes(data[10:14])
        _timestamp = int.from_bytes(data[14:22])

        # Adjust buffer size
        if _length != BUF_SIZE:
            BUF_SIZE = _length
            logger.info("Changing socket recv buffer to: %d", _length)

        # Validate full payload
        if len(data) < _length:
            logger.error("Received data too short: expected %d, got %d", _length, len(data))
            return

        # Handle error type
        if _type == 1:
            _error = int.from_bytes(data[22:26])
            logger.info("version: %d, type: %d, length: %d, timestamp: %d, error: %d",
                        _version, _type, _length, _timestamp, _error)

        # Handle distance sensor
        elif _type == 11:
            _distance = int.from_bytes(data[22:26])
            logger.info("version: %d, type: %d, length: %d, sequence: %d, timestamp: %d, distance: %d",
                        _version, _type, _length, _sequence, _timestamp, _distance)

        # Handle profile scanner (type 21–24)
        elif 21 <= _type <= 24:
            _profiles = []
            for i in range(22, _length, 20):
                p_bytes = data[i:i+4]
                x_bytes = data[i+4:i+12]
                y_bytes = data[i+12:i+20]

                if len(p_bytes) == 4 and len(x_bytes) == 8 and len(y_bytes) == 8:
                    try:
                        polar_distance = struct.unpack('f', p_bytes)[0]
                        x = struct.unpack('d', x_bytes)[0]
                        y = struct.unpack('d', y_bytes)[0]
                        _profiles.append({
                            'polar_distance': polar_distance,
                            'x': x,
                            'y': y
                        })
                    except struct.error as e:
                        logger.error("Failed to unpack profile data at offset %d: %s", i, e)
                        continue
                else:
                    logger.warning("Invalid profile data at offset %d", i)
                    continue

            logger.info("version: %d, type: %d, length: %d, sequence: %d, timestamp: %d, profiles: %d",
                        _version, _type, _length, _sequence, _timestamp, len(_profiles))

        else:
            logger.warning("Unknown type: %d", _type)


    except (struct.error, ValueError, IndexError) as e:
        logger.error("Error parsing header or data: %s", e)


"""
Main - Connect to DSE NET-Connect
"""

if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 2730

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            fcntl.fcntl(s, fcntl.F_SETFL, os.O_NONBLOCK)

            # Send the 'start' command
            s.send(b'start\n')

            logger.info("Connected to %s:%d. Waiting for data...", host, port)

            while True:
                try:
                    msg = s.recv(BUF_SIZE)
                except socket.error as e:
                    err = e.args[0]
                    if err == errno.EAGAIN or err == errno.EWOULDBLOCK:
                        time.sleep(0.1)
                        continue
                    else:
                        logger.error("Socket error: %s", e)
                        sys.exit(1)
                else:
                    if len(msg) >= 2:
                        _magic = msg[:2]
                        if _magic == b'\x1b\x1e' and len(msg) >= HEADER_SIZE:
                            parse(msg)
                    else:
                        logger.debug("Received empty message")

    except KeyboardInterrupt:
        logger.info("Received interrupt. Exiting gracefully.")
        sys.exit(0)
    except Exception as e:
        logger.error("Unexpected error: %s", e)
        sys.exit(1)


