#!/usr/bin/python2.7

import argparse
import crc16

import sys

"""
Read the hex digit data of a DDR-3 SPD dump in the format written by i2cdump,
show what the checksum is and should be, and warn if it doesn't match,
and optionally output a binary version of it.
"""


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("input_filename", help="filename of the hex dump to read")
    parser.add_argument("--output", help="write an SPD file in binary form", metavar="FILENAME")
    return parser.parse_args()


def die(msg):
    print >> sys.stderr, msg
    sys.exit(1)


def read_hexdump(input_filename):
    try:
        with open(input_filename, "r") as handle:
            data = handle.read()
    except IOError, e:
        if e.errno == 2:
            die("File %s not found" % input_filename)
        raise
    lines = data.split("\n")
    data_bytes = []
    pos = 0
    for line in lines[1:]:
        if line == "":
            continue
        prefix = "%02x: " % pos
        assert line.startswith(prefix)
        parts = line[len(prefix):].split(" ")
        parts = parts[:16]
        assert len(parts) == 16

        for part in parts:
            x = int(part, 16)
            data_bytes.append(chr(x))

        pos += 16
    data_bytes = "".join(data_bytes)
    return data_bytes


def main():
    options = parse_args()
    input_filename = options.input_filename

    print "Reading hex digits from %s" % input_filename
    spd_bytes = read_hexdump(input_filename)

    expected_len = 256
    if len(spd_bytes) != expected_len:
        die("Invalid length %d bytes (expected %d bytes)" % (len(spd_bytes), expected_len))

    spd_revision = ord(spd_bytes[1])
    if spd_revision != 0x11:
        die("Unexpected SPD revision 0x%02x" % spd_revision)

    # This is only intended to work on a DDR-3 SPD
    basic_memory_type = ord(spd_bytes[2])
    if basic_memory_type != 11:
        die("Not a DDR-3 SPD (basic memory type 0x%02x)" % basic_memory_type)

    read_crc_first = ord(spd_bytes[0x7e])
    read_crc_second = ord(spd_bytes[0x7f])

    print "Read CRC16 bytes at 0x7e, 0x7f: %02x %02x" % (read_crc_first, read_crc_second)

    if ord(spd_bytes[0]) & 0x80:
        num_bytes_to_crc = 117
    else:
        num_bytes_to_crc = 126

    print "Calculating CRC16 on %d bytes" % num_bytes_to_crc
    bytes_to_crc = spd_bytes[:num_bytes_to_crc]
    crc_val = crc16.crc16xmodem(bytes_to_crc)

    calculated_crc_first = crc_val & 0xff
    calculated_crc_second = crc_val >> 8

    print "Calculated CRC16 bytes: %02x %02x" % (calculated_crc_first, calculated_crc_second)

    if (calculated_crc_first, calculated_crc_second) != (read_crc_first, read_crc_second):
        print >> sys.stderr, "WARNING: Checksum in the SPD is incorrect!"

    if options.output:
        output_filename = options.output
        print "Writing binary SPD file %s" % output_filename
        with open(output_filename, "wb") as handle:
            handle.write(spd_bytes)


if __name__ == "__main__":
    main()
