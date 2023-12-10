#!/usr/bin/env python3

import getopt
import sys
import zlib
from abc import ABCMeta, abstractmethod
from typing import ByteString

class DataDecryptor(metaclass=ABCMeta):
    @abstractmethod
    def encrypt(self, bytestream: ByteString) -> bytes:
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, bytestream: ByteString) -> bytes:
        raise NotImplementedError


class DT01DataDecrypter(DataDecryptor):
    _DEFAULT_BLOCK_LEN: int = 9

    def encrypt(self, bytestream: ByteString) -> bytes:
        bytestream = memoryview(bytearray(zlib.compress(bytestream)))

        length: int = len(bytestream)
        block_len: int = self._DEFAULT_BLOCK_LEN
        block_count: int = length // block_len

        if not block_count:
            block_count = 1
            block_len = length

        block_current_pos: int = 1
        block_remaining: int = block_len
        current_pos: int = 0

        while block_current_pos <= block_len and block_remaining >= 1:
            current_pos = block_count * block_current_pos - 1
            bytestream[current_pos] ^= (block_count * block_remaining) & 0xFF
            block_current_pos += 1
            block_remaining -= 1

        return bytes(bytestream)

    def decrypt(self, bytestream: ByteString) -> bytes:
        bytestream = memoryview(bytearray(bytestream))

        length: int = len(bytestream)
        block_len: int = self._DEFAULT_BLOCK_LEN
        block_count: int = length // block_len

        if not block_count:
            block_count = 1
            block_len = length

        block_current_pos: int = 1
        block_remaining: int = block_len
        current_pos: int = 0

        while block_current_pos <= block_len and block_remaining >= 1:
            current_pos = block_count * block_current_pos - 1
            bytestream[current_pos] ^= (block_count * block_remaining) & 0xFF
            block_current_pos += 1
            block_remaining -= 1

        return zlib.decompress(bytestream)

class DT03DataDecrypter(DataDecryptor):
    _LEN: int = 77

    def _internal(self, bytestream: ByteString, encrypt_length: int) -> bytes:
        bytestream = memoryview(bytearray(bytestream))

        current_pos: int = 0
        encrypt_pos: int = 0

        while encrypt_length - encrypt_pos >= 2:
            bytestream[encrypt_pos] ^= (encrypt_pos + 2) & 0xFF
            bytestream[encrypt_pos + 1] ^= (encrypt_pos + 1) & 0xFF
            bytestream[encrypt_pos + 2] ^= encrypt_pos & 0xFF
            current_pos = encrypt_pos + 3
            encrypt_pos += self._LEN

        return bytes(bytestream)

    def decrypt(self, bytestream: ByteString) -> bytes:
        return self._internal(bytestream, len(bytestream) - 1)

    def encrypt(self, bytestream: ByteString) -> bytes:
        return self._internal(bytestream, len(bytestream))

class EncryptManager:
    encryptors: dict[int, DataDecryptor] = {
        1: DT01DataDecrypter,
        3: DT03DataDecrypter
    }

    def encrypt(self, enctype: int, bytestream: ByteString) -> bytes:
        encryptor = self.encryptors[enctype]

        bytestream = encryptor().encrypt(bytestream)

        return bytes(
            [63, 63, 0, enctype]
        ) + bytestream

    def decrypt(self, bytestream: ByteString) -> bytes:
        if bytestream[0:3] != b"\x3F\x3F\x00":
            raise ValueError("Unmatch magic number")

        decryptor = self.encryptors[bytestream[3]]

        return decryptor().decrypt(bytestream[4:])

def print_help(prog_name):
    print(f"Usage: {prog_name} [OPTIONS]... [FILENAME]")
    print("Encrypt/Decrypt")
    print()
    print("File may be '-' to read from stdin / write to stdout")
    print("Default is decrypt stdin to stdout")
    print()
    print("  -e, --encrypt            Encrypt files")
    print("  -d, --decrypt            Decrypt files (default)")
    print("  -o, --output <FILENAME>  Write output to file (default stdout)")
    print("  -h, --help       Display this help")

def main(argc, argv):
    command_line = getopt.gnu_getopt(argv[1:], "edho:", ["encrypt", "decrypt", "help", "output="])
    input_file = sys.stdin.buffer
    output_file = sys.stdout.buffer
    exec_function = EncryptManager().decrypt

    for option, argument in command_line[0]:
        if option in ("-e", "--encrypt"):
            exec_function = EncryptManager().encrypt

        elif option in ("-d", "--decrypt"):
            exec_function = EncryptManager().decrypt

        elif option in ("-o", "--output"):
            output_file = sys.stdout.buffer if argument == '-' else open(argument, "wb")

        elif option in ("-h", "--help"):
            print_help(argv[0])
            return 0

    if command_line[1]:
        input_file = sys.stdin.buffer if command_line[1] == '-' else open(command_line[1][0], "rb")

    output_file.write(exec_function(input_file.read()))
    return 0

if __name__ == "__main__":
    sys.exit(main(len(sys.argv), sys.argv))
