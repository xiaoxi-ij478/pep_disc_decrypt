#!/usr/bin/env python3

import getopt
import os
import pathlib
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


class UnmatchMagicNumberError(ValueError):
    pass


_in_script = False
class EncryptManager:
    encryptors: dict[int, DataDecryptor] = {
        1: DT01DataDecrypter,
        3: DT03DataDecrypter
    }

    def encrypt(self, enctype: int, bytestream: ByteString) -> bytes:
        if _in_script:
            print("使用加密算法", enctype, file=sys.stderr)

        encryptor = self.encryptors[enctype]

        bytestream = encryptor().encrypt(bytestream)

        return bytes(
            [63, 63, 0, enctype]
        ) + bytestream

    def decrypt(self, bytestream: ByteString) -> bytes:
        if bytestream[0:3] != b"\x3F\x3F\x00":
            raise UnmatchMagicNumberError("Unmatch magic number")

        if _in_script:
            print("使用加密算法", bytestream[3], file=sys.stderr)

        decryptor = self.encryptors[bytestream[3]]

        return decryptor().decrypt(bytestream[4:])


def print_help(prog_name):
    print(f"使用方法: {prog_name} [选项]... [输入文件]", file=sys.stderr)
    print("加密 / 解密人教社光盘的文件 v0.0.1", file=sys.stderr)
    print(file=sys.stderr)
    print("输入 / 输出文件可以是 `-' 以从标准输入读取 / 写入到标准输出", file=sys.stderr)
    print("默认行为是解密标准输入到标准输出", file=sys.stderr)
    print(file=sys.stderr)
    print("  -e, --encrypt <算法 ID>   使用 <算法 ID> 加密文件", file=sys.stderr)
    print("  -d, --decrypt             解密文件 (默认行为)", file=sys.stderr)
    print("  -o, --output <输出文件>   写入输出到 <输出文件> (默认为标准输出)", file=sys.stderr)
    print("                            (如果 <输出文件> 存在且 `-r' 没有指定, 则抛出错误)", file=sys.stderr)
    # -d, -r 都被用了 :O
    print("  -f, --dir <目录>          将输出文件放置在 <目录> 下", file=sys.stderr)
    print("                            (不可与 `-r' 同时使用)", file=sys.stderr)
    print("  -r, --replace             如果没有 `-o', 则替换输入文件 (除非是标准输入)", file=sys.stderr)
    print("                            如果有 `-o', 则强制覆盖指定的输出文件", file=sys.stderr)
    print("  -h, --help                显示这个帮助", file=sys.stderr)

def main(argc, argv):
    # 我的命令行写的就是个垃圾, 凑合看吧

    command_line = getopt.gnu_getopt(
        argv[1:], "e:do:rf:h",
        ["encrypt=", "decrypt", "output=", "replace", "dir=", "help"]
    )
    input_file = sys.stdin.buffer
    output_file = '-'
    replace = False
    encrypt = False
    output_dir = pathlib.Path()

    for option, argument in command_line[0]:
        if option in ("-e", "--encrypt"):
            encrypt_algorithm = int(argument)
            encrypt = True

        elif option in ("-d", "--decrypt"):
            encrypt = False

        elif option in ("-o", "--output"):
            output_file = argument

        elif option in ("-r", "--replace"):
            replace = True

        elif option in ("-f", "--dir"):
            output_dir = pathlib.Path(argument)

        elif option in ("-h", "--help"):
            print_help(argv[0])
            return 0

    if command_line[1]:
        input_file = sys.stdin.buffer if command_line[1] == '-' else open(command_line[1][0], "rb")

        # 如果指定了输入文件和替换文件, 那么把输出文件设置为输入文件
        if output_file == '-' and replace:
            output_file = command_line[1][0]

    data = input_file.read()

    if encrypt:
        # 如果有 <文件名>.enc_algo, 从那里获取加密算法 ID
        # 前提是不从标准输入读数据

        # 当前版本就算有 .enc_algo, 命令行也得指定一个加密算法 ID
        # 因为 Python 的 getopt 库还不支持 e:: 这种选项
        # (我不想学什么 optparse)
        if (
            input_file is not sys.stdin.buffer and
            os.access(input_file.name + ".enc_algo", os.R_OK)
        ):
            encrypt_algorithm = int(open(input_file.name + ".enc_algo").read())

        processed_data = EncryptManager().encrypt(encrypt_algorithm, data)
    else:
        try:
            processed_data = EncryptManager().decrypt(data)
        except UnmatchMagicNumberError:
            print("文件未加密", file=sys.stderr)
            return 1

    if output_file == '-':
        sys.stdout.buffer.write(processed_data)
    else:
        # 把加密算法 ID 写到<文件名>.enc_algo 里,
        # 下次加密的时候用 (如果写不进去就算了)
        try:
            print(data[3], file=open(output_dir / (output_file + ".enc_algo"), "w"))
        except:
            pass

        with open(output_dir / output_file, "wb" if replace else "xb") as output_file_obj:
            output_file_obj.write(processed_data)

    return 0

if __name__ == "__main__":
    # 显示 "使用加密算法 1/3"
    _in_script = True
    sys.exit(main(len(sys.argv), sys.argv))
