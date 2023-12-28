#!/usr/bin/env python3

import getopt
import io
import pathlib
import sys

# 基本从 file_decrypt.py 里照搬了
def print_help(prog_name):
    print(f"使用方法: {prog_name} [选项]... [输入文件]", file=sys.stderr)
    print("解密人教社光盘 ISO v0.0.1", file=sys.stderr)
    print(file=sys.stderr)
    print("输入 / 输出文件可以是 `-' 以从标准输入读取 / 写入到标准输出", file=sys.stderr)
    print("默认行为是解密标准输入到标准输出", file=sys.stderr)
    print(file=sys.stderr)
    print("  -o, --output <输出文件>   写入输出到 <输出文件> (默认为标准输出)", file=sys.stderr)
    print("                            (如果 <输出文件> 存在且 `-r' 没有指定, 则抛出错误)", file=sys.stderr)
    # 跟着文件解密脚本走了 (虽然我可以改成 -d)
    print("  -f, --dir <目录>          将输出文件放置在 <目录> 下", file=sys.stderr)
    print("                            (不可与 `-r' 同时使用)", file=sys.stderr)
    print("  -r, --replace             如果没有 `-o', 则替换输入文件 (除非是标准输入)", file=sys.stderr)
    print("                            如果有 `-o', 则强制覆盖指定的输出文件", file=sys.stderr)
    print("  -h, --help                显示这个帮助", file=sys.stderr)

def main(argc, argv):
    command_line = getopt.gnu_getopt(
        argv[1:], "e:do:rf:h",
        ["encrypt=", "decrypt", "output=", "replace", "dir=", "help"]
    )
    input_file = sys.stdin.buffer
    output_file = '-'
    replace = False
    output_dir = pathlib.Path()

    for option, argument in command_line[0]:
        if option in ("-o", "--output"):
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

    # ISO 的结构: https://wiki.osdev.org/ISO_9660
    # data 原本是文件夹, 但在 ISO 里用 flag 被标记成了一个文件
    # 我们把 flag 改成文件夹即可

    # 输入文件可能是标准输入, 我们没法确定它的大小
    # 所以用传统的 .read()
    data = io.BytesIO(input_file.read())

    if len(data.getbuffer()) < 0x8000:
        # 文件被截断 (有可能直接在终端里读标准输入了)
        print("文件被截断", file=sys.stderr)
        return 1

    # LBA = ?
    data.seek(0x8882)
    lba_size = int.from_bytes(data.read(2))

    # goto root directory entry
    data.seek(0x88A2)
    data.seek(lba_size * int.from_bytes(data.read(4)))

    # 找 "data/"
    while True:
        length = int.from_bytes(data.read(2), "little")
        tmp_data = data.read(length - 2)
        if b"d\x00a\x00t\x00a\x00" in tmp_data:
            data.seek(-length, io.SEEK_CUR)
            break

    # 修改 flag
    data.seek(25, io.SEEK_CUR)
    data.write(b'\x06')

    if output_file == '-':
        sys.stdout.buffer.write(data.getbuffer())
    else:
        with open(output_dir / output_file, "wb" if replace else "xb") as output_file_obj:
            output_file_obj.write(data.getbuffer())

    return 0

if __name__ == "__main__":
    sys.exit(main(len(sys.argv), sys.argv))
