import re
import subprocess
import sys
import os
import time

# Note that this was made with the assistance of GPT4.

# BASE_DIRECTORY = f"bitmap-dump-{time.strftime('%Y-%m-%d-%H')}"
BASE_DIRECTORY = f"bitmap-dump"


def parse_data(file_path):
    with open(file_path, 'r') as f:
        lines = f.readlines()

    data = []
    for line in lines:
        sector_match = re.search(r'sector: (\d+)', line)
        bytes_match = re.search(r'bytes: (\d+)', line)

        if sector_match and bytes_match:
            sector = int(sector_match.group(1))
            nbytes = int(bytes_match.group(1))
            data.append((line, sector, nbytes))

    return data

def print_hexdump(device, sector, nbytes, line):
    offset = sector
    count = nbytes // 512
    comm = re.search(r'comm: (\w+)', line).group(1)
    rwbs = re.search(r'rwbs: (\w+)', line).group(1)
    dd_cmd = f'sudo dd if={device} skip={offset} count={count} bs=512 2>/dev/null > ./{BASE_DIRECTORY}/offset-{offset}-comm-{comm}-rwbs-{rwbs}.bin'
    print(dd_cmd)
    output = subprocess.check_output(dd_cmd, shell=True)


def main():
    file_path = sys.argv[1]
    device = sys.argv[2]
    os.makedirs(BASE_DIRECTORY, exist_ok=True)

    parsed_data = parse_data(file_path)

    for line, sector, nbytes in parsed_data:
        print(f'Line: {line}')
        print_hexdump(device, sector, nbytes, line)

if __name__ == '__main__':
    main()
