# Copyright (c) 2015-2024 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

"""Headless script for demonstrating Binary Ninja automated base address detection for
raw position-dependent firmware binaries
"""

import argparse
import json
from os import walk, path
from binaryninja import BaseAddressDetection, log_to_stderr, LogLevel, log_info, log_error


def _get_directory_listing(_path: str) -> list[str]:
    if path.isfile(_path):
        return [_path]

    if not path.isdir(_path):
        raise FileNotFoundError(f"Path '{_path}' is not a file or directory")

    files = []
    for dirpath, _, filenames in walk(_path):
        for filename in filenames:
            files.append(path.join(dirpath, filename))
    return files


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="detect base address of position-dependent raw firmware binaries")
    parser.add_argument("path", help="path to the position-dependent raw firmware binary or directory")
    parser.add_argument("--debug", action="store_true", help="enable debug logging")
    parser.add_argument("--reasons", action="store_true", help="show reasons for base address selection")
    parser.add_argument("--analysis", type=str, help="analysis level", default="full")
    parser.add_argument("--arch", type=str, default="", help="architecture of the binary")
    return parser.parse_args()


def _setup_logger(debug: bool) -> None:
    if debug:
        log_to_stderr(LogLevel.DebugLog)
    else:
        log_to_stderr(LogLevel.InfoLog)


def main() -> None:
    """Run the program"""
    args = _parse_args()
    _setup_logger(args.debug)

    files = _get_directory_listing(args.path)
    for _file in files:
        log_info(f"Running base address detection analysis on '{_file}'...")
        bad = BaseAddressDetection(_file)
        if not bad.detect_base_address(analysis=args.analysis, arch=args.arch):
            log_error("Base address detection analysis failed")
            continue

        json_dict = dict()
        json_dict["filename"] = path.basename(_file)
        json_dict["preferred_candidate"] = dict()
        json_dict["preferred_candidate"]["address"] = f"0x{bad.preferred_base_address:x}"
        json_dict["preferred_candidate"]["confidence"] = bad.confidence
        json_dict["aborted"] = bad.aborted
        json_dict["last_tested"] = f"0x{bad.last_tested_base_address:x}"
        json_dict["candidates"] = dict()
        for baseaddr, score in bad.scores:
            json_dict["candidates"][f"0x{baseaddr:x}"] = dict()
            json_dict["candidates"][f"0x{baseaddr:x}"]["score"] = score
            json_dict["candidates"][f"0x{baseaddr:x}"]["function hits"] = bad.get_function_hits(baseaddr)
            json_dict["candidates"][f"0x{baseaddr:x}"]["string hits"] = bad.get_string_hits(baseaddr)
            json_dict["candidates"][f"0x{baseaddr:x}"]["data hits"] = bad.get_data_hits(baseaddr)
            if args.reasons:
                json_dict["candidates"][f"0x{baseaddr:x}"]["reasons"] = dict()
                for reason in bad.get_reasons(baseaddr):
                    json_dict["candidates"][f"0x{baseaddr:x}"]["reasons"][f"0x{reason.pointer:x}"] = {
                        "poi_offset": f"0x{reason.offset:x}",
                        "poi_type": reason.type,
                    }

        print(json.dumps(json_dict, indent=4))


if __name__ == "__main__":
    main()
