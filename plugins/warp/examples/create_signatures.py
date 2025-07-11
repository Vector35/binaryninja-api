#!/usr/bin/env python3

import sys
from pathlib import Path
from binaryninja import load
from binaryninja.warp import WarpContainer, WarpFunction, WarpTarget

def process_binary(input_file: str, output_dir: str) -> None:
    input_path = Path(input_file)
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    bv = load(input_path)
    bv.update_analysis_and_wait()
    if not bv:
        return

    # Sources exist only in containers, so we will just pull off the first available container.
    # In the future we might make container construction available to the API.
    container = WarpContainer.all()[0]
    output_file = output_dir / f"{input_path.stem}_analysis.warp"
    # Add the source so we can add functions to it and then commit it (write to disk)
    source = container.add_source(str(output_file))

    # NOTE: You probably want to pull the platform from the function, but for this example it's fine.
    target = WarpTarget(bv.platform)
    # NOTE: You probably want to filter for functions with actual annotations, no point to signature a function with no symbol.
    functions_to_warp = [WarpFunction(func) for func in bv.functions]
    container.add_functions(target, source, functions_to_warp)

    # Actually write the warp file to disk.
    container.commit_source(source)
    bv.file.close()

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input_binary> <output_directory>")
        sys.exit(1)
    process_binary(sys.argv[1], sys.argv[2])