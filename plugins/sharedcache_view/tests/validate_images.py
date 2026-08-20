import re
import sys
import os
from binaryninja import sharedcache, load


# This is some apple map file thingy, you will know if you have one because you will have a .map file.
def parse_map_file(map_file_path):
    mappings = []
    libraries = []

    with open(map_file_path, 'r') as file:
        lines = file.readlines()

    mapping_pattern = re.compile(
        r"mapping\s+(?P<type>[A-Z]+)\s+(?P<size>[\dMKB]+)\s+0x(?P<start>[a-fA-F0-9]+)\s+->\s+0x(?P<end>[a-fA-F0-9]+)"
    )
    library_pattern = re.compile(
        r"^(?P<library>.+)$"
    )
    section_pattern = re.compile(
        r"\s+(?P<section>[^\s]+)\s+0x(?P<start>[a-fA-F0-9]+)\s+->\s+0x[a-fA-F0-9]+"
    )

    current_library = None

    for line in lines:
        # Check for a region mapping line
        mapping_match = mapping_pattern.match(line)
        if mapping_match:
            mappings.append({
                "type": mapping_match.group("type"),
                "size": mapping_match.group("size"),
                "start": int(mapping_match.group("start"), 16)
            })
            continue

        # Check for a section line within a library
        section_match = section_pattern.match(line)
        if section_match and current_library is not None:
            current_library["sections"].append({
                "section": section_match.group("section"),
                "start": int(section_match.group("start"), 16)
            })
            continue

        # Check for a library name line
        library_match = library_pattern.match(line)
        if library_match:
            current_library = {
                "name": library_match.group("library"),
                "sections": []
            }
            libraries.append(current_library)
            continue

    return mappings, libraries


def main():
    if len(sys.argv) < 2:
        print("Please provide a shared cache binary path to validate. There must be an adjacent .map file.")
        sys.exit(1)

    binary_path = sys.argv[1]
    bv = load(binary_path)
    assert bv is not None, f"Failed to create BinaryView for {str(binary_path)}"
    controller = sharedcache.SharedCacheController(bv)
    assert controller.is_valid

    map_file_path = bv.file.filename + ".map"
    if not os.path.exists(map_file_path):
        print(f"Error: Map file does not exist at path: {map_file_path}")
        sys.exit(1)

    mappings, map_images = parse_map_file(map_file_path)

    # Validate images and sections
    for map_image in map_images:
        image = controller.get_image_with_name(map_image["name"])
        if not image:
            raise ValueError(f"Image not found: {map_image['name']}")
        print(f"Checking image... {image.name}")

        for section in map_image["sections"]:
            if not section["start"] in image.region_starts:
                raise ValueError(
                    f"Section not found in image '{image.name}': {section['start']} -> {image.region_starts}")

    print("Validation successful!")


if __name__ == "__main__":
    main()
