# Container Transforms

Container Transforms are specialized transforms that enable Binary Ninja to extract and navigate files within container formats such as ZIP archives, disk images, and other multi-file structures. Unlike simple encoding transforms (Base64, Hex, etc.), container transforms can produce multiple output files and interact with the Container Browser UI.

You can list all available container transforms (those with detection support) using:

```python
>>> [x.name for x in Transform if getattr(x, "supports_detection", False)]
['Gzip', 'Zlib', 'Bzip2', 'LZMA', 'LZ4Frame', 'Zstd', 'XZ', 'Zip', 'CaRT', 'Tar', 'AR', 'CPIO', 'DMG', 'UImage', 'FIT', 'TRX', 'IntelHex', 'SRec', 'TiTxt', 'IMG4', 'LZFSE', 'Universal']
```

## Overview

The Transform API provides the foundation for creating custom container decoders. Container transforms differ from standard transforms in that they:

1. Support **context-aware decoding** via `perform_decode_with_context()`
2. Can produce **multiple output files** from a single input
3. Support **password protection** and other interactive parameters
4. Integrate with the **Container Browser** UI for file selection

## Basic Transform Structure

All transforms, including container transforms, inherit from the `Transform` base class. Here's a minimal example:

```python
from binaryninja import Transform, TransformType, TransformCapabilities

class MyContainerTransform(Transform):
    transform_type = TransformType.DecodeTransform
    capabilities = TransformCapabilities.TransformSupportsContext | TransformCapabilities.TransformSupportsDetection
    name = "MyContainer"
    long_name = "My Container Format"
    group = "Container"

    def can_decode(self, input):
        """Check if this transform can decode the input"""
        # Check for magic bytes or other signatures
        head = input.read(0, 4)
        return head == b"MYCN"  # Your format's magic bytes

    def perform_decode_with_context(self, context, params):
        """Context-aware extraction for multi-file containers"""
        # Implementation details below
        pass

# Register the transform
MyContainerTransform.register()
```

## Container Extraction Protocol

Container transforms typically operate in **two phases**:

### Phase 1: Discovery

During discovery, the transform enumerates all available files and populates `context.available_files`:

```python
def perform_decode_with_context(self, context, params):
    # Parse the container format
    container = parse_my_format(context.input)

    # Phase 1: Discovery
    if not context.has_available_files:
        file_list = [entry.name for entry in container.entries]
        context.set_available_files(file_list)
        return False  # More user interaction needed
```

Returning `False` indicates that the Container Browser should present these files to the user for selection.

### Phase 2: Extraction

Once the user selects files, the transform extracts them and creates child contexts:

```python
def perform_decode_with_context(self, context, params):
    container = parse_my_format(context.input)

    # Phase 1: Discovery (as above)
    if not context.has_available_files:
        # ... discovery code ...
        return False

    # Phase 2: Extraction
    requested = context.requested_files
    if not requested:
        return False  # No files selected yet

    complete = True
    for filename in requested:
        try:
            data = container.extract(filename)
            context.create_child(DataBuffer(data), filename)
        except Exception as e:
            # Create child with error status
            context.create_child(
                DataBuffer(b""),
                filename,
                result=TransformResult.TransformFailure,
                message=str(e)
            )
            complete = False

    return complete  # True if all files extracted successfully
```

## Complete Example: ZipPython

Binary Ninja includes a reference implementation of a ZIP container transform in `api/python/transform.py`.



## Transform Results and Error Handling

Use `TransformResult` values to communicate extraction status:

- `TransformResult.TransformSuccess`: Extraction completed successfully
- `TransformResult.TransformNotAttempted`: Extraction not attempted
- `TransformResult.TransformFailure`: Generic extraction failure
- `TransformResult.TransformRequiresPassword`: File is encrypted and needs a password

Set results on individual child contexts:

```python
context.create_child(
    data=databuffer.DataBuffer(extracted_data),
    filename="file.bin",
    result=TransformResult.TransformSuccess,
    message=""  # Optional success message
)
```

## Working with Passwords

Container transforms should integrate with Binary Ninja's password management system:

```python
# Get passwords from settings
passwords = Settings().get_string_list('files.container.defaultPasswords')

# Check for password in transform parameters
if "password" in params:
    p = params["password"]
    pwd = p.decode("utf-8", "replace") if isinstance(p, (bytes, bytearray)) else str(p)
    passwords.insert(0, pwd)

# Try each password
for password in passwords:
    try:
        content = extract_with_password(container, filename, password)
        break  # Success!
    except PasswordError:
        continue  # Try next password
```

When a file requires a password that wasn't provided, use `TransformResult.TransformRequiresPassword` to signal the UI to prompt the user.

## Metadata and Virtual Paths

Container transforms automatically create metadata that tracks the extraction chain:

```python
# After opening a file extracted through containers:
>>> bv.parent_view.auto_metadata['container']
{
    'chain': [
        {'transform': 'Zip'},
        {'transform': 'Base64'}
    ],
    'virtualPath': 'Zip(/path/to/archive.zip)::Base64(encoded_file)::extracted'
}
```

You can also add custom metadata to child contexts:

```python
child = context.create_child(data, filename)
if child.metadata_obj:
    child.metadata_obj["custom_field"] = "value"
```

## Testing Container Transforms

When testing your container transform, you can use the Python API directly:

```python
from binaryninja import TransformSession, load

# Test basic extraction
session = TransformSession("test_container.bin")

# Process and check results
if session.process():
    print(f"Extraction complete: {session.current_context.filename}")
else:
    print("User interaction required")
    ctx = session.current_context
    if ctx.parent and ctx.parent.has_available_files:
        print(f"Available files: {ctx.parent.available_files}")
```

### Loading Extracted Files

After processing, select the context and load it as a BinaryView:

```python
# Select the final context for loading
session.set_selected_contexts(session.current_context)

# Load the extracted file
with load(session.current_view) as view:
    print(f"Loaded: {view.file.filename}")
    print(f"View type: {view.view_type}")
```

### Manual Transform Selection

When auto-detection fails (e.g., Base64 has no magic bytes), you can manually specify the transform:

```python
# Create session and process the container
session = TransformSession("archive.zip")
if not session.process():
    print("Failed to extract archive")
    return

# Get the extracted file context
extracted_ctx = session.current_context

# Manually set the transform to apply
extracted_ctx.set_transform_name("Base64")

# Process from this context to apply the transform
if not session.process_from(extracted_ctx):
    print("Failed to apply Base64 transform")
    return

# Select and load the final decoded file
final_ctx = session.current_context
session.set_selected_contexts(final_ctx)

with load(session.current_view) as bv:
    print(f"Loaded: {bv.file.filename}")
    print(f"View type: {bv.view_type}")
    print(f"Transform chain: {bv.file.virtual_path}")
```

### Transform Chaining

TransformSession automatically handles multi-layer extraction:

```python
# Process a nested container (e.g., tar.gz or tar.xz)
session = TransformSession("archive.tar.gz")

# Single process() call handles the entire chain
if session.process():
    # Load the final extracted file
    session.set_selected_contexts(session.current_context)
    with load(session.current_view) as bv:
        # View the complete extraction chain
        print(bv.file.virtual_path)
        # Example output: 'Gzip(/path/to/archive.tar.gz)::Tar()::extracted'
```

### UI Testing Modes

For interactive testing in the UI:

1. **Full Mode**: Settings → `files.container.mode` → "Full"
   - Opens your container and shows all extracted files immediately
2. **Interactive Mode**: Settings → `files.container.mode` → "Interactive"
   - Requires clicking through each level of the container hierarchy

## API Reference

For complete API documentation, see:

- [`Transform`](https://api.binary.ninja/binaryninja.transform-module.html#binaryninja.transform.Transform) - Base transform class
- [`TransformContext`](https://api.binary.ninja/binaryninja.transform-module.html#binaryninja.transform.TransformContext) - Container extraction context
- [`TransformSession`](https://api.binary.ninja/binaryninja.transform-module.html#binaryninja.transform.TransformSession) - Multi-stage extraction workflow
- [`TransformResult`](https://api.binary.ninja/binaryninja.enums-module.html#binaryninja.enums.TransformResult) - Extraction result codes
- [`TransformCapabilities`](https://api.binary.ninja/binaryninja.enums-module.html#binaryninja.enums.TransformCapabilities) - Transform capability flags
