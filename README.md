# BinModder - Professional Binary File Modifier

**BinModder** is an advanced binary file modification toolkit inspired by professional tools like SuifTech.
It provides a comprehensive suite of utilities for analyzing, editing, patching, and managing binary files
across a wide range of formats including firmware images, ECU bins, ROM files, PS2/PS3 formats, ELF, PE, and more.

---

## Features

### Core Engine
- **Binary Reader/Writer** with full endianness support (LE, BE, PDP, Honeywell)
- **Hex Engine** with colored output, ASCII display, and offset navigation
- **Patch Engine** supporting IPS, UPS, BPS, and custom patch formats
- **Checksum Engine** with 30+ algorithms (CRC8/16/32/64, MD5, SHA-1/256/512, Fletcher, Adler, etc.)
- **Search Engine** with Boyer-Moore, KMP, Rabin-Karp, and regex binary search
- **Crypto Engine** (XOR, AES-ECB/CBC, DES, Triple-DES, RC4, Blowfish)
- **Compression Engine** (RLE, LZ77, LZSS, LZO, zlib/deflate)
- **Diff Engine** for binary comparison and delta generation

### Supported File Formats
- **ECU BIN** - Automotive ECU firmware
- **EEPROM BIN** - EEPROM memory dumps
- **Firmware BIN** - Generic firmware images
- **PS2 BIN/ISO** - PlayStation 2 formats
- **PS3 BIN/PKG** - PlayStation 3 formats
- **ELF** - Executable and Linkable Format
- **PE/DLL** - Windows Portable Executable
- **ROM** - Generic ROM images
- **RAW** - Raw binary data

### Tools
- **Hex Editor** - Interactive hex/ASCII editing with bookmarks
- **Patcher** - Apply/create patches (IPS, UPS, BPS, custom)
- **Extractor** - Extract sections, segments, and embedded data
- **Injector** - Inject data at specific offsets with alignment support
- **Comparator** - Visual binary diff and merge tool
- **Converter** - Format conversion (hex, base64, int arrays, C arrays)
- **Validator** - File integrity and format validation
- **Template Engine** - Define and apply binary structure templates
- **Script Engine** - Automation scripting with BinModder Script Language (BSL)

### User Interfaces
- **CLI** - Full-featured command line interface
- **GUI** - Tkinter-based graphical interface with hex panels
- **Interactive Mode** - REPL-style interactive shell

---

## Installation

```bash
git clone https://github.com/msrelectronicss/app-modd-damos.git
cd app-modd-damos
pip install -r requirements.txt
python main.py
```

### Requirements
- Python 3.8+
- tkinter (for GUI)
- pycryptodome (for crypto operations)
- colorama (for colored terminal output)
- rich (for enhanced CLI display)

---

## Quick Start

### CLI Usage

```bash
# Open a binary file in hex view
python main.py hex myfile.bin

# Apply an IPS patch
python main.py patch apply myfile.bin patch.ips

# Calculate checksums
python main.py checksum myfile.bin --all

# Search for a hex pattern
python main.py search myfile.bin "FF FF 00 AB"

# Compare two binary files
python main.py diff file1.bin file2.bin

# Extract bytes from offset
python main.py extract myfile.bin --offset 0x1000 --size 0x200 -o extracted.bin

# Inject data at offset
python main.py inject myfile.bin --offset 0x2000 --data "deadbeef"

# Launch GUI
python main.py gui
```

### Script Mode

```bash
# Run a BSL script
python main.py script my_modification.bsl myfile.bin
```

### BSL Script Example

```bsl
# BinModder Script Language example
open "firmware.bin" as f

# Seek to offset 0x1000
seek f 0x1000

# Read 4 bytes as uint32 LE
var checksum = read_u32_le f

# Patch byte at offset
patch f 0x2000 0xFF

# Recalculate CRC32
var crc = crc32 f 0x0000 0x8000
write_u32_le f 0x8000 crc

# Save
save f "firmware_patched.bin"
print "Done! CRC32 = " + hex(crc)
```

---

## Architecture

```
app-modd-damos/
├── main.py                    # Application entry point
├── core/                      # Core binary engine
│   ├── binary_reader.py       # Binary reading with endianness
│   ├── binary_writer.py       # Binary writing with transactions
│   ├── binary_analyzer.py     # File structure analysis
│   ├── hex_engine.py          # Hex display engine
│   ├── patch_engine.py        # Patch creation/application
│   ├── checksum.py            # Checksum algorithms
│   ├── crypto.py              # Cryptographic operations
│   ├── compression.py         # Compression/decompression
│   ├── diff_engine.py         # Binary diff/merge
│   └── search_engine.py       # Pattern search algorithms
├── formats/                   # File format parsers
│   ├── base_format.py         # Abstract base class
│   ├── ecu_bin.py             # ECU firmware format
│   ├── eeprom_bin.py          # EEPROM dump format
│   ├── firmware_bin.py        # Generic firmware
│   ├── ps2_bin.py             # PS2 format
│   ├── ps3_bin.py             # PS3 format
│   ├── elf_format.py          # ELF format
│   ├── pe_format.py           # PE/DLL format
│   └── rom_bin.py             # ROM format
├── tools/                     # Modification tools
│   ├── hex_editor.py          # Interactive hex editor
│   ├── patcher.py             # Patch tools
│   ├── extractor.py           # Data extraction
│   ├── injector.py            # Data injection
│   ├── comparator.py          # Binary comparison
│   ├── converter.py           # Format conversion
│   ├── validator.py           # File validation
│   ├── template_engine.py     # Template system
│   └── script_engine.py       # BSL script engine
├── ui/                        # User interfaces
│   ├── cli/                   # Command line interface
│   │   ├── main_cli.py        # CLI entry point
│   │   ├── hex_view.py        # Hex viewer commands
│   │   └── commands.py        # All CLI commands
│   └── gui/                   # Graphical interface
│       ├── main_window.py     # Main application window
│       ├── hex_panel.py       # Hex editor panel
│       ├── toolbar.py         # Toolbar and menus
│       ├── dialogs.py         # Dialog windows
│       └── widgets.py         # Custom widgets
├── utils/                     # Utilities
│   ├── byte_utils.py          # Byte manipulation
│   ├── string_utils.py        # String utilities
│   ├── math_utils.py          # Math functions
│   ├── file_utils.py          # File operations
│   └── log_utils.py           # Logging system
├── tests/                     # Test suite
├── templates/                 # Binary structure templates
├── scripts/                   # Example BSL scripts
├── plugins/                   # Plugin system
└── docs/                      # Documentation
```

---

## Plugin System

BinModder supports plugins for extending functionality:

```python
from plugins import BinModderPlugin

class MyPlugin(BinModderPlugin):
    name = "my_plugin"
    version = "1.0.0"

    def on_file_open(self, binary_file):
        # Called when a file is opened
        pass

    def on_patch_apply(self, patch, binary_file):
        # Called before patch is applied
        pass
```

---

## Template System

Define binary structures with XML-based templates:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<template name="ECU Header" version="1.0">
  <structure offset="0x0000">
    <field name="magic" type="bytes" size="4" expected="45 43 55 20"/>
    <field name="version" type="uint16_le"/>
    <field name="build_date" type="string" size="8"/>
    <field name="checksum" type="uint32_le"/>
    <field name="data_start" type="uint32_le"/>
    <field name="data_size" type="uint32_le"/>
  </structure>
</template>
```

---

## License

MIT License - See LICENSE file for details.

## Contributing

Pull requests welcome. Please ensure all tests pass before submitting.

## Credits

Developed by MSR Electronics - Professional Binary Tools Division
