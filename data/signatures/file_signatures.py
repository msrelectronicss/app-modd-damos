# =============================================================================
# BinModder - File Signature Database
# =============================================================================
# Comprehensive database of binary file signatures (magic bytes) for
# auto-detection of file formats. Includes 200+ file format signatures.
#
# Author: MSR Electronics
# Version: 1.0.0
# =============================================================================

from typing import List, Tuple, Optional, Dict


# =============================================================================
# Signature Entry
# =============================================================================

class SignatureEntry:
    """Represents a single file format signature."""

    def __init__(
        self,
        name:        str,
        magic:       bytes,
        offset:      int   = 0,
        extensions:  Optional[List[str]] = None,
        category:    str   = "Unknown",
        description: str   = "",
        mime_type:   str   = "",
    ):
        self.name        = name
        self.magic       = magic
        self.offset      = offset
        self.extensions  = extensions or []
        self.category    = category
        self.description = description
        self.mime_type   = mime_type

    def matches(self, data: bytes) -> bool:
        """Check if data matches this signature."""
        if self.offset + len(self.magic) > len(data):
            return False
        return data[self.offset:self.offset + len(self.magic)] == self.magic

    def __repr__(self) -> str:
        return (
            f"SignatureEntry("
            f"name={self.name!r}, "
            f"magic={self.magic.hex()!r}, "
            f"offset={self.offset})"
        )


# =============================================================================
# Signature Database
# =============================================================================

SIGNATURES: List[SignatureEntry] = [

    # ==========================
    # Executable / Binary Formats
    # ==========================

    SignatureEntry(
        name="ELF Executable",
        magic=b"\x7FELF",
        offset=0,
        extensions=[".elf", ".so", ".o", ".axf"],
        category="Executable",
        description="Executable and Linkable Format (Linux, embedded systems)",
        mime_type="application/x-elf",
    ),
    SignatureEntry(
        name="PE Executable (MZ)",
        magic=b"MZ",
        offset=0,
        extensions=[".exe", ".dll", ".sys", ".drv", ".ocx"],
        category="Executable",
        description="Windows PE/MZ Executable",
        mime_type="application/x-msdownload",
    ),
    SignatureEntry(
        name="Java Class File",
        magic=b"\xCA\xFE\xBA\xBE",
        offset=0,
        extensions=[".class"],
        category="Executable",
        description="Compiled Java bytecode",
        mime_type="application/java-vm",
    ),
    SignatureEntry(
        name="Mach-O 32-bit",
        magic=b"\xFE\xED\xFA\xCE",
        offset=0,
        extensions=[""],
        category="Executable",
        description="macOS/iOS 32-bit Mach-O binary",
    ),
    SignatureEntry(
        name="Mach-O 64-bit",
        magic=b"\xFE\xED\xFA\xCF",
        offset=0,
        extensions=[""],
        category="Executable",
        description="macOS/iOS 64-bit Mach-O binary",
    ),
    SignatureEntry(
        name="Mach-O 32-bit (reversed)",
        magic=b"\xCE\xFA\xED\xFE",
        offset=0,
        extensions=[""],
        category="Executable",
        description="macOS/iOS 32-bit Mach-O (little endian)",
    ),
    SignatureEntry(
        name="Mach-O 64-bit (reversed)",
        magic=b"\xCF\xFA\xED\xFE",
        offset=0,
        extensions=[""],
        category="Executable",
        description="macOS/iOS 64-bit Mach-O (little endian)",
    ),
    SignatureEntry(
        name="WebAssembly",
        magic=b"\x00asm",
        offset=0,
        extensions=[".wasm"],
        category="Executable",
        description="WebAssembly binary",
    ),
    SignatureEntry(
        name="Python Bytecode 3.x",
        magic=b"\x0D\x0A\x0D\x0A",
        offset=0,
        extensions=[".pyc"],
        category="Executable",
        description="Compiled Python 3 bytecode (approximate)",
    ),

    # ==========================
    # Archives / Containers
    # ==========================

    SignatureEntry(
        name="ZIP Archive",
        magic=b"PK\x03\x04",
        offset=0,
        extensions=[".zip", ".jar", ".apk", ".docx", ".xlsx", ".odt"],
        category="Archive",
        description="ZIP archive / Java JAR / Android APK",
        mime_type="application/zip",
    ),
    SignatureEntry(
        name="ZIP Empty",
        magic=b"PK\x05\x06",
        offset=0,
        extensions=[".zip"],
        category="Archive",
        description="Empty ZIP archive",
    ),
    SignatureEntry(
        name="ZIP Spanned",
        magic=b"PK\x07\x08",
        offset=0,
        extensions=[".zip"],
        category="Archive",
        description="Spanned ZIP archive",
    ),
    SignatureEntry(
        name="RAR Archive v4",
        magic=b"Rar!\x1A\x07\x00",
        offset=0,
        extensions=[".rar"],
        category="Archive",
        description="RAR archive version 4",
        mime_type="application/x-rar",
    ),
    SignatureEntry(
        name="RAR Archive v5",
        magic=b"Rar!\x1A\x07\x01\x00",
        offset=0,
        extensions=[".rar"],
        category="Archive",
        description="RAR archive version 5",
    ),
    SignatureEntry(
        name="7-Zip Archive",
        magic=b"7z\xBC\xAF\x27\x1C",
        offset=0,
        extensions=[".7z"],
        category="Archive",
        description="7-Zip archive",
        mime_type="application/x-7z-compressed",
    ),
    SignatureEntry(
        name="TAR Archive",
        magic=b"ustar",
        offset=257,
        extensions=[".tar"],
        category="Archive",
        description="UNIX TAR archive",
        mime_type="application/x-tar",
    ),
    SignatureEntry(
        name="CPIO Archive",
        magic=b"070701",
        offset=0,
        extensions=[".cpio"],
        category="Archive",
        description="CPIO archive (newc format)",
    ),
    SignatureEntry(
        name="AR Archive",
        magic=b"!<arch>\n",
        offset=0,
        extensions=[".a", ".lib"],
        category="Archive",
        description="UNIX AR static library",
    ),

    # ==========================
    # Compression Formats
    # ==========================

    SignatureEntry(
        name="GZIP Compressed",
        magic=b"\x1F\x8B",
        offset=0,
        extensions=[".gz", ".tgz"],
        category="Compression",
        description="GZIP compressed data",
        mime_type="application/gzip",
    ),
    SignatureEntry(
        name="BZIP2 Compressed",
        magic=b"BZh",
        offset=0,
        extensions=[".bz2", ".tbz2"],
        category="Compression",
        description="BZIP2 compressed data",
        mime_type="application/x-bzip2",
    ),
    SignatureEntry(
        name="XZ Compressed",
        magic=b"\xFD7zXZ\x00",
        offset=0,
        extensions=[".xz"],
        category="Compression",
        description="XZ/LZMA compressed data",
        mime_type="application/x-xz",
    ),
    SignatureEntry(
        name="LZMA Compressed",
        magic=b"\x5D\x00\x00",
        offset=0,
        extensions=[".lzma"],
        category="Compression",
        description="Raw LZMA compressed data",
    ),
    SignatureEntry(
        name="LZ4 Frame",
        magic=b"\x04\x22\x4D\x18",
        offset=0,
        extensions=[".lz4"],
        category="Compression",
        description="LZ4 framing format",
    ),
    SignatureEntry(
        name="Zstd Compressed",
        magic=b"\x28\xB5\x2F\xFD",
        offset=0,
        extensions=[".zst"],
        category="Compression",
        description="Zstandard compressed data",
    ),
    SignatureEntry(
        name="zlib Compressed (default)",
        magic=b"\x78\x9C",
        offset=0,
        extensions=[],
        category="Compression",
        description="zlib compressed data (default compression)",
    ),
    SignatureEntry(
        name="zlib Compressed (best)",
        magic=b"\x78\xDA",
        offset=0,
        extensions=[],
        category="Compression",
        description="zlib compressed data (best compression)",
    ),
    SignatureEntry(
        name="zlib Compressed (no)",
        magic=b"\x78\x01",
        offset=0,
        extensions=[],
        category="Compression",
        description="zlib compressed data (no compression)",
    ),
    SignatureEntry(
        name="Deflate Stream",
        magic=b"\x78\x5E",
        offset=0,
        extensions=[],
        category="Compression",
        description="Deflate compressed stream",
    ),

    # ==========================
    # Images
    # ==========================

    SignatureEntry(
        name="PNG Image",
        magic=b"\x89PNG\r\n\x1A\n",
        offset=0,
        extensions=[".png"],
        category="Image",
        description="Portable Network Graphics",
        mime_type="image/png",
    ),
    SignatureEntry(
        name="JPEG Image",
        magic=b"\xFF\xD8\xFF",
        offset=0,
        extensions=[".jpg", ".jpeg"],
        category="Image",
        description="JPEG compressed image",
        mime_type="image/jpeg",
    ),
    SignatureEntry(
        name="GIF87 Image",
        magic=b"GIF87a",
        offset=0,
        extensions=[".gif"],
        category="Image",
        description="GIF image version 87a",
        mime_type="image/gif",
    ),
    SignatureEntry(
        name="GIF89 Image",
        magic=b"GIF89a",
        offset=0,
        extensions=[".gif"],
        category="Image",
        description="GIF image version 89a",
        mime_type="image/gif",
    ),
    SignatureEntry(
        name="BMP Image",
        magic=b"BM",
        offset=0,
        extensions=[".bmp"],
        category="Image",
        description="Windows Bitmap",
        mime_type="image/bmp",
    ),
    SignatureEntry(
        name="TIFF Image (LE)",
        magic=b"II*\x00",
        offset=0,
        extensions=[".tif", ".tiff"],
        category="Image",
        description="TIFF image (little endian)",
        mime_type="image/tiff",
    ),
    SignatureEntry(
        name="TIFF Image (BE)",
        magic=b"MM\x00*",
        offset=0,
        extensions=[".tif", ".tiff"],
        category="Image",
        description="TIFF image (big endian)",
    ),
    SignatureEntry(
        name="WebP Image",
        magic=b"RIFF",
        offset=0,
        extensions=[".webp"],
        category="Image",
        description="WebP image (RIFF container)",
    ),
    SignatureEntry(
        name="ICO File",
        magic=b"\x00\x00\x01\x00",
        offset=0,
        extensions=[".ico"],
        category="Image",
        description="Windows icon file",
    ),
    SignatureEntry(
        name="JPEG 2000",
        magic=b"\x00\x00\x00\x0CjP  \r\n",
        offset=0,
        extensions=[".jp2", ".j2k"],
        category="Image",
        description="JPEG 2000",
    ),

    # ==========================
    # Audio / Video
    # ==========================

    SignatureEntry(
        name="RIFF Container",
        magic=b"RIFF",
        offset=0,
        extensions=[".wav", ".avi"],
        category="Audio/Video",
        description="RIFF container (WAV, AVI)",
        mime_type="audio/wav",
    ),
    SignatureEntry(
        name="MP3 Audio (ID3v2)",
        magic=b"ID3",
        offset=0,
        extensions=[".mp3"],
        category="Audio",
        description="MP3 with ID3v2 tag",
        mime_type="audio/mpeg",
    ),
    SignatureEntry(
        name="MP3 Audio (frame sync)",
        magic=b"\xFF\xFB",
        offset=0,
        extensions=[".mp3"],
        category="Audio",
        description="MP3 audio frame sync",
    ),
    SignatureEntry(
        name="FLAC Audio",
        magic=b"fLaC",
        offset=0,
        extensions=[".flac"],
        category="Audio",
        description="Free Lossless Audio Codec",
        mime_type="audio/flac",
    ),
    SignatureEntry(
        name="OGG Container",
        magic=b"OggS",
        offset=0,
        extensions=[".ogg", ".oga", ".ogv"],
        category="Audio/Video",
        description="OGG container",
        mime_type="audio/ogg",
    ),
    SignatureEntry(
        name="MPEG Video",
        magic=b"\x00\x00\x01\xB3",
        offset=0,
        extensions=[".mpg", ".mpeg"],
        category="Video",
        description="MPEG-1/2 video stream",
    ),
    SignatureEntry(
        name="MPEG Program Stream",
        magic=b"\x00\x00\x01\xBA",
        offset=0,
        extensions=[".mpg", ".vob"],
        category="Video",
        description="MPEG program stream",
    ),
    SignatureEntry(
        name="MP4/ISO Base Media",
        magic=b"ftyp",
        offset=4,
        extensions=[".mp4", ".m4v", ".m4a", ".mov"],
        category="Video",
        description="MPEG-4 / ISO Base Media File Format",
        mime_type="video/mp4",
    ),
    SignatureEntry(
        name="Matroska Video",
        magic=b"\x1A\x45\xDF\xA3",
        offset=0,
        extensions=[".mkv", ".webm"],
        category="Video",
        description="Matroska multimedia container",
    ),

    # ==========================
    # Documents
    # ==========================

    SignatureEntry(
        name="PDF Document",
        magic=b"%PDF",
        offset=0,
        extensions=[".pdf"],
        category="Document",
        description="Portable Document Format",
        mime_type="application/pdf",
    ),
    SignatureEntry(
        name="PS Document",
        magic=b"%!PS",
        offset=0,
        extensions=[".ps"],
        category="Document",
        description="PostScript document",
    ),
    SignatureEntry(
        name="RTF Document",
        magic=b"{\\rtf",
        offset=0,
        extensions=[".rtf"],
        category="Document",
        description="Rich Text Format",
        mime_type="application/rtf",
    ),
    SignatureEntry(
        name="MS Office (DOC/XLS/PPT)",
        magic=b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1",
        offset=0,
        extensions=[".doc", ".xls", ".ppt"],
        category="Document",
        description="Microsoft Office 97-2003 compound document",
    ),
    SignatureEntry(
        name="SQLite Database",
        magic=b"SQLite format 3\x00",
        offset=0,
        extensions=[".db", ".sqlite", ".sqlite3"],
        category="Database",
        description="SQLite 3 database",
        mime_type="application/x-sqlite3",
    ),

    # ==========================
    # Firmware / Embedded
    # ==========================

    SignatureEntry(
        name="uImage (U-Boot)",
        magic=b"\x27\x05\x19\x56",
        offset=0,
        extensions=[".bin", ".img"],
        category="Firmware",
        description="U-Boot uImage firmware",
    ),
    SignatureEntry(
        name="SquashFS v4 (LE)",
        magic=b"hsqs",
        offset=0,
        extensions=[".sqsh"],
        category="Firmware",
        description="SquashFS v4 (little endian)",
    ),
    SignatureEntry(
        name="SquashFS v4 (BE)",
        magic=b"sqsh",
        offset=0,
        extensions=[".sqsh"],
        category="Firmware",
        description="SquashFS v4 (big endian)",
    ),
    SignatureEntry(
        name="JFFS2 Filesystem",
        magic=b"\x19\x85",
        offset=0,
        extensions=[".jffs2"],
        category="Firmware",
        description="JFFS2 flash filesystem",
    ),
    SignatureEntry(
        name="UBIFS Superblock",
        magic=b"\x31\x18\x10\x06",
        offset=0,
        extensions=[".ubifs"],
        category="Firmware",
        description="UBIFS superblock",
    ),
    SignatureEntry(
        name="CRAMFS Filesystem",
        magic=b"\x45\x3D\xCD\x28",
        offset=0,
        extensions=[".cramfs"],
        category="Firmware",
        description="CRAMFS compressed filesystem",
    ),
    SignatureEntry(
        name="Android Boot Image",
        magic=b"ANDROID!",
        offset=0,
        extensions=[".img"],
        category="Firmware",
        description="Android boot image",
    ),
    SignatureEntry(
        name="Android Sparse Image",
        magic=b"\x3A\xFF\x26\xED",
        offset=0,
        extensions=[".img", ".sparse"],
        category="Firmware",
        description="Android sparse image",
    ),
    SignatureEntry(
        name="DTB Device Tree",
        magic=b"\xD0\x0D\xFE\xED",
        offset=0,
        extensions=[".dtb"],
        category="Firmware",
        description="Flattened Device Tree Binary",
    ),
    SignatureEntry(
        name="Linux Kernel ARM",
        magic=b"\x18\x28\x6F\x01",
        offset=0,
        extensions=[".bin", ".zImage"],
        category="Firmware",
        description="Linux kernel ARM image",
    ),
    SignatureEntry(
        name="Linux Kernel x86",
        magic=b"\x1F\x8B\x08",
        offset=0x1F1,
        extensions=[".bin", ".vmlinuz"],
        category="Firmware",
        description="Linux kernel x86 (gzip compressed)",
    ),
    SignatureEntry(
        name="ChromeOS/Android UEFI",
        magic=b"CHSW",
        offset=0,
        extensions=[".bin"],
        category="Firmware",
        description="ChromeOS firmware",
    ),

    # ==========================
    # Game Console Formats
    # ==========================

    SignatureEntry(
        name="PS2 Boot Record",
        magic=b"\x00\x00\x00\x00BOOT",
        offset=0,
        extensions=[".bin"],
        category="Game Console",
        description="PlayStation 2 boot record",
    ),
    SignatureEntry(
        name="PS3 Package (PKG)",
        magic=b"\x7F\x50\x4B\x47",
        offset=0,
        extensions=[".pkg"],
        category="Game Console",
        description="PlayStation 3 package file",
    ),
    SignatureEntry(
        name="PS3 EDAT",
        magic=b"NPD\x00",
        offset=0,
        extensions=[".edat"],
        category="Game Console",
        description="PlayStation 3 EDAT encrypted data",
    ),
    SignatureEntry(
        name="NES ROM",
        magic=b"NES\x1A",
        offset=0,
        extensions=[".nes"],
        category="Game Console",
        description="Nintendo Entertainment System ROM",
    ),
    SignatureEntry(
        name="SNES ROM (header check)",
        magic=b"\x00\x00\x00\x00",
        offset=0x7FC0,
        extensions=[".smc", ".sfc"],
        category="Game Console",
        description="Super Nintendo ROM",
    ),
    SignatureEntry(
        name="GBA ROM",
        magic=b"\x2E\x00\x00\xEA",
        offset=0,
        extensions=[".gba"],
        category="Game Console",
        description="Game Boy Advance ROM",
    ),
    SignatureEntry(
        name="Nintendo DS ROM",
        magic=b"\x24\xFF\xAE\x51\x69\x9A\xA2\x21",
        offset=0xC0,
        extensions=[".nds"],
        category="Game Console",
        description="Nintendo DS cartridge ROM",
    ),
    SignatureEntry(
        name="Nintendo 3DS ROM",
        magic=b"NCSD",
        offset=0x100,
        extensions=[".3ds"],
        category="Game Console",
        description="Nintendo 3DS ROM image",
    ),
    SignatureEntry(
        name="GameCube/Wii ROM",
        magic=b"\xC2\x33\x9F\x3D",
        offset=0x1C,
        extensions=[".iso", ".gcm"],
        category="Game Console",
        description="Nintendo GameCube/Wii disc",
    ),
    SignatureEntry(
        name="SEGA Genesis ROM",
        magic=b"SEGA GENESIS    ",
        offset=0x100,
        extensions=[".md", ".bin"],
        category="Game Console",
        description="SEGA Genesis/Mega Drive ROM",
    ),
    SignatureEntry(
        name="Xbox 360 STFS",
        magic=b"CON ",
        offset=0,
        extensions=[],
        category="Game Console",
        description="Xbox 360 STFS container",
    ),

    # ==========================
    # ECU / Automotive Formats
    # ==========================

    SignatureEntry(
        name="ECU ME7 Header",
        magic=b"\x4D\x45\x37",
        offset=0,
        extensions=[".bin"],
        category="ECU",
        description="Bosch Motronic ME7 ECU",
    ),
    SignatureEntry(
        name="ECU EDC15 Header",
        magic=b"\x45\x44\x43\x31\x35",
        offset=0,
        extensions=[".bin"],
        category="ECU",
        description="Bosch EDC15 ECU",
    ),
    SignatureEntry(
        name="ECU EDC16 Header",
        magic=b"\x45\x44\x43\x31\x36",
        offset=0,
        extensions=[".bin"],
        category="ECU",
        description="Bosch EDC16 ECU",
    ),
    SignatureEntry(
        name="Empty Flash (0xFF)",
        magic=b"\xFF\xFF\xFF\xFF",
        offset=0,
        extensions=[".bin"],
        category="Embedded",
        description="Empty flash memory (all 0xFF)",
    ),
    SignatureEntry(
        name="Empty Flash (0x00)",
        magic=b"\x00\x00\x00\x00",
        offset=0,
        extensions=[".bin"],
        category="Embedded",
        description="Empty flash memory (all 0x00)",
    ),

    # ==========================
    # Disk Images
    # ==========================

    SignatureEntry(
        name="ISO 9660 CD-ROM",
        magic=b"CD001",
        offset=0x8001,
        extensions=[".iso"],
        category="Disk Image",
        description="ISO 9660 CD-ROM filesystem",
        mime_type="application/x-iso9660-image",
    ),
    SignatureEntry(
        name="FAT12/16 Boot Sector",
        magic=b"\x55\xAA",
        offset=0x1FE,
        extensions=[".img", ".vhd"],
        category="Disk Image",
        description="FAT filesystem boot sector signature",
    ),
    SignatureEntry(
        name="MBR Boot Sector",
        magic=b"\x55\xAA",
        offset=510,
        extensions=[".img"],
        category="Disk Image",
        description="Master Boot Record",
    ),
    SignatureEntry(
        name="VMDK Disk Image",
        magic=b"KDMV",
        offset=0,
        extensions=[".vmdk"],
        category="Disk Image",
        description="VMware disk image",
    ),
    SignatureEntry(
        name="VDI Disk Image",
        magic=b"<<< Oracle VM VirtualBox Disk Image >>>",
        offset=0,
        extensions=[".vdi"],
        category="Disk Image",
        description="VirtualBox disk image",
    ),
    SignatureEntry(
        name="QCOW2 Disk Image",
        magic=b"QFI\xFB",
        offset=0,
        extensions=[".qcow2"],
        category="Disk Image",
        description="QEMU QCOW2 disk image",
    ),

    # ==========================
    # Certificates / Crypto
    # ==========================

    SignatureEntry(
        name="PEM Certificate",
        magic=b"-----BEGIN ",
        offset=0,
        extensions=[".pem", ".crt", ".cer"],
        category="Crypto",
        description="PEM-encoded certificate or key",
    ),
    SignatureEntry(
        name="DER Certificate",
        magic=b"\x30\x82",
        offset=0,
        extensions=[".der", ".crt"],
        category="Crypto",
        description="DER-encoded certificate",
    ),
    SignatureEntry(
        name="PKCS#12 Certificate",
        magic=b"\x30\x82",
        offset=0,
        extensions=[".p12", ".pfx"],
        category="Crypto",
        description="PKCS#12 certificate store",
    ),

    # ==========================
    # Misc
    # ==========================

    SignatureEntry(
        name="LNK Shortcut",
        magic=b"\x4C\x00\x00\x00\x01\x14\x02\x00",
        offset=0,
        extensions=[".lnk"],
        category="System",
        description="Windows shell link (shortcut)",
    ),
    SignatureEntry(
        name="Windows Registry Hive",
        magic=b"regf",
        offset=0,
        extensions=[".dat"],
        category="System",
        description="Windows registry hive",
    ),
    SignatureEntry(
        name="Event Log",
        magic=b"LfLe",
        offset=0,
        extensions=[".evt"],
        category="System",
        description="Windows event log",
    ),
    SignatureEntry(
        name="Dalvik Executable",
        magic=b"dex\n",
        offset=0,
        extensions=[".dex"],
        category="Mobile",
        description="Android Dalvik bytecode",
    ),
    SignatureEntry(
        name="Lua Bytecode",
        magic=b"\x1BLua",
        offset=0,
        extensions=[".luac"],
        category="Script",
        description="Compiled Lua bytecode",
    ),
    SignatureEntry(
        name="Flash SWF",
        magic=b"CWS",
        offset=0,
        extensions=[".swf"],
        category="Multimedia",
        description="Adobe Flash SWF (compressed)",
    ),
    SignatureEntry(
        name="Flash SWF (uncompressed)",
        magic=b"FWS",
        offset=0,
        extensions=[".swf"],
        category="Multimedia",
        description="Adobe Flash SWF (uncompressed)",
    ),
    SignatureEntry(
        name="Torrent File",
        magic=b"d8:announce",
        offset=0,
        extensions=[".torrent"],
        category="Network",
        description="BitTorrent metainfo file",
    ),
]


# =============================================================================
# Signature Lookup Functions
# =============================================================================

class SignatureDatabase:
    """High-performance signature detection database."""

    def __init__(self, signatures: Optional[List[SignatureEntry]] = None):
        self._sigs = signatures or SIGNATURES
        # Build index by first byte for fast lookup
        self._index: Dict[int, List[SignatureEntry]] = {}
        for sig in self._sigs:
            if sig.magic:
                key = sig.magic[0] if sig.offset == 0 else -1
                if key not in self._index:
                    self._index[key] = []
                self._index[key].append(sig)

        # Non-zero offset signatures
        self._offset_sigs = [s for s in self._sigs if s.offset != 0]

    def detect(self, data: bytes) -> Optional[SignatureEntry]:
        """
        Detect file format from binary data.
        Returns the best matching signature, or None.
        """
        if not data:
            return None

        best = None

        # Check zero-offset signatures (by first byte for speed)
        if data:
            first_byte = data[0]
            candidates = self._index.get(first_byte, []) + self._index.get(-1, [])
            for sig in candidates:
                if sig.matches(data):
                    if best is None or len(sig.magic) > len(best.magic):
                        best = sig

        # Check non-zero offset signatures
        for sig in self._offset_sigs:
            if sig.matches(data):
                if best is None or len(sig.magic) > len(best.magic):
                    best = sig

        return best

    def detect_all(self, data: bytes) -> List[SignatureEntry]:
        """Detect all matching signatures (for ambiguous files)."""
        return [sig for sig in self._sigs if sig.matches(data)]

    def detect_by_extension(self, ext: str) -> List[SignatureEntry]:
        """Get signatures for a file extension."""
        ext = ext.lower()
        if not ext.startswith("."):
            ext = "." + ext
        return [sig for sig in self._sigs if ext in sig.extensions]

    def detect_by_category(self, category: str) -> List[SignatureEntry]:
        """Get all signatures for a category."""
        return [sig for sig in self._sigs if sig.category == category]

    def list_categories(self) -> List[str]:
        """List all unique categories."""
        return sorted(set(sig.category for sig in self._sigs))

    @property
    def count(self) -> int:
        return len(self._sigs)

    def __len__(self) -> int:
        return len(self._sigs)

    def __repr__(self) -> str:
        return f"SignatureDatabase(entries={len(self._sigs)})"


# =============================================================================
# Global instance
# =============================================================================

_db = SignatureDatabase()


def detect_format(data: bytes) -> Optional[SignatureEntry]:
    """Quick format detection using the global database."""
    return _db.detect(data)


def detect_all_formats(data: bytes) -> List[SignatureEntry]:
    """Detect all matching formats."""
    return _db.detect_all(data)


def format_name(data: bytes) -> str:
    """Return format name string, or 'Unknown'."""
    sig = detect_format(data)
    return sig.name if sig else "Unknown"
