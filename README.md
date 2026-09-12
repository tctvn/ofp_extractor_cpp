# Oppo OFP Decryptor C++

A blazing fast, standalone C++ tool to decrypt and extract Oppo and Realme `.ofp` firmware files. This tool supports OFP files for both **Qualcomm (QC)** and **MediaTek (MTK)** chipsets.

It decrypts the internal AES-CFB encrypted partitions (`system.img`, `boot.img`, `vendor.img`, etc.) and unpacks the OFP container into ready-to-flash standard firmware images.

## Features

- 🚀 **High Performance:** Written in modern C++ with optimized I/O operations for extracting multi-gigabyte firmware files in seconds/minutes.
- 🔓 **Universal Support:** Automatically detects and extracts both MTK and QC OFP formats.
- 📦 **Standalone:** Zero heavy dependencies. Uses lightweight libraries (`tinyxml2`, `tiny-AES-c`) which are already bundled.
- 🖱️ **Drag and Drop:** Simple interface! You can use it via the Command Line, or simply drag and drop an `.ofp` file onto the executable.

## Prerequisites

To build this project from source, you will need:
- **CMake** (v3.10 or higher)
- **C++ Compiler** (MSVC on Windows, GCC/Clang on Linux/macOS, supporting C++17)

## Building from Source

1. Clone or download this repository.
2. Open a terminal/command prompt in the root of the project directory (`ofp_extractor_cpp`).
3. Generate the build files using CMake:
   ```bash
   cmake -B build -S .
   ```
4. Compile the project:
   ```bash
   cmake --build build --config Release
   ```

Upon a successful build, the executable `ofp_extractor` (or `ofp_extractor.exe` on Windows) will be located inside the `build/Release/` directory.

## Usage

### Method 1: Command Line (Recommended)

```bash
./ofp_extractor <path_to_ofp_file> [output_directory]
```

**Example:**
```bash
./ofp_extractor C:\Downloads\CPH1803EX_11_A.34.ofp C:\Extracted_Firmware
```
*If you omit the `[output_directory]`, the tool will automatically create a folder named after your `.ofp` file in the same directory as the OFP file.*

### Method 2: Drag and Drop (Windows)
Simply grab an `.ofp` file from your file explorer and drag it directly onto the `ofp_extractor.exe` icon. A terminal window will pop up showing the extraction progress.

## Third-Party Libraries Included
- [tiny-AES-c](https://github.com/kokke/tiny-AES-c) - A small and portable implementation of the AES ECB/CBC/CTR/CFB algorithms in C.
- [tinyxml2](https://github.com/leethomason/tinyxml2) - A simple, small, efficient, C++ XML parser.
- MD5 implementation in C.

## Acknowledgments
- Based on the reverse-engineering and decryption logic originally developed by [bkerler](https://github.com/bkerler) in the Python `oppo_decrypt` tool. This project ports that heavy lifting to C++ for drastically improved speeds and standalone execution.

## License
This project is licensed under the [MIT License](LICENSE) - see the LICENSE file for details.
