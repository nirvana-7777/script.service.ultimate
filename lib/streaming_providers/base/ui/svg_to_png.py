"""
Lightweight SVG to PNG converter for QR codes
Pure Python implementation - no external dependencies
Optimized for simple QR code SVGs (rectangles only)

Size: ~5KB
Dependencies: None (uses only Python standard library)
"""
import xml.etree.ElementTree as ET
import struct
import zlib
import io
from typing import Tuple, Optional


class SVGToPNGConverter:
    """
    Minimal SVG to PNG converter for QR codes

    Handles SVG files containing:
    - <rect> elements (QR code squares)
    - <path> elements with simple rect commands
    - Basic viewBox and dimensions
    """

    def __init__(self):
        self.width = 0
        self.height = 0
        self.pixels = []

    def convert(self, svg_data: bytes, output_size: int = 512) -> bytes:
        """
        Convert SVG data to PNG

        Args:
            svg_data: SVG file content as bytes
            output_size: Desired output size in pixels (square)

        Returns:
            PNG file content as bytes
        """
        # Parse SVG
        root = ET.fromstring(svg_data)

        # Get dimensions
        viewbox = root.get('viewBox')
        if viewbox:
            parts = viewbox.split()
            svg_width = float(parts[2])
            svg_height = float(parts[3])
        else:
            svg_width = float(root.get('width', '100').replace('px', ''))
            svg_height = float(root.get('height', '100').replace('px', ''))

        # Create output image
        self.width = output_size
        self.height = output_size

        # Initialize white background
        self.pixels = [[255, 255, 255] for _ in range(self.width * self.height)]

        # Calculate scale factor
        scale_x = output_size / svg_width
        scale_y = output_size / svg_height

        # Process all rect elements (QR code squares)
        for rect in root.iter('{http://www.w3.org/2000/svg}rect'):
            self._draw_rect(rect, scale_x, scale_y)

        # Process path elements (alternative QR format)
        for path in root.iter('{http://www.w3.org/2000/svg}path'):
            self._draw_path(path, scale_x, scale_y)

        # Generate PNG
        return self._create_png()

    def _draw_rect(self, rect, scale_x: float, scale_y: float):
        """Draw a rectangle from SVG rect element"""
        try:
            x = float(rect.get('x', 0))
            y = float(rect.get('y', 0))
            width = float(rect.get('width', 0))
            height = float(rect.get('height', 0))
            fill = rect.get('fill', 'black').lower()

            # Only draw black rectangles (QR code data)
            if fill in ['black', '#000', '#000000', 'rgb(0,0,0)']:
                # Scale coordinates
                x1 = int(x * scale_x)
                y1 = int(y * scale_y)
                x2 = int((x + width) * scale_x)
                y2 = int((y + height) * scale_y)

                # Draw rectangle
                self._fill_rect(x1, y1, x2, y2)
        except (ValueError, TypeError):
            pass

    def _draw_path(self, path, scale_x: float, scale_y: float):
        """Draw rectangles from SVG path element (M x y h w v h commands)"""
        try:
            d = path.get('d', '')
            fill = path.get('fill', 'black').lower()

            # Only draw black paths
            if fill not in ['black', '#000', '#000000', 'rgb(0,0,0)']:
                return

            # Parse simple path commands (M x y h w v h format for rectangles)
            commands = d.replace(',', ' ').split()
            i = 0
            while i < len(commands):
                if commands[i] == 'M':
                    # Move to position
                    x = float(commands[i + 1])
                    y = float(commands[i + 2])
                    i += 3

                    # Look for h (horizontal) and v (vertical) to form rectangle
                    if i + 3 < len(commands):
                        if commands[i] == 'h':
                            width = float(commands[i + 1])
                            i += 2
                            if commands[i] == 'v':
                                height = float(commands[i + 1])
                                i += 2

                                # Draw rectangle
                                x1 = int(x * scale_x)
                                y1 = int(y * scale_y)
                                x2 = int((x + width) * scale_x)
                                y2 = int((y + height) * scale_y)
                                self._fill_rect(x1, y1, x2, y2)
                else:
                    i += 1
        except (ValueError, TypeError, IndexError):
            pass

    def _fill_rect(self, x1: int, y1: int, x2: int, y2: int):
        """Fill rectangle with black color"""
        for y in range(max(0, y1), min(self.height, y2)):
            for x in range(max(0, x1), min(self.width, x2)):
                idx = y * self.width + x
                if 0 <= idx < len(self.pixels):
                    self.pixels[idx] = [0, 0, 0]  # Black

    def _create_png(self) -> bytes:
        """
        Create PNG file from pixel data
        Uses PNG format specification for maximum compatibility
        """
        # PNG signature
        png_data = b'\x89PNG\r\n\x1a\n'

        # IHDR chunk (image header)
        ihdr_data = struct.pack('>IIBBBBB',
                                self.width,  # Width
                                self.height,  # Height
                                8,  # Bit depth
                                2,  # Color type (RGB)
                                0,  # Compression
                                0,  # Filter
                                0  # Interlace
                                )
        png_data += self._make_chunk(b'IHDR', ihdr_data)

        # IDAT chunk (image data)
        raw_data = b''
        for y in range(self.height):
            raw_data += b'\x00'  # Filter type (none)
            for x in range(self.width):
                idx = y * self.width + x
                pixel = self.pixels[idx]
                raw_data += bytes(pixel)

        compressed_data = zlib.compress(raw_data, 9)
        png_data += self._make_chunk(b'IDAT', compressed_data)

        # IEND chunk (end of file)
        png_data += self._make_chunk(b'IEND', b'')

        return png_data

    def _make_chunk(self, chunk_type: bytes, data: bytes) -> bytes:
        """Create a PNG chunk with length, type, data, and CRC"""
        length = struct.pack('>I', len(data))
        crc = zlib.crc32(chunk_type + data) & 0xffffffff
        crc_bytes = struct.pack('>I', crc)
        return length + chunk_type + data + crc_bytes


def convert_svg_to_png(svg_data: bytes, output_size: int = 512) -> bytes:
    """
    Convenience function to convert SVG to PNG

    Args:
        svg_data: SVG file content as bytes
        output_size: Desired output size (default 512x512)

    Returns:
        PNG file content as bytes

    Example:
        with open('qr_code.svg', 'rb') as f:
            svg_data = f.read()
        png_data = convert_svg_to_png(svg_data, output_size=512)
        with open('qr_code.png', 'wb') as f:
            f.write(png_data)
    """
    converter = SVGToPNGConverter()
    return converter.convert(svg_data, output_size)


# Test function
if __name__ == '__main__':
    # Example: Create a simple test QR-like SVG and convert it
    test_svg = b'''<?xml version="1.0" encoding="UTF-8"?>
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
        <rect fill="white" x="0" y="0" width="100" height="100"/>
        <rect fill="black" x="10" y="10" width="10" height="10"/>
        <rect fill="black" x="30" y="10" width="10" height="10"/>
        <rect fill="black" x="50" y="10" width="10" height="10"/>
        <rect fill="black" x="10" y="30" width="10" height="10"/>
        <rect fill="black" x="50" y="30" width="10" height="10"/>
        <rect fill="black" x="10" y="50" width="10" height="10"/>
        <rect fill="black" x="30" y="50" width="10" height="10"/>
        <rect fill="black" x="50" y="50" width="10" height="10"/>
    </svg>'''

    png_data = convert_svg_to_png(test_svg, output_size=512)
    print(f"Converted SVG to PNG: {len(png_data)} bytes")

    # Save to file if you want to test
    # with open('test_qr.png', 'wb') as f:
    #     f.write(png_data)