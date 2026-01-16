"""
Fast QR Code Generator for Kodi
Pure Python implementation using qrcode library
Generates PNG QR codes directly from URLs

This is a GENERIC module - no provider-specific logic!
Size: qrcode library is ~50KB, pure Python
"""

import io
from typing import Optional


def generate_qr_code_png(data: str, size: int = 512) -> Optional[bytes]:
    """
    Generate QR code PNG from data string

    This is a generic function that works for ANY provider.
    No provider-specific logic here!

    Args:
        data: String to encode (URL, code, etc.)
        size: Output size in pixels (square)

    Returns:
        PNG file content as bytes, or None if failed
    """
    try:
        import qrcode  # type: ignore
        from qrcode.image.pure import PyPNGImage  # type: ignore

        # Create QR code
        qr = qrcode.QRCode(
            version=1,  # Auto-size
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )

        qr.add_data(data)
        qr.make(fit=True)

        # Generate image using pure Python PNG backend
        img = qr.make_image(image_factory=PyPNGImage, fill_color="black", back_color="white")

        # Convert to PNG bytes
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        png_data = buffer.getvalue()

        return png_data

    except ImportError:
        # Fallback: Try with PIL if available
        try:
            import qrcode

            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )

            qr.add_data(data)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")

            buffer = io.BytesIO()
            img.save(buffer, format="PNG")
            png_data = buffer.getvalue()

            return png_data

        except Exception as e:
            print(f"Failed to generate QR code: {e}")
            return None

    except Exception as e:
        print(f"Failed to generate QR code: {e}")
        return None


# Test function
if __name__ == "__main__":
    # Test QR generation
    test_url = "https://example.com/login?code=ABC123"

    png_data = generate_qr_code_png(test_url, size=512)
    if png_data:
        print(f"Generated QR code PNG: {len(png_data)} bytes")

        # Save to file for testing
        with open("test_qr.png", "wb") as f:
            f.write(png_data)
        print("Saved to test_qr.png")
    else:
        print("Failed to generate QR code")
