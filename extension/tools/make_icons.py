"""Draw the PhishGuard shield icon as PNGs (16/32/48/128) with only the
standard library, so the repo needs no image editor or Pillow.

Run from the extension folder:  py tools/make_icons.py
"""
import struct
import zlib
from pathlib import Path

TOP, BOTTOM = (56, 189, 248), (99, 102, 241)  # sky-400 -> indigo-500
CHECK = [(-0.36, 0.02), (-0.08, 0.30), (0.40, -0.24)]
THICKNESS = 0.12


def in_shield(u: float, v: float) -> bool:
    """Shield in [-1, 1] coordinates (v grows downwards)."""
    if v < -0.85 or v > 0.95:
        return False
    if v <= 0.15:
        # Rounded top corners: inside a rectangle minus the corner circles.
        r, x0, y0 = 0.22, 0.78 - 0.22, -0.85 + 0.22
        if abs(u) > 0.78:
            return False
        if abs(u) > x0 and v < y0:
            return (abs(u) - x0) ** 2 + (v - y0) ** 2 <= r * r
        return True
    # Lower half: an ellipse narrowing to the point at the bottom.
    return abs(u) <= 0.78 * max(0.0, 1 - ((v - 0.15) / 0.8) ** 2) ** 0.5


def near_check(u: float, v: float) -> bool:
    for (ax, ay), (bx, by) in zip(CHECK, CHECK[1:]):
        dx, dy = bx - ax, by - ay
        t = max(0.0, min(1.0, ((u - ax) * dx + (v - ay) * dy) / (dx * dx + dy * dy)))
        if (u - ax - t * dx) ** 2 + (v - ay - t * dy) ** 2 <= (THICKNESS / 2) ** 2:
            return True
    return False


def render(size: int, samples: int = 4) -> bytes:
    rows = []
    for y in range(size):
        row = bytearray([0])  # PNG filter type 0 for this scanline
        for x in range(size):
            acc = [0.0, 0.0, 0.0, 0.0]
            for sy in range(samples):
                for sx in range(samples):
                    u = ((x + (sx + 0.5) / samples) / size) * 2 - 1
                    v = ((y + (sy + 0.5) / samples) / size) * 2 - 1
                    if not in_shield(u * 1.08, v * 1.08):
                        continue
                    if near_check(u, v):
                        color = (255, 255, 255)
                    else:
                        t = (v + 1) / 2
                        color = tuple(round(a + (b - a) * t) for a, b in zip(TOP, BOTTOM))
                    for i in range(3):
                        acc[i] += color[i]
                    acc[3] += 255
            n = samples * samples
            alpha = acc[3] / n
            rgb = [round(c / (acc[3] / 255)) if acc[3] else 0 for c in acc[:3]]
            row += bytes(rgb + [round(alpha)])
        rows.append(bytes(row))
    raw = b"".join(rows)

    def chunk(tag: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data))

    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # 8-bit RGBA
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


if __name__ == "__main__":
    out = Path(__file__).resolve().parents[1] / "icons"
    out.mkdir(exist_ok=True)
    for size in (16, 32, 48, 128):
        (out / f"icon{size}.png").write_bytes(render(size))
        print("wrote", out / f"icon{size}.png")
