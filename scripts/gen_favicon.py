"""Generates the 16x16 favicon (ICO, 32-bit BMP, no external assets): a blue disc with a white "B".
Prints base64; the same string is embedded as FAVICON_B64 in api/index.py and deno/main.ts (tests compare)."""
import base64, struct
B = ["0111100", "0100010", "0100010", "0111100", "0100010", "0100010", "0111100"]  # 7x7 glyph
def build():
    n = 16; px = []
    for y in range(n - 1, -1, -1):  # BMP rows bottom-up
        for x in range(n):
            dx, dy = x - 7.5, y - 7.5; inside = dx * dx + dy * dy <= 7.6 * 7.6
            gx, gy = x - 5, y - 4; glyph = 0 <= gx < 7 and 0 <= gy < 7 and B[gy][gx] == "1"
            px.append((255, 255, 255, 255) if inside and glyph else (0xD2, 0x52, 0x00, 255) if inside else (0, 0, 0, 0))  # BGRA
    xor = b"".join(bytes(p) for p in px); andmask = b"\0" * (4 * n)  # 16 px rows padded to 32 bits
    bmp = struct.pack("<IiiHHIIiiII", 40, n, 2 * n, 1, 32, 0, len(xor) + len(andmask), 0, 0, 0, 0) + xor + andmask
    return struct.pack("<HHH", 0, 1, 1) + struct.pack("<BBBBHHII", n, n, 0, 0, 1, 32, len(bmp), 22) + bmp
if __name__ == "__main__": print(base64.b64encode(build()).decode())
