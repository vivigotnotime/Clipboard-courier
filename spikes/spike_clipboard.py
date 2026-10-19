"""Spikes 2-4: text clipboard, region capture, image clipboard on Wayland.

Run:  python spikes/spike_clipboard.py
When the crosshair appears, drag a region (Esc cancels).
"""
import pathlib
import shutil
import subprocess
import tempfile

# Are the tools installed?
for tool in ("wl-copy", "wl-paste", "grim", "slurp"):
    print(f"{tool:9} -> {shutil.which(tool) or 'MISSING'}")

# Spike 2: text round trip
sample = b"courier spike text"
subprocess.run(["wl-copy"], input=sample, check=True)
pasted = subprocess.run(["wl-paste", "--no-newline"], capture_output=True, check=True).stdout
print("Text round-trip OK:", pasted == sample)

# Spike 3: selected-region capture
geometry = subprocess.run(["slurp"], capture_output=True, text=True)
if geometry.returncode != 0:
    print("Region selection cancelled; skipping capture and image spikes.")
    raise SystemExit(0)

shot = pathlib.Path(tempfile.gettempdir()) / "courier_spike.png"
subprocess.run(["grim", "-g", geometry.stdout.strip(), str(shot)], check=True)
print(f"Captured {shot} ({shot.stat().st_size} bytes)")

# Spike 4: put the PNG on the clipboard
with open(shot, "rb") as f:
    subprocess.run(["wl-copy", "--type", "image/png"], stdin=f, check=True)
types = subprocess.run(["wl-paste", "--list-types"], capture_output=True, text=True).stdout.split()
print("Clipboard now offers:", types)
print("Now paste into another app (e.g. a chat box or GIMP) to confirm the image arrived.")
