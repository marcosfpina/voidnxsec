#!/usr/bin/env python3
"""
Audeze Mobius — HID vendor command DFU trigger.

The device enumerates as 0BDA:4B09 (Realtek frontend) in its current
broken state. The HID interface (iface 3) is the only programmable
surface during the ~1.3s active window. Strategy:

  1. Pre-open /dev/hidrawN on edge-trigger (poll /sys at 5ms)
  2. Fire candidate vendor commands rapidly
  3. Watch for re-enum as native Audeze 22d9:0002 (bootloader)
     or GigaDevice 28e9:0189 (factory ROM DFU)
     or STM32 0483:df11 (STM compat DFU)

Candidate command bytes derived from the project's existing
hid-fw-dump.py (cmd 0x10 = ENTER_DFU, 0xFF = RESET, etc.).
We fuzz a small set; never any write/erase commands.
"""
import os
import sys
import time
import glob
from pathlib import Path

SYSFS = Path("/sys/bus/usb/devices")
TARGET_VID = 0x0BDA
TARGET_PID = 0x4B09
HID_REPORT_SIZE = 64

# Candidate command bytes that should be SAFE (no flash write/erase)
# Format: 65-byte report: [report_id=0x00, cmd, payload...]
CANDIDATES = [
    (0x01, "GET_FW_VERSION"),
    (0x02, "GET_FW_CHECKSUM"),
    (0x10, "ENTER_DFU"),
    (0x11, "ENTER_BOOTLOADER_alt"),
    (0x80, "VENDOR_QUERY_alt"),
    (0xA0, "MFG_MODE"),
    (0xF0, "REBOOT_TO_DFU"),
    (0xFE, "REBOOT_SOFT"),
]


def find_target_sysfs():
    for entry in SYSFS.iterdir():
        if ":" in entry.name or entry.name.startswith("usb"):
            continue
        try:
            vid = int((entry / "idVendor").read_text().strip(), 16)
            pid = int((entry / "idProduct").read_text().strip(), 16)
        except Exception:
            continue
        if vid == TARGET_VID and pid == TARGET_PID:
            return entry
    return None


def find_hidraw(sysfs_dev):
    """Locate /dev/hidrawN node bound to this device, if any."""
    if sysfs_dev is None:
        return None
    for hidraw_sys in glob.glob(str(sysfs_dev) + "/*/*/hidraw/hidraw*"):
        name = os.path.basename(hidraw_sys)
        node = f"/dev/{name}"
        if os.path.exists(node):
            return node
    return None


def scan_unusual():
    hits = []
    for entry in SYSFS.iterdir():
        if ":" in entry.name or entry.name.startswith("usb"):
            continue
        try:
            vid = int((entry / "idVendor").read_text().strip(), 16)
            pid = int((entry / "idProduct").read_text().strip(), 16)
        except Exception:
            continue
        if vid == 0x22D9:
            hits.append((entry.name, f"{vid:04x}:{pid:04x}", "Audeze native"))
        elif (vid, pid) == (0x0483, 0xDF11):
            hits.append((entry.name, f"{vid:04x}:{pid:04x}", "STM32 DFU"))
        elif (vid, pid) == (0x28E9, 0x0189):
            hits.append((entry.name, f"{vid:04x}:{pid:04x}", "GigaDevice DFU"))
    return hits


def fire_at_hidraw(node, cmd_byte, label):
    """Write a single vendor report and try to read response."""
    try:
        fd = os.open(node, os.O_RDWR | os.O_NONBLOCK)
    except OSError as e:
        return f"open-fail:{e}"
    try:
        report = bytearray(HID_REPORT_SIZE + 1)
        report[0] = 0x00  # report id
        report[1] = cmd_byte
        try:
            n = os.write(fd, bytes(report))
            wrote = n
        except OSError as e:
            return f"write-fail:{e.errno}:{e.strerror}"
        # tiny read attempt
        time.sleep(0.01)
        try:
            resp = os.read(fd, HID_REPORT_SIZE)
            return f"wrote={wrote} resp={resp.hex()[:32]}"
        except BlockingIOError:
            return f"wrote={wrote} resp=(none)"
        except OSError as e:
            return f"wrote={wrote} read-fail:{e.errno}"
    finally:
        try:
            os.close(fd)
        except Exception:
            pass


def main():
    print("=== Mobius HID vendor DFU trigger ===")
    print("Fast-poll /sys; on appearance: open hidraw, fire candidates.")
    cycles = 0
    last_present = None
    deadline = time.monotonic() + 30.0
    fired_in_cycle = 0
    max_attempts_per_window = 4

    while time.monotonic() < deadline:
        cycles += 1
        sysfs = find_target_sysfs()
        present = sysfs is not None

        if present and last_present is False:
            # Window just opened
            t0 = time.monotonic()
            print(f"\n[+0.000] WINDOW OPEN at sysfs={sysfs.name}")
            fired_in_cycle = 0
            # Wait for hidraw to materialize (kernel needs ~600ms)
            node = None
            wait_start = time.monotonic()
            while time.monotonic() - wait_start < 0.9:
                node = find_hidraw(sysfs)
                if node:
                    break
                time.sleep(0.02)
                # Bail if device vanishes mid-wait
                if find_target_sysfs() is None:
                    print(f"  [-] vanished while waiting for hidraw")
                    node = None
                    break

            if node:
                print(f"  [+{time.monotonic()-t0:.3f}s] hidraw={node}")
                # Fire candidates while still alive
                for cmd, label in CANDIDATES:
                    if find_target_sysfs() is None:
                        print(f"  [-] device gone during fire loop")
                        break
                    elapsed = time.monotonic() - t0
                    result = fire_at_hidraw(node, cmd, label)
                    print(f"  [+{elapsed:.3f}s] cmd 0x{cmd:02x} {label:25s} -> {result}")
                    fired_in_cycle += 1
                    # Check immediately for state change
                    hits = scan_unusual()
                    if hits:
                        print(f"  ★ STATE CHANGE: {hits}")
                        return
                    time.sleep(0.05)
            else:
                print(f"  [-] no hidraw node materialized")

        if not present and last_present is True:
            print(f"[-] window closed ({cycles} polls, fired={fired_in_cycle})")

        last_present = present
        time.sleep(0.005)

    print("\n=== Final scan ===")
    hits = scan_unusual()
    print(f"DFU-mode VIDs: {hits if hits else 'none'}")


if __name__ == "__main__":
    main()
