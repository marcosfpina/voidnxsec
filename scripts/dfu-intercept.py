#!/usr/bin/env python3
"""
Audeze Mobius — DFU window intercept.

The device boot-loops every ~2.9s with ~1.3s active window enumerated
as Realtek 0bda:4b09. We race the window:
  1. Poll /sys at 5ms intervals
  2. On appearance, dump interface descriptors (one-shot, for learning)
  3. Fire candidate DFU triggers via control transfer + HID raw report
  4. Watch for re-enum as native Audeze VID (22d9:*) or STM32 DFU (0483:df11)
"""
import os
import sys
import time
import struct
from pathlib import Path

SYSFS = Path("/sys/bus/usb/devices")
TARGET_VID = 0x0BDA
TARGET_PID = 0x4B09
NATIVE_AUDEZE_VID = 0x22D9
STM32_DFU = (0x0483, 0xDF11)
GIGADEVICE_DFU = (0x28E9, 0x0189)

POLL_S = 0.005


def find_target():
    """Return (sysfs_path, busnum, devnum) or None."""
    for entry in SYSFS.iterdir():
        if ":" in entry.name or entry.name.startswith("usb"):
            continue
        try:
            vid = int((entry / "idVendor").read_text().strip(), 16)
            pid = int((entry / "idProduct").read_text().strip(), 16)
        except (FileNotFoundError, OSError, ValueError):
            continue
        if vid == TARGET_VID and pid == TARGET_PID:
            try:
                busnum = int((entry / "busnum").read_text().strip())
                devnum = int((entry / "devnum").read_text().strip())
            except Exception:
                continue
            return entry, busnum, devnum
    return None


def scan_unusual():
    """Return list of paths that look like Audeze DFU/bootloader VIDs."""
    hits = []
    for entry in SYSFS.iterdir():
        if ":" in entry.name or entry.name.startswith("usb"):
            continue
        try:
            vid = int((entry / "idVendor").read_text().strip(), 16)
            pid = int((entry / "idProduct").read_text().strip(), 16)
        except Exception:
            continue
        if vid == NATIVE_AUDEZE_VID:
            hits.append((entry.name, vid, pid, "Audeze native"))
        elif (vid, pid) == STM32_DFU:
            hits.append((entry.name, vid, pid, "STM32 DFU"))
        elif (vid, pid) == GIGADEVICE_DFU:
            hits.append((entry.name, vid, pid, "GD DFU"))
    return hits


def attempt_dfu_detach(busnum, devnum):
    """Send DFU_DETACH (bmReqType=0x21, bReq=0x00) on iface 0."""
    try:
        import usb.core
        import usb.util
    except ImportError:
        print("  [!] pyusb missing"); return None

    dev = usb.core.find(idVendor=TARGET_VID, idProduct=TARGET_PID)
    if dev is None:
        return "device-vanished"

    results = {}
    # Try detaching kernel drivers from all interfaces first
    try:
        cfg = dev.get_active_configuration()
        for iface in cfg:
            ifnum = iface.bInterfaceNumber
            try:
                if dev.is_kernel_driver_active(ifnum):
                    dev.detach_kernel_driver(ifnum)
                    results[f"detached_kdrv_iface{ifnum}"] = "ok"
            except Exception as e:
                results[f"detached_kdrv_iface{ifnum}"] = f"fail:{e}"
        results["interfaces"] = [
            {
                "num": iface.bInterfaceNumber,
                "alt": iface.bAlternateSetting,
                "class": iface.bInterfaceClass,
                "sub": iface.bInterfaceSubClass,
                "proto": iface.bInterfaceProtocol,
                "endpoints": [hex(e.bEndpointAddress) for e in iface],
            }
            for iface in cfg
        ]
    except Exception as e:
        results["cfg_read"] = f"fail:{e}"

    # Attempts: vary wIndex over likely DFU interfaces
    for wIndex in (0, 1, 2, 3):
        for bmReq, bReq, wVal, label in [
            (0x21, 0x00, 0, f"DFU_DETACH iface{wIndex}"),
            (0x40, 0x00, 0, f"vendor_0x00 iface{wIndex}"),
            (0x40, 0xFF, 0, f"vendor_reset iface{wIndex}"),
            (0x21, 0x01, 0, f"DFU_DNLOAD_probe iface{wIndex}"),
        ]:
            try:
                r = dev.ctrl_transfer(bmReq, bReq, wVal, wIndex, 8, timeout=200)
                results[label] = f"OK: {bytes(r).hex()}"
            except usb.core.USBError as e:
                results[label] = f"err:{e.errno}:{e.strerror}"
            except Exception as e:
                results[label] = f"exc:{e}"
    return results


def main():
    print("=== Mobius DFU intercept ===")
    print(f"Polling /sys every {POLL_S*1000:.0f}ms for {TARGET_VID:04x}:{TARGET_PID:04x}")
    cycles = 0
    last_state = None
    deadline = time.monotonic() + 30.0

    while time.monotonic() < deadline:
        cycles += 1
        tgt = find_target()
        now_state = tgt is not None

        # State edge: absent → present (window just opened)
        if now_state and last_state is False:
            entry, busnum, devnum = tgt
            t0 = time.monotonic()
            print(f"\n[+{t0:.3f}] WINDOW OPEN  path={entry.name} bus={busnum} dev={devnum}")
            # tiny delay so config descriptors are populated
            time.sleep(0.05)
            results = attempt_dfu_detach(busnum, devnum)
            elapsed = time.monotonic() - t0
            print(f"[+{elapsed:.3f}s after open] attempts:")
            if isinstance(results, dict):
                for k, v in results.items():
                    if k == "interfaces":
                        print(f"  interfaces:")
                        for i in v:
                            print(f"    {i}")
                    else:
                        print(f"  {k}: {v}")
            else:
                print(f"  {results}")

            # Check for re-enum into bootloader VID
            hits = scan_unusual()
            if hits:
                print(f"  ★ NEW VID/PID detected: {hits}")
                break

        if not now_state and last_state is True:
            print(f"[-] window closed (cycle {cycles})")

        last_state = now_state
        time.sleep(POLL_S)

    print("\n=== Final scan ===")
    hits = scan_unusual()
    if hits:
        print(f"DFU/bootloader VIDs present: {hits}")
    else:
        print("No DFU/bootloader VID change observed.")


if __name__ == "__main__":
    main()
