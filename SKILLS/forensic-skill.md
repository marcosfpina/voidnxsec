# USB Hardware Debugging & Firmware Recovery Skill
## NixOS/Linux — Embedded Devices, DFU, Audio Class

---

## CONTEXT

This skill applies when diagnosing USB enumeration failures, firmware boot loops,
DFU recovery, and USB audio class issues on NixOS. Primary targets: embedded devices
(headsets, DACs, controllers) using Realtek/GD32/STM32 chipsets.

---

## ENVIRONMENT NOTES (NixOS-specific)

Tools are NOT globally available. Always use nix-shell or check nixpkgs first.

```bash
# One-shot tool access (preferred)
nix-shell -p usbutils dfu-util python3Packages.pyusb --run "<command>"

# Or add to devShell in flake.nix for persistent access:
# buildInputs = [ pkgs.usbutils pkgs.dfu-util pkgs.python3Packages.pyusb ];
```

---

## DIAGNOSTIC LAYERS (run in order)

### Layer 0 — Physical
- Different USB cable (USB-C to A vs USB-C to C changes negotiation)
- Different USB port (bus 1/2 vs bus 3/4 = different xHCI controller)
- Powered USB hub to rule out power budget issues
- Device battery level (some embedded devices misbehave under 20%)

### Layer 1 — Kernel observation
```bash
# Real-time kernel events
sudo dmesg -w | grep -iE "usb|xhci|disconnect|reset|error|dfu|GD32|STM32"

# Count enumeration cycles (boot loop indicator)
sudo journalctl -b 0 -k | grep "New USB device" | grep -c "idVendor"

# Full device tree
lsusb -t

# Verbose device info (replace VID:PID)
lsusb -v -d VVVV:PPPP 2>/dev/null
```

### Layer 2 — Boot loop classification

Pattern: connect → enumerate → disconnect (~1-2s) → repeat

| Symptom | Classification | Root cause |
|---|---|---|
| No error, clean enum, fast reset | Firmware boot loop | Bad/partial flash |
| `device not accepting address` | Electrical/power issue | Cable, hub, port |
| `reset after Xms` repeated | xHCI quirk or power | BIOS/kernel quirk |
| `over-current` | Hardware damage | Port or device |
| Enumerates as GD32/STM32 DFU | DFU mode trap | Interrupted flash |

### Layer 3 — DFU detection
```bash
# Check if device is in DFU mode (VID 0483 = STM32/GD32, VID 0bda = Realtek)
nix-shell -p dfu-util --run "dfu-util -l"

# Also check raw lsusb for alternate VIDs
lsusb | grep -iE "0483|1fc9|03eb|2341"

# udevadm for full device attributes
sudo udevadm info -a -n /dev/bus/usb/BUS/DEVICE
```

### Layer 4 — pyusb raw inspection
```python
# Run with: nix-shell -p python3Packages.pyusb --run "python3 script.py"
import usb.core, time

VID = 0x0bda  # adjust
PID = 0x4b09  # adjust

while True:
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev:
        print(f"Found: bus={dev.bus} addr={dev.address}")
        for cfg in dev:
            for intf in cfg:
                print(f"  Interface {intf.bInterfaceNumber}: "
                      f"class={intf.bInterfaceClass} "
                      f"subclass={intf.bInterfaceSubClass} "
                      f"protocol={intf.bInterfaceProtocol}")
        break
    time.sleep(0.05)
```

USB class codes relevant to audio devices:
- `0x01` = Audio
- `0x03` = HID
- `0xFE subclass 0x01` = DFU

---

## DFU RECOVERY WORKFLOW

### If device appears in DFU mode:
```bash
# List DFU targets
nix-shell -p dfu-util --run "dfu-util -l"

# Flash .bin file (adjust alt, address per device datasheet)
nix-shell -p dfu-util --run \
  "dfu-util -a 0 -D firmware.bin --dfuse-address 0x08000000"

# Flash .dfu file (self-contained with target info)
nix-shell -p dfu-util --run "dfu-util -D firmware.dfu"

# Reset device after flash
nix-shell -p dfu-util --run "dfu-util -e"
```

### GD32-specific notes:
- GD32 is pin-compatible STM32 clone, same DFU protocol (USB DFU 1.1)
- VID in DFU mode: `0x28e9` (GigaDevice) or `0x0483` (STM32 compatible)
- Some GD32 devices expose DFU only when BOOT0 pin is high — not software-triggerable
- ROM DFU bootloader survives any bad flash (it's in write-protected ROM)

---

## AUDIO CLASS SPECIFIC

### Audeze Mobius (VID 0bda PID 4b09):
- Realtek USB audio chip + GD32 MCU
- Flash targets: USB (Realtek), MCU (GD32), DSP, BT (separate subsystems)
- Boot loop = MCU firmware corrupt, Realtek layer still partially works (hence HID up, audio down)
- Recovery window: ~1.2s before self-reset
- HQ app requires audio class enumeration complete — won't see device in boot loop
- dfu-util can reach GD32 ROM bootloader independent of application firmware

### Timing a boot loop for tool interception:
```bash
# Script to catch device in enumeration window
python3 - << 'EOF'
import usb.core, time, subprocess

VID, PID = 0x0bda, 0x4b09
print("Waiting for device...")
cycles = 0
while True:
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev:
        cycles += 1
        t = time.time()
        print(f"Cycle {cycles} at {t:.3f} — bus={dev.bus} addr={dev.address}")
        # Place your intervention here
        time.sleep(0.1)
    time.sleep(0.02)
EOF
```

---

## NIXOS UDEV RULES (for persistent device access without sudo)

Add to `configuration.nix` or hardware module:
```nix
services.udev.extraRules = ''
  # Audeze Mobius
  SUBSYSTEM=="usb", ATTRS{idVendor}=="0bda", ATTRS{idProduct}=="4b09", MODE="0666", GROUP="audio"
  # GD32 DFU mode
  SUBSYSTEM=="usb", ATTRS{idVendor}=="28e9", MODE="0666", GROUP="wheel"
  # STM32 DFU mode  
  SUBSYSTEM=="usb", ATTRS{idVendor}=="0483", ATTRS{idProduct}=="df11", MODE="0666", GROUP="wheel"
'';
```

---

## USEFUL REFERENCES

- USB class codes: https://www.usb.org/defined-class-codes
- DFU spec: USB Device Firmware Upgrade Specification 1.1
- GD32 datasheet: search "GD32 DFU AN" on GigaDevice site
- dfu-util docs: https://dfu-util.sourceforge.net/dfu-suffix.html
- Realtek USB audio: VID 0bda covers entire Realtek USB product line

---

## INSTALL PATH (voidnxlabs)

Copy to: `/mnt/skills/user/usb-hw-debug/SKILL.md`
