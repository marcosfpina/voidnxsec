# Audeze Mobius Firmware RE Kit

Hardware de $600 não morre enquanto houver USB e paciência.

## TL;DR

```bash
nix develop
mobius-probe
python scripts/usb-loop-monitor.py -d 60 -o timeline.json
mobius-analyze ./fw/
mobius-capture
mobius-fw-dump
mobius-ghidra fw.bin
mobius-flash fw-patched.bin
```

## Setup

```bash
sudo cp udev/99-audeze-mobius.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo usermod -aG plugdev,wireshark $USER
```

NixOS:

```nix
services.udev.extraRules = builtins.readFile ./udev/99-audeze-mobius.rules;
users.users.seuuser.extraGroups = [ "plugdev" "wireshark" ];
```

## O Problema: Reset Loop

Firmware corrompido → watchdog dispara → bootloader sobe →
não encontra firmware válido → reseta → repete.

Boa notícia: bootloader ainda respira. Janela de oportunidade.

```bash
# Mede o ciclo exato
python scripts/usb-loop-monitor.py --duration 60 --output timeline.json
# PID 0002 aparecendo = DFU mode = flash direto viável
```

## Captura do DMU (mais valioso)

```bash
# Terminal 1
mobius-capture mobius-dmu-session.pcapng

# Terminal 2 — abre o DMU e tenta qualquer operação
# Wireshark depois:
wireshark mobius-dmu-session.pcapng
# Filtro: usb.transfer_type == 0x01
```

## Flash

```bash
# Seguro com backup automático
mobius-flash firmware-patched.bin

# Manual:
dfu-util --device 22d9: --detach
dfu-util --device 22d9:0002 --alt 0 --download firmware.bin --reset
```

## Se Reset Loop < 500ms: JTAG/SWD

```bash
# Abre o headset, procura pads SWD (SWDIO, SWDCLK, GND, VCC)
openocd \
  -f interface/stlink.cfg \
  -f target/stm32f4x.cfg \
  -c "init; halt; dump_image fw-jtag.bin 0x08000000 0x80000; exit"
```

---

## Environment

| Field                          | Value                                          |
| ------------------------------ | ---------------------------------------------- |
| Host kernel                    | 6.18.31                                        |
| USB controller (affected port) | xHCI `0000:00:14.0`, bus 3, port `3-2`         |
| Device VID:PID                 | `0BDA:4B09` (Realtek layer)                    |
| bcdDevice                      | `0.13`                                         |
| USB speed                      | High-speed (480 Mbps)                          |
| Interfaces enumerated          | HID only (audio class never completes)         |
| Reset origin                   | Device-side (zero host errors)                 |
| Boot loop interval             | ~1.2s                                          |
| BIOS version at incident       | 1.53 (updated from 1.31 same session)          |
| ACPI anomaly                   | `\_SB.PC00.RP08.CMDR` AE_NOT_FOUND post-update |
