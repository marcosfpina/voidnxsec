# CLAUDE.md — USB Firmware Recovery Session

## Audeze Mobius // GD32 MCU boot loop intercept

---

## MISSION

O headset Audeze Mobius está preso em boot loop após flash incompleto.
O objetivo desta sessão é interceptar o device na janela de ~1.2s de enumeração
ou congelar o loop via kernel/USB stack — e reflashar o MCU via dfu-util.

Nenhuma pergunta de confirmação. Executa, observa, itera.

---

## HARDWARE CONTEXT

```
Device:      Audeze Mobius 3D 8Ch
VID:PID:     0x0BDA:0x4B09  (Realtek USB layer)
bcdDevice:   0.13
USB speed:   High-speed (480 Mbps)
Port:        bus 3, port 3-2
Controller:  xHCI 0000:00:14.0
Chip (MCU):  GD32 (GigaDevice STM32-compatible)
DFU VID:     0x28e9 (GigaDevice) or 0x0483 (STM32 compat)
```

```
Boot loop pattern:
  [t+0.00s]  device conecta, HID enumera (hid-generic OK)
  [t+1.20s]  USB disconnect — zero erros de host
  [t+1.45s]  reconecta — ciclo infinito

  Audio class nunca completa.
  Manufacturer/Serial = "Audeze Mobius 3D 8Ch" (firmware quirk, normal)
  Host-side: zero erros — reset é iniciado pelo próprio device.
  Diagnóstico: MCU firmware corrompido, GD32 em application boot loop.
```

---

## ENVIRONMENT

NixOS. Ferramentas não estão no PATH global.

```bash
# Sempre via nix-shell
nix-shell -p usbutils dfu-util python3Packages.pyusb --run "<cmd>"

# Ou spawn shell persistente
nix-shell -p usbutils dfu-util python3Packages.pyusb
```

---

## STRATEGY (em ordem de tentativa)

### 1. Confirma estado atual

```bash
nix-shell -p dfu-util --run "dfu-util -l"
lsusb | grep -iE "0bda|28e9|0483|audeze"
sudo dmesg | tail -30 | grep -iE "usb|dfu|GD32"
```

### 2. Intercepção por janela (pyusb polling)

- Poll a cada 10ms
- Detecta o device no momento exato do connect
- Tenta query das interfaces antes do reset
- Tenta enviar comando DFU detach via HID/control transfer

### 3. Congelamento via kernel

```bash
# Opção A — power management do port
echo on | sudo tee /sys/bus/usb/devices/3-2/power/control

# Opção B — unbind/rebind do controller (agressivo)
echo '0000:00:14.0' | sudo tee /sys/bus/pci/drivers/xhci_hcd/unbind
sleep 1
echo '0000:00:14.0' | sudo tee /sys/bus/pci/drivers/xhci_hcd/bind
```

### 4. DFU via USB control transfer na janela

```python
# DFU Detach request (bmRequestType=0x21, bRequest=0x00)
# Tenta forçar o device a entrar em DFU mode via protocol
import usb.core

dev = usb.core.find(idVendor=0x0bda, idProduct=0x4b09)
if dev:
    dev.ctrl_transfer(0x21, 0x00, 0, 0, None, timeout=500)
```

### 5. Flash (quando device estabilizar em DFU)

```bash
nix-shell -p dfu-util --run \
  "dfu-util -a 0 -D MCU_firmware.bin --dfuse-address 0x08000000:leave"
```

---

## FIRMWARE FILES

Localiza os arquivos do flash package e lista:

```bash
find ~ -name "*.bin" -o -name "*.dfu" -o -name "*.mfw" 2>/dev/null | head -20
```

O package contém subsistemas separados:

- USB firmware (Realtek)
- MCU firmware (GD32) ← target principal
- DSP firmware
- BT firmware

---

## COMPORTAMENTO ESPERADO

- Não para pra perguntar. Executa e reporta output.
- Se um approach falha, documenta o erro e tenta o próximo.
- Mantém um log running do que foi tentado e resultado.
- Se o device entrar em DFU mode estável, para tudo e avisa antes de qualquer write.
- Se encontrar algo inesperado no lsusb/dmesg, analisa antes de continuar.

---

## ABORT CONDITIONS

Para imediatamente se:

- `over-current` aparecer no dmesg
- Qualquer write em device errado
- dfu-util reportar target mismatch de address
