# hardware-context.yml

# Audeze Mobius — USB Boot Loop Fix

# Source: dmesg boot session, kernel 6.18.31

host:
kernel: "6.18.31"
xhci_controllers: - pci: "0000:00:0d.0"
buses: [1, 2]
hci_version: "0x120"
hcc_params: "0x20007fc1"
quirks: "0x0000000200009810"
usb_spec: "USB 3.2 Enhanced SuperSpeed" - pci: "0000:00:14.0"
buses: [3, 4]
hci_version: "0x120"
hcc_params: "0x20007fc1"
quirks: "0x0000100200009810" # quirk diferente — nota relevante
usb_spec: "USB 3.1 Enhanced SuperSpeed"
acpi_errors: - symbol: "\_SB.PC00.RP08.CMDR"
code: "AE_NOT_FOUND"
method: "\_SB.PC00.RP05.PCRP.\_ON"
note: "post BIOS 1.53 — possivelmente relacionado ao update"
ucsi:
error: "unknown error 256"
detail: "GET_CABLE_PROPERTY failed (-5)"
device: "USBC000:00"

device:
product: "Audeze Mobius 3D 8Ch"
manufacturer: "Audeze Mobius 3D 8Ch" # manufacturer = product string (firmware quirk)
serial: "Audeze Mobius 3D 8Ch" # serial = product string (firmware quirk)
usb:
vid: "0x0BDA" # Realtek — não Audeze VID nativo
pid: "0x4B09"
bcdDevice: "0.13"
speed: "high-speed" # USB 2.0 480Mbps
bus: 3
port: "3-2"
controller: "0000:00:14.0"

interfaces: # enumeradas via hid-generic antes do crash - number: "1.3"
driver: "hid-generic"
type: "USB HID v1.11"
nodes: [hiddev96, hidraw0]
input_nodes: ["Consumer Control", "main HID"]
note: "único subsistema que sobe antes do reset — audio class nunca completa"

boot_loop:
pattern: "connect → HID enum → disconnect → repeat"
interval_seconds: "~1.2"
first_disconnect: 6.39 # segundos após boot
enumeration_count: "55+" # dentro da sessão de boot (device# 2 → 60+)
error_on_disconnect: null # ZERO erros de host — reset iniciado pelo device
snd_usb_audio_registered: 22.51 # carregou DEPOIS do loop já estar ativo
diagnosis: "MCU firmware corrupt — boot loop iniciado pelo próprio GD32"
