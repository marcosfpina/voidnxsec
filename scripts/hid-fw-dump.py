#!/usr/bin/env python3
"""
Audeze Mobius — HID Vendor Command Firmware Dumper
---------------------------------------------------
Device em reset loop = bootloader ainda vivo em algum ponto do ciclo.
Esse script é agressivo no timing — pega a janela de boot.
"""

import hid, sys, time, struct, argparse
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional

AUDEZE_VID = 0x22D9
MOBIUS_PIDS = {
    0x0001: "Mobius (normal mode)",
    0x0002: "Mobius (bootloader/DFU)",
    0x0003: "Mobius (DFU detached)",
}

class VendorCmd:
    GET_FW_VERSION = 0x01
    GET_FW_CHECKSUM = 0x02
    ENTER_DFU = 0x10
    READ_FLASH = 0x20
    RESET_DEVICE = 0xFF

HID_REPORT_SIZE = 64

@dataclass
class MobiusDevice:
    vid: int; pid: int; path: bytes; description: str = ""
    handle: Optional[hid.device] = field(default=None, repr=False)

    def open(self) -> bool:
        try:
            self.handle = hid.device()
            self.handle.open_path(self.path)
            self.handle.set_nonblocking(0)
            return True
        except Exception as e:
            print(f"  [!] Falha ao abrir: {e}", file=sys.stderr)
            self.handle = None
            return False

    def close(self):
        if self.handle:
            try: self.handle.close()
            except: pass
            self.handle = None

    def send_vendor(self, cmd: int, payload: bytes = b"") -> Optional[bytes]:
        if not self.handle: return None
        report = bytearray(HID_REPORT_SIZE + 1)
        report[0] = 0x00; report[1] = cmd
        report[2:2+len(payload)] = payload
        try:
            self.handle.write(bytes(report))
            resp = self.handle.read(HID_REPORT_SIZE, timeout_ms=500)
            return bytes(resp) if resp else None
        except Exception as e:
            print(f"  [WARN] HID I/O: {e}", file=sys.stderr)
            return None


def find_mobius(verbose=False) -> list:
    found = []
    for info in hid.enumerate():
        is_audeze = (info['vendor_id'] == AUDEZE_VID and
                     info['product_id'] in MOBIUS_PIDS)
        is_named = any(k in info.get('product_string','').lower()
                       for k in ('audeze', 'mobius'))
        if is_audeze or is_named:
            desc = MOBIUS_PIDS.get(info['product_id'], f"PID 0x{info['product_id']:04x}")
            dev = MobiusDevice(vid=info['vendor_id'], pid=info['product_id'],
                               path=info['path'], description=desc)
            found.append(dev)
            if verbose:
                print(f"  [+] {dev.description}: {info['path']}")
    return found


def poll_until_found(max_wait=30.0, poll_interval=0.3, verbose=True) -> Optional[MobiusDevice]:
    """
    Polling agressivo — o device em reset loop aparece por ~200-500ms
    antes de sumir de novo. Intervalo curto é essencial.
    """
    deadline = time.monotonic() + max_wait
    dots = 0
    last_seen_at = None

    while time.monotonic() < deadline:
        devices = find_mobius(verbose=False)
        if devices:
            if last_seen_at is None:
                print(f"\n  [*] Device apareceu! Janela ativa...")
            last_seen_at = time.monotonic()
            return devices[0]

        if last_seen_at and (time.monotonic() - last_seen_at) < 2.0:
            # Acabou de sumir — pode ser o reset loop
            print(f"  [!] Device sumiu após {time.monotonic()-last_seen_at:.1f}s — reset loop confirmado")
            print(f"  [*] Aguardando próxima janela...")

        if verbose:
            print(f"\r  [*] Polling{'.' * (dots % 4)}   ", end='', flush=True)
            dots += 1
        time.sleep(poll_interval)

    print()
    return None


def dump_via_hid_read(dev: MobiusDevice, output_path: Path) -> int:
    BLOCK_SIZE = 56
    FLASH_SIZE = 512 * 1024
    total_read = 0

    print(f"  [*] Dump por blocos ({FLASH_SIZE // 1024}KB alvo)...")
    with open(output_path, 'wb') as f:
        addr = 0; errors = 0
        while addr < FLASH_SIZE:
            payload = struct.pack('>II', addr, BLOCK_SIZE)
            resp = dev.send_vendor(VendorCmd.READ_FLASH, payload)
            if resp and len(resp) >= BLOCK_SIZE:
                f.write(resp[8:8+BLOCK_SIZE])
                total_read += BLOCK_SIZE; errors = 0
                if addr % (16*1024) == 0:
                    print(f"\r  [*] {addr//1024}KB / {FLASH_SIZE//1024}KB", end='', flush=True)
            else:
                errors += 1
                f.write(b'\xFF' * BLOCK_SIZE)
                if errors > 10:
                    print(f"\n  [!] Device resetou em 0x{addr:08x}")
                    break
            addr += BLOCK_SIZE
    print()
    return total_read


def dump_passive(dev: MobiusDevice, output_path: Path) -> int:
    """Lê dados espontâneos durante boot — útil pra capturar o que o
    bootloader manda antes de resetar."""
    print("  [*] Modo passivo: capturando dados de boot...")
    collected = bytearray()
    deadline = time.monotonic() + 5.0
    if not dev.handle: return 0
    dev.handle.set_nonblocking(1)
    while time.monotonic() < deadline:
        try:
            data = dev.handle.read(HID_REPORT_SIZE)
            if data:
                collected.extend(data)
                print(f"\r  [*] Coletado: {len(collected)} bytes", end='', flush=True)
        except: break
    print()
    if collected:
        output_path.write_bytes(bytes(collected))
    return len(collected)


def main():
    parser = argparse.ArgumentParser(description='Audeze Mobius HID Firmware Dumper')
    parser.add_argument('--output', '-o', type=Path, default=Path('firmware-hid-dump.bin'))
    parser.add_argument('--wait', '-w', type=float, default=60.0)
    parser.add_argument('--verbose', '-v', action='store_true')
    args = parser.parse_args()

    print("=== Audeze Mobius HID Firmware Dumper ===\n")

    current = find_mobius(verbose=args.verbose)
    dev = current[0] if current else poll_until_found(max_wait=args.wait)

    if not dev:
        print("[!] Timeout — device não apareceu."); sys.exit(1)

    print(f"[OK] {dev.description}")
    if not dev.open():
        print("[!] Falha ao abrir HID. Verifique udev rules."); sys.exit(1)

    try:
        ver = dev.send_vendor(VendorCmd.GET_FW_VERSION)
        if ver:
            try: print(f"[*] Versão raw: {bytes(b for b in ver if 32<=b<127).decode()}")
            except: print(f"[*] Versão raw (hex): {ver[:16].hex()}")

        bytes_read = dump_via_hid_read(dev, args.output)
        if bytes_read == 0:
            passive_out = args.output.with_suffix('.passive.bin')
            bytes_read = dump_passive(dev, passive_out)
            if bytes_read: print(f"[OK] {bytes_read} bytes passivos → {passive_out}")
            else: print("[!] Sem dados. Use mobius-capture para analisar o DMU."); sys.exit(1)
        else:
            print(f"[OK] {bytes_read} bytes → {args.output}")
    finally:
        dev.close()

if __name__ == '__main__':
    main()
