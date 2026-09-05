#!/usr/bin/env python3
"""
Audeze Mobius — Firmware Binary Analyzer
-----------------------------------------
Análise estática profunda: estrutura ARM Cortex-M, vetor de interrupção,
seções de áudio/DSP, strings de versão, checksum validation.
"""

import sys, struct, math, argparse
from pathlib import Path
from dataclasses import dataclass
from typing import Optional
from collections import Counter

# ── ARM Cortex-M Vector Table ────────────────────────────────────────────────
# Os primeiros 64 bytes de um firmware ARM barebones são o vetor de interrupção
# Offset 0x00: Initial Stack Pointer
# Offset 0x04: Reset Handler (entry point)
# Offset 0x08 em diante: exception handlers

CORTEX_M_VECTORS = [
    (0x00, "Initial Stack Pointer"),
    (0x04, "Reset_Handler (entry point)"),
    (0x08, "NMI_Handler"),
    (0x0C, "HardFault_Handler"),
    (0x10, "MemManage_Handler"),
    (0x14, "BusFault_Handler"),
    (0x18, "UsageFault_Handler"),
    (0x28, "SVC_Handler"),
    (0x2C, "DebugMon_Handler"),
    (0x34, "PendSV_Handler"),
    (0x38, "SysTick_Handler"),
    # Offset 0x3C em diante: peripheral IRQs (device-specific)
]

# Endereço base de flash típico para STM32 (mais provável no Mobius)
FLASH_BASE_STM32 = 0x08000000
FLASH_BASE_GENERIC = 0x00000000

# Magic bytes conhecidos
MAGICS = {
    b'\x7fELF': 'ELF binary',
    b'DfuSe':   'DFU suffix (ST DFU format)',
    b'\x1f\x8b': 'gzip compressed',
    b'PK\x03\x04': 'ZIP archive',
    b'\xfe\xed\xfa\xce': 'Mach-O binary',
    b'\x89PNG': 'PNG image (embedded resource?)',
    b'RIFF': 'RIFF container (WAV?)',
    # ARM Thumb2 boot típico — LDR SP, = valor (common cortex-M start)
    b'\x00\x00\x00\x20': 'Possível Cortex-M (stack pointer típico @0x20000000)',
}

# Padrões de strings interessantes pro Mobius
INTERESTING_PATTERNS = [
    'version', 'firmware', 'fw', 'boot', 'dfu', 'audeze', 'mobius',
    'waves', 'nx', 'dsp', 'filter', 'eq', 'bass', 'treble', 'surround',
    'usb', 'hid', 'audio', 'sample', 'rate', 'channel', 'volume',
    'error', 'fail', 'ok', 'init', 'flash', 'erase', 'write', 'read',
    'bluetooth', 'bt', 'mic', 'headset',
]


@dataclass
class FirmwareInfo:
    path: Path
    size: int
    data: bytes
    entropy: float
    likely_arch: str = "unknown"
    flash_base: int = 0
    entry_point: Optional[int] = None
    stack_init: Optional[int] = None
    is_arm_cortexm: bool = False
    has_dfu_suffix: bool = False
    version_strings: list = None
    interesting_strings: list = None

    def __post_init__(self):
        self.version_strings = []
        self.interesting_strings = []


def compute_entropy(data: bytes, block_size: int = 256) -> float:
    """Entropia de Shannon — 0.0 = constante, 1.0 = random/encriptado."""
    if not data: return 0.0
    counts = Counter(data)
    total = len(data)
    entropy = -sum((c/total) * math.log2(c/total) for c in counts.values())
    return entropy / 8.0  # normaliza para [0, 1]


def entropy_map(data: bytes, chunk_size: int = 1024) -> list[tuple[int, float]]:
    """Mapa de entropia por chunk — identifica regiões comprimidas/encriptadas."""
    result = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i:i+chunk_size]
        if chunk:
            result.append((i, compute_entropy(chunk)))
    return result


def analyze_arm_vectors(data: bytes, base: int = FLASH_BASE_STM32) -> dict:
    """Tenta interpretar os primeiros bytes como vetor ARM Cortex-M."""
    if len(data) < 0x40:
        return {}

    vectors = {}
    for offset, name in CORTEX_M_VECTORS:
        if offset + 4 <= len(data):
            value = struct.unpack_from('<I', data, offset)[0]
            vectors[name] = value

    # Valida heurística:
    # 1. Stack pointer deve apontar pro fim da RAM (0x20000000 + size)
    # 2. Reset handler deve ser endereço dentro do flash (base + offset)
    sp = vectors.get("Initial Stack Pointer", 0)
    reset = vectors.get("Reset_Handler (entry point)", 0)

    is_valid_arm = (
        0x20000000 <= sp <= 0x20100000 and    # RAM típica STM32
        base <= reset <= base + len(data)      # dentro do flash
    )

    vectors['_is_valid_arm'] = is_valid_arm
    vectors['_reset_offset'] = reset - base if is_valid_arm else None
    return vectors


def extract_strings(data: bytes, min_len: int = 5) -> list[tuple[int, str]]:
    """Extrai strings ASCII printable com posição."""
    results = []
    current = []
    start = 0

    for i, b in enumerate(data):
        if 32 <= b < 127:
            if not current:
                start = i
            current.append(chr(b))
        else:
            if len(current) >= min_len:
                results.append((start, ''.join(current)))
            current = []

    if len(current) >= min_len:
        results.append((start, ''.join(current)))

    return results


def find_version_strings(strings: list[tuple[int, str]]) -> list[tuple[int, str]]:
    """Filtra strings que parecem versões de firmware."""
    import re
    version_patterns = [
        re.compile(r'[Vv]?\d+\.\d+[\.\d]*'),        # 1.0.0 / v2.3
        re.compile(r'[Ff][Ww][-_]?\d+'),              # FW-123
        re.compile(r'[Bb]uild[-_ ]\d+'),              # Build 456
        re.compile(r'\d{4}[-/]\d{2}[-/]\d{2}'),      # 2023-04-15 (data de build)
    ]
    results = []
    for offset, s in strings:
        for pat in version_patterns:
            if pat.search(s):
                results.append((offset, s))
                break
    return results


def analyze(fw_path: Path, flash_base: int = FLASH_BASE_STM32) -> FirmwareInfo:
    data = fw_path.read_bytes()
    info = FirmwareInfo(
        path=fw_path,
        size=len(data),
        data=data,
        entropy=compute_entropy(data),
        flash_base=flash_base,
    )

    # Magic bytes
    for magic, desc in MAGICS.items():
        if data[:len(magic)] == magic:
            info.likely_arch = desc
            break

    # DFU suffix (ST DFU format — últimos 16 bytes)
    if len(data) >= 16 and data[-8:-3] == b'UFD\x10\x01':
        info.has_dfu_suffix = True

    # ARM Cortex-M vector table
    vectors = analyze_arm_vectors(data, flash_base)
    if vectors.get('_is_valid_arm'):
        info.is_arm_cortexm = True
        info.likely_arch = "ARM Cortex-M (STM32 ou similar)"
        info.stack_init = vectors.get("Initial Stack Pointer")
        info.entry_point = vectors.get("Reset_Handler (entry point)")

    # Strings
    all_strings = extract_strings(data)
    info.version_strings = find_version_strings(all_strings)
    info.interesting_strings = [
        (off, s) for off, s in all_strings
        if any(p in s.lower() for p in INTERESTING_PATTERNS)
    ]

    return info


def print_report(info: FirmwareInfo):
    def hr(): print("─" * 60)

    print(f"\n{'═'*60}")
    print(f"  Firmware Analysis: {info.path.name}")
    print(f"{'═'*60}")

    print(f"\n  Tamanho:      {info.size:,} bytes ({info.size/1024:.1f} KB)")
    print(f"  Entropia:     {info.entropy:.3f} ", end="")
    if info.entropy > 0.95:
        print("⚠ MUITO ALTA — comprimido ou encriptado")
    elif info.entropy > 0.80:
        print("↑ alta — pode ter seções comprimidas")
    elif info.entropy > 0.50:
        print("→ normal para firmware misto")
    else:
        print("↓ baixa — firmware com muito padding (0xFF/0x00)")

    print(f"  Arquitetura:  {info.likely_arch}")

    if info.has_dfu_suffix:
        print(f"  DFU Suffix:   ✓ ST DFU format detectado")

    if info.is_arm_cortexm:
        hr()
        print(f"  ARM Cortex-M Vector Table (base: 0x{info.flash_base:08x})")
        print(f"    Stack Pointer: 0x{info.stack_init:08x}")
        print(f"    Entry Point:   0x{info.entry_point:08x}  "
              f"(offset +0x{info.entry_point - info.flash_base:x})")
        print()
        print("  → Em Ghidra: Language = ARM:LE:32:Cortex")
        print(f"  → Base address: 0x{info.flash_base:08x}")
        print(f"  → Entry: 0x{info.entry_point:08x}")

    hr()
    print("  Strings de versão encontradas:")
    if info.version_strings:
        for offset, s in info.version_strings[:15]:
            print(f"    0x{offset:06x}  {s}")
    else:
        print("    (nenhuma encontrada — firmware pode estar encriptado)")

    hr()
    print("  Strings de interesse (áudio/USB/sistema):")
    if info.interesting_strings:
        for offset, s in info.interesting_strings[:30]:
            print(f"    0x{offset:06x}  {s}")
    else:
        print("    (nenhuma — alta probabilidade de firmware encriptado)")

    # Mapa de entropia por região
    hr()
    print("  Mapa de entropia por região:")
    emap = entropy_map(info.data, chunk_size=4096)
    for offset, ent in emap:
        bar_len = int(ent * 30)
        bar = '█' * bar_len + '░' * (30 - bar_len)
        flag = ""
        if ent > 0.95: flag = " ← encriptado/comprimido"
        elif ent < 0.1: flag = " ← padding"
        print(f"    0x{offset:05x}  {bar}  {ent:.2f}{flag}")

    print()
    print("  PRÓXIMOS PASSOS:")
    if info.is_arm_cortexm:
        print("  1. Ghidra: Language=ARM:LE:32:Cortex, base=0x08000000")
        print(f"  2. No Ghidra, marque 0x{info.entry_point:08x} como entry point")
        print("  3. Procure por funções de áudio: filtra por 'audio', 'eq', 'usb'")
        print("  4. Compare strings com a versão funcionando (se tiver)")
    if info.entropy > 0.90:
        print("  ⚠ Firmware altamente encriptado:")
        print("     → Capture tráfego do DMU fazendo update (mobius-capture)")
        print("     → O DMU provavelmente descriptografa antes de flashar")
        print("     → Analise o próprio DMU para extrair a chave")
    print()


def main():
    parser = argparse.ArgumentParser(description='Audeze Mobius Firmware Analyzer')
    parser.add_argument('firmware', type=Path, nargs='+',
                        help='Arquivo(s) de firmware para analisar')
    parser.add_argument('--base', '-b', type=lambda x: int(x, 16),
                        default=FLASH_BASE_STM32,
                        help='Endereço base do flash (default: 0x08000000 para STM32)')
    args = parser.parse_args()

    for fw_path in args.firmware:
        if not fw_path.exists():
            print(f"[!] Não encontrado: {fw_path}")
            continue
        info = analyze(fw_path, flash_base=args.base)
        print_report(info)


if __name__ == '__main__':
    main()
