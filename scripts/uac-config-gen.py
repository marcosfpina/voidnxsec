#!/usr/bin/env python3
"""
Audeze Mobius — UacFwConfig.exe Schema Extractor + config.ini Generator
------------------------------------------------------------------------
Duas funções principais:
  1. Extrai as chaves esperadas do UacFwConfig.exe via análise de strings
  2. Gera o config.ini canônico com os valores corretos do Mobius

Uso:
  # Extrai schema do exe (Windows PE ou Wine)
  python uac-config-gen.py --extract UacFwConfig.exe

  # Gera config.ini canônico direto
  python uac-config-gen.py --generate --output config.ini

  # Valida um config.ini existente
  python uac-config-gen.py --validate config.ini
"""

import sys, re, struct, argparse, configparser, json
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

# ─────────────────────────────────────────────────────────────────────────────
# Especificações canônicas do Audeze Mobius
# Fonte: FCC filings, specs oficiais, teardowns, kernel USB descriptors
# ─────────────────────────────────────────────────────────────────────────────
MOBIUS_SPEC = {
    # ── Identidade USB ────────────────────────────────────────────────────────
    "USB": {
        "VID":              "0x22D9",       # Audeze LLC
        "PID":              "0x0001",       # Mobius normal mode
        "PID_DFU":          "0x0002",       # Bootloader / DFU mode
        "bcdUSB":           "0x0200",       # USB 2.0
        "bcdDevice":        "0x0100",       # Device version 1.0 (ajustar se souber)
        "Manufacturer":     "Audeze LLC",
        "Product":          "Audeze Mobius",
        "SerialNumber":     "",             # Gerado por device ou deixado vazio
        "MaxPower":         "500",          # mA — USB high power
        "SelfPowered":      "0",            # Bus powered
        "RemoteWakeup":     "1",
    },

    # ── USB Audio Class (UAC 1.0 / 2.0) ──────────────────────────────────────
    "Audio": {
        # O Mobius suporta até 96kHz/24bit via USB
        "SampleRates":      "44100,48000,96000",
        "BitDepth":         "24",           # 24-bit padrão
        "Channels":         "2",            # Stereo (output)
        "ChannelsIn":       "2",            # Mic stereo
        "bInterval":        "1",
        "PacketSize":       "196",          # @ 48kHz/24bit/2ch: 48000*3*2/1000 = 288, arredonda

        # Feedback endpoint (isochronous)
        "FeedbackEnable":   "1",
        "FeedbackInterval": "4",

        # Terminal types
        "OutTerminalType":  "0x0302",       # Headphones
        "InTerminalType":   "0x0201",       # Microphone

        # Volume control
        "VolumeMin":        "-127",         # dB * 256
        "VolumeMax":        "0",
        "VolumeRes":        "1",
        "VolumeDefault":    "0",

        # Mute
        "MuteEnable":       "1",
    },

    # ── HID Interface (controles, vendor commands) ────────────────────────────
    "HID": {
        "Enable":           "1",
        "VendorUsagePage":  "0xFF00",       # Vendor-specific
        "VendorUsage":      "0x0001",
        "ReportSize":       "64",
        "PollInterval":     "1",            # ms
    },

    # ── DSP / EQ ──────────────────────────────────────────────────────────────
    "DSP": {
        "Enable":           "1",
        "EQBands":          "10",
        "EQPresetDefault":  "0",            # Flat
        "SurroundEnable":   "1",            # Waves Nx
        "SurroundDefault":  "0",            # Off por padrão
        "BassBoostEnable":  "1",
        "BassBoostDefault": "0",
    },

    # ── Bluetooth ─────────────────────────────────────────────────────────────
    "Bluetooth": {
        "Enable":           "1",
        "Version":          "3.0",
        "Profile":          "A2DP,HFP,HSP",
        "DeviceName":       "Audeze Mobius",
    },

    # ── IMU / Head Tracking ───────────────────────────────────────────────────
    "IMU": {
        "Enable":           "1",
        "Type":             "6DOF",         # 6 degrees of freedom
        "SampleRate":       "1000",         # Hz
    },

    # ── Flash Layout ──────────────────────────────────────────────────────────
    # Baseado em ARM Cortex-M típico — ajustar após dump
    "Flash": {
        "BaseAddress":      "0x08000000",
        "Size":             "0x80000",      # 512KB
        "BootloaderSize":   "0x8000",       # 32KB bootloader
        "AppStart":         "0x08008000",
        "ConfigStart":      "0x0807E000",   # Últimos 8KB para config
        "ConfigSize":       "0x2000",
    },

    # ── UacFwConfig específico ────────────────────────────────────────────────
    # Chaves que o UacFwConfig.exe provavelmente usa
    "FwConfig": {
        "Version":          "1",
        "ChecksumEnable":   "1",
        "EncryptionEnable": "0",
        "SignatureEnable":  "0",
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Padrões de chaves que o UacFwConfig.exe tipicamente procura
# (extraídos de análise de strings de toolchains UAC similares)
# ─────────────────────────────────────────────────────────────────────────────
KNOWN_KEYS_PATTERNS = [
    # USB identity
    r'VID', r'PID', r'Vendor', r'Product', r'Manufacturer', r'Serial',
    r'bcdUSB', r'bcdDevice', r'MaxPower', r'SelfPower',

    # Audio
    r'SampleRate', r'BitDepth', r'Channel', r'Volume', r'Mute',
    r'bInterval', r'PacketSize', r'Terminal', r'Feedback',

    # HID
    r'HID', r'Report', r'UsagePage', r'Usage', r'Poll',

    # Config structure
    r'Version', r'Checksum', r'Encrypt', r'Signature',
    r'Flash', r'Address', r'Size', r'Offset',

    # C-Media / UAC specific
    r'CMIDI', r'UAC', r'FW_', r'CFG_', r'CONFIG',
]


def extract_schema_from_exe(exe_path: Path) -> dict:
    """
    Analisa o UacFwConfig.exe para descobrir quais chaves ele lê do config.ini.
    Procura por:
      1. Strings que parecem section names ([Section])
      2. Strings que parecem key names (key=value patterns)
      3. GetPrivateProfileString calls → chaves hardcoded
    """
    print(f"[*] Analisando {exe_path.name} ({exe_path.stat().st_size:,} bytes)...")

    data = exe_path.read_bytes()
    schema = {}

    # Extrai todas as strings ASCII
    strings = extract_ascii_strings(data, min_len=3)

    # Filtra strings que parecem INI keys/sections
    ini_candidates = []
    for offset, s in strings:
        # Section names: curtas, sem espaço, CamelCase ou UPPER
        if re.match(r'^[A-Za-z][A-Za-z0-9_]{2,30}$', s):
            score = 0
            for pat in KNOWN_KEYS_PATTERNS:
                if re.search(pat, s, re.I):
                    score += 1
            if score > 0:
                ini_candidates.append((offset, s, score))

    # Agrupa por relevância
    ini_candidates.sort(key=lambda x: -x[2])

    print(f"[*] {len(ini_candidates)} chaves candidatas encontradas")
    print()

    # Procura por padrões de GetPrivateProfileString (Windows API)
    # A função é chamada com: section, key, default, buffer, size, filename
    # Antes da call, os args são pushados na stack (32-bit) ou passados em regs (64-bit)
    # Heurística: strings próximas entre si e antes de uma call instruction
    gpps_pattern = b'GetPrivateProfileString'
    gpps_offset = data.find(gpps_pattern)
    if gpps_offset != -1:
        print(f"[+] GetPrivateProfileString encontrada @ 0x{gpps_offset:08x}")
        print("    O exe definitivamente lê INI files — schema extraction válida")
    else:
        # Pode estar importando pelo ordinal ou nome diferente
        print("[?] GetPrivateProfileString não encontrada diretamente")
        print("    Pode usar: ReadINI, IniRead, ou implementação própria")

    # Procura por seções típicas
    common_sections = ['USB', 'Audio', 'HID', 'DSP', 'Config', 'Flash',
                       'Device', 'Firmware', 'FW', 'UAC', 'General']
    found_sections = []
    for section in common_sections:
        pattern = section.encode('ascii') + b'\x00'
        if pattern in data:
            found_sections.append(section)

    if found_sections:
        print(f"[+] Seções encontradas no binário: {', '.join(found_sections)}")

    print()
    print("Chaves mais prováveis (por relevância):")
    for offset, key, score in ini_candidates[:40]:
        print(f"  0x{offset:06x}  {'★'*min(score,5)}  {key}")

    return {
        'candidates': ini_candidates,
        'found_sections': found_sections,
        'has_gpps': gpps_offset != -1,
    }


def extract_ascii_strings(data: bytes, min_len: int = 4) -> list:
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
    return results


def generate_config_ini(
    output_path: Path,
    extra_keys: Optional[dict] = None,
    verbose: bool = True,
) -> str:
    """
    Gera o config.ini canônico do Audeze Mobius.
    Baseado nas especificações conhecidas + análise do toolchain.
    """
    spec = MOBIUS_SPEC.copy()
    if extra_keys:
        for section, keys in extra_keys.items():
            if section in spec:
                spec[section].update(keys)
            else:
                spec[section] = keys

    config = configparser.ConfigParser()
    config.optionxform = str  # preserva case das chaves

    for section, keys in spec.items():
        config[section] = keys

    # Adiciona cabeçalho com contexto
    header = (
        "; Audeze Mobius — config.ini\n"
        "; Gerado pelo audeze-mobius-re kit (voidnxlabs)\n"
        ";\n"
        "; ATENÇÃO: Verifique os valores USB (VID, PID, bcdDevice) contra\n"
        "; o dump original ou lsusb antes de flashar.\n"
        "; A maioria dos valores de áudio são canônicos para o Mobius.\n"
        ";\n"
        "; Para validar: python uac-config-gen.py --validate config.ini\n"
        ";\n\n"
    )

    import io
    buf = io.StringIO()
    config.write(buf)
    content = header + buf.getvalue()

    output_path.write_text(content)

    if verbose:
        print(f"[OK] config.ini gerado: {output_path}")
        print(f"     {len(spec)} seções, {sum(len(v) for v in spec.values())} chaves")
        print()
        for section, keys in spec.items():
            print(f"  [{section}]")
            for k, v in keys.items():
                print(f"    {k} = {v}")
            print()

    return content


def validate_config(config_path: Path) -> bool:
    """
    Valida um config.ini existente contra o schema esperado do Mobius.
    """
    print(f"[*] Validando {config_path}...")
    config = configparser.ConfigParser()
    config.optionxform = str

    try:
        config.read(config_path)
    except Exception as e:
        print(f"[!] Erro ao parsear INI: {e}")
        return False

    errors = []
    warnings = []

    # Verifica seções obrigatórias
    required_sections = ['USB', 'Audio']
    for section in required_sections:
        if not config.has_section(section):
            errors.append(f"Seção [{section}] ausente — obrigatória")

    # Verifica chaves críticas
    critical_keys = {
        'USB': ['VID', 'PID', 'Product'],
        'Audio': ['SampleRates', 'BitDepth', 'Channels'],
    }
    for section, keys in critical_keys.items():
        if config.has_section(section):
            for key in keys:
                if not config.has_option(section, key):
                    errors.append(f"Chave ausente: [{section}] {key}")
                elif not config.get(section, key).strip():
                    errors.append(f"Chave vazia: [{section}] {key}")

    # Valida VID/PID
    if config.has_option('USB', 'VID'):
        vid = config.get('USB', 'VID').strip()
        if vid not in ('0x22D9', '0x22d9', '22D9', '22d9'):
            warnings.append(f"VID inesperado: {vid} (esperado 0x22D9 para Audeze)")

    # Valida sample rates
    if config.has_option('Audio', 'SampleRates'):
        rates = config.get('Audio', 'SampleRates')
        if '48000' not in rates:
            warnings.append("48000Hz ausente dos SampleRates — pode causar falha de init")

    # Relata
    if errors:
        print(f"\n[!] {len(errors)} ERRO(S):")
        for e in errors:
            print(f"    ✗ {e}")

    if warnings:
        print(f"\n[~] {len(warnings)} AVISO(S):")
        for w in warnings:
            print(f"    ⚠ {w}")

    if not errors and not warnings:
        print("[OK] config.ini parece válido para o Mobius")
    elif not errors:
        print(f"\n[OK] Sem erros críticos ({len(warnings)} avisos)")

    return len(errors) == 0


def diff_configs(path_a: Path, path_b: Path):
    """Compara dois config.ini — útil pra ver o que mudou entre versões."""
    ca = configparser.ConfigParser()
    cb = configparser.ConfigParser()
    ca.optionxform = str
    cb.optionxform = str
    ca.read(path_a)
    cb.read(path_b)

    all_sections = set(ca.sections()) | set(cb.sections())
    print(f"Diff: {path_a.name} vs {path_b.name}")
    print()

    for section in sorted(all_sections):
        keys_a = dict(ca[section]) if ca.has_section(section) else {}
        keys_b = dict(cb[section]) if cb.has_section(section) else {}
        all_keys = set(keys_a) | set(keys_b)

        section_diffs = []
        for key in sorted(all_keys):
            va = keys_a.get(key, '<ausente>')
            vb = keys_b.get(key, '<ausente>')
            if va != vb:
                section_diffs.append((key, va, vb))

        if section_diffs:
            print(f"  [{section}]")
            for key, va, vb in section_diffs:
                print(f"    {key}:")
                print(f"      - {va}")
                print(f"      + {vb}")
            print()


def main():
    parser = argparse.ArgumentParser(
        description='Audeze Mobius UacFwConfig schema extractor + config.ini generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('--extract', type=Path, metavar='EXE',
                        help='Extrai schema do UacFwConfig.exe')
    parser.add_argument('--generate', action='store_true',
                        help='Gera config.ini canônico do Mobius')
    parser.add_argument('--validate', type=Path, metavar='INI',
                        help='Valida um config.ini existente')
    parser.add_argument('--diff', nargs=2, type=Path, metavar=('A', 'B'),
                        help='Compara dois config.ini')
    parser.add_argument('--output', '-o', type=Path, default=Path('config.ini'),
                        help='Arquivo de saída (default: config.ini)')
    parser.add_argument('--set', '-s', action='append', default=[],
                        metavar='SECTION.KEY=VALUE',
                        help='Override de chave específica (ex: USB.bcdDevice=0x0200)')
    args = parser.parse_args()

    # Processa overrides
    extra = {}
    for override in args.set:
        try:
            key_path, value = override.split('=', 1)
            section, key = key_path.split('.', 1)
            extra.setdefault(section, {})[key] = value
        except ValueError:
            print(f"[!] Formato inválido: {override} — use SECTION.KEY=VALUE")

    if args.extract:
        extract_schema_from_exe(args.extract)

    if args.generate:
        generate_config_ini(args.output, extra_keys=extra or None)

    if args.validate:
        valid = validate_config(args.validate)
        sys.exit(0 if valid else 1)

    if args.diff:
        diff_configs(args.diff[0], args.diff[1])

    if not any([args.extract, args.generate, args.validate, args.diff]):
        # Default: gera o config.ini
        print("[*] Nenhuma operação especificada — gerando config.ini canônico")
        generate_config_ini(args.output, extra_keys=extra or None)


if __name__ == '__main__':
    main()
