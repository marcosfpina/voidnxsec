# MobiusAutoAnalysis.py — Ghidra script para firmware Audeze Mobius
# Roda via: analyzeHeadless ... -postScript MobiusAutoAnalysis.py

import re
from ghidra.util.task import TaskMonitor
from java.awt import Color

KNOWN_STRINGS = {
    'Audeze Mobius': 'DEVICE_NAME',
    'Waves Nx':      'DSP_VENDOR',
    'Bootloader':    'BOOT_SECTION',
    'USB Audio':     'USB_CLASS',
    'Firmware':      'FW_MARKER',
}

VECTOR_LABELS = [
    (0x00, "_initial_sp",           "Initial Stack Pointer"),
    (0x04, "Reset_Handler",         "Entry point — RE começa aqui"),
    (0x08, "NMI_Handler",           "Non-Maskable Interrupt"),
    (0x0C, "HardFault_Handler",     "Hard Fault — aqui caem os crashes"),
    (0x10, "MemManage_Handler",     "Memory Fault"),
    (0x14, "BusFault_Handler",      "Bus Fault"),
    (0x38, "SysTick_Handler",       "System Tick — timing/scheduler"),
]

def run():
    print("=" * 55)
    print("  Audeze Mobius Ghidra Auto-Analysis")
    print("=" * 55)

    base = currentProgram.getImageBase()

    # 1. Vector table
    print("\n[*] ARM Cortex-M vector table...")
    for offset, name, comment in VECTOR_LABELS:
        addr = base.add(offset)
        try:
            createLabel(addr, name, True)
            setPlateComment(addr, comment)
            createBookmark(addr, "VECTOR_TABLE", name)
            print(f"    {name} @ {addr}")
        except Exception as e:
            print(f"    WARN {name}: {e}")

    # Entry point real (dereference Reset_Handler vector)
    try:
        reset_vec = base.add(0x04)
        entry_raw = getInt(reset_vec) & 0xFFFFFFFE  # clear Thumb bit
        entry = toAddr(entry_raw)
        createLabel(entry, "FIRMWARE_ENTRY", True)
        setBackgroundColor(entry, Color(50, 200, 80, 100))
        createBookmark(entry, "ENTRY_POINT", "Reset_Handler real — começa aqui")
        print(f"    [★] Entry real: {entry}")
    except Exception as e:
        print(f"    WARN entry point: {e}")

    # 2. Strings conhecidas
    print("\n[*] Strings conhecidas...")
    for s, label in KNOWN_STRINGS.items():
        found = findBytes(None, s.encode('ascii'), 20)
        if found:
            createBookmark(found, "KNOWN_STRING", f"{label}: {s}")
            print(f"    '{s}' @ {found}")

    # 3. Versão via regex nas defined data
    print("\n[*] Strings de versão...")
    ver_pat = re.compile(r'[Vv]?\d+\.\d+[\.\d]*')
    from ghidra.program.model.data import StringDataType
    data_iter = currentProgram.getListing().getDefinedData(True)
    while data_iter.hasNext():
        d = data_iter.next()
        if isinstance(d.getDataType(), StringDataType):
            s = str(d.getValue())
            if ver_pat.search(s) and len(s) < 60:
                createBookmark(d.getAddress(), "VERSION_STRING", s)
                print(f"    @ {d.getAddress()}: {s}")

    # 4. Refs a periférico USB STM32
    print("\n[*] Refs USB peripheral...")
    for usb_base in [0x40040000, 0x40005C00]:
        refs = list(getReferencesTo(toAddr(usb_base)))
        for ref in refs[:5]:
            createBookmark(ref.getFromAddress(), "USB_ACCESS",
                          f"USB periph @ 0x{usb_base:08x}")
            print(f"    {ref.getFromAddress()} → USB 0x{usb_base:08x}")

    print("\n[OK] Done. Window > Bookmarks para navegar.")

run()
