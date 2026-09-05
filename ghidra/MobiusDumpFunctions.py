# Ghidra post-script — exports decompiled functions + strings + xrefs.
# Run via analyzeHeadless with -postScript MobiusDumpFunctions.py
#
# Outputs:
#   /tmp/mobius-ghidra-out/functions.txt   — all decompiled functions
#   /tmp/mobius-ghidra-out/strings.txt     — defined strings + xrefs
#   /tmp/mobius-ghidra-out/summary.txt     — analysis summary

import os
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

OUT_DIR = "/tmp/mobius-ghidra-out"
try:
    os.makedirs(OUT_DIR)
except OSError:
    pass

prog = currentProgram
listing = prog.getListing()
fm = prog.getFunctionManager()
mem = prog.getMemory()
refs = prog.getReferenceManager()

# Summary
with open(os.path.join(OUT_DIR, "summary.txt"), "w") as f:
    f.write("Program: %s\n" % prog.getName())
    f.write("Language: %s\n" % prog.getLanguageID())
    f.write("Compiler: %s\n" % prog.getCompilerSpec().getCompilerSpecID())
    f.write("Image base: 0x%08x\n" % prog.getImageBase().getOffset())
    f.write("Memory blocks:\n")
    for b in mem.getBlocks():
        f.write("  %s: 0x%08x - 0x%08x  (%d bytes) r=%s w=%s x=%s\n" % (
            b.getName(), b.getStart().getOffset(), b.getEnd().getOffset(),
            b.getSize(), b.isRead(), b.isWrite(), b.isExecute()))
    f.write("\nFunction count: %d\n" % fm.getFunctionCount())

# Strings
with open(os.path.join(OUT_DIR, "strings.txt"), "w") as f:
    di = listing.getDefinedData(True)
    for d in di:
        try:
            dt = d.getDataType().getName()
            if "string" in dt.lower() or "char" in dt.lower():
                addr = d.getAddress()
                val = d.getValue()
                if val is None:
                    continue
                s = str(val).replace("\n", "\\n")
                if len(s) < 4:
                    continue
                # xrefs
                xrefs = []
                for r in refs.getReferencesTo(addr):
                    xrefs.append("0x%08x" % r.getFromAddress().getOffset())
                f.write("0x%08x  %-60s  xrefs=[%s]\n" % (
                    addr.getOffset(), s[:60], ",".join(xrefs[:8])))
        except Exception:
            continue

# Decompiled functions
decomp = DecompInterface()
decomp.openProgram(prog)
monitor = ConsoleTaskMonitor()

with open(os.path.join(OUT_DIR, "functions.txt"), "w") as f:
    funcs = list(fm.getFunctions(True))
    f.write("# %d functions\n\n" % len(funcs))
    for fn in funcs:
        try:
            res = decomp.decompileFunction(fn, 30, monitor)
            if res is None or not res.decompileCompleted():
                f.write("// FAIL: %s @ 0x%08x\n\n" % (fn.getName(),
                    fn.getEntryPoint().getOffset()))
                continue
            f.write("// %s @ 0x%08x\n" % (fn.getName(),
                fn.getEntryPoint().getOffset()))
            f.write(res.getDecompiledFunction().getC())
            f.write("\n")
        except Exception as e:
            f.write("// EXC %s: %s\n\n" % (fn.getName(), e))

print("[OK] Wrote %s/{summary,strings,functions}.txt" % OUT_DIR)
