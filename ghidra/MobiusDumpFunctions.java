// Ghidra Java script — exports decompiled functions, strings, summary.
// Run via analyzeHeadless ... -postScript MobiusDumpFunctions.java
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.ConsoleTaskMonitor;

import java.io.File;
import java.io.PrintWriter;
import java.util.Iterator;

public class MobiusDumpFunctions extends GhidraScript {
    private static final String OUT_DIR = "/tmp/mobius-ghidra-out";

    @Override
    public void run() throws Exception {
        new File(OUT_DIR).mkdirs();
        Program prog = currentProgram;
        Listing listing = prog.getListing();
        Memory mem = prog.getMemory();
        ReferenceManager refs = prog.getReferenceManager();

        // ── summary.txt ────────────────────────────────────────────────
        try (PrintWriter w = new PrintWriter(OUT_DIR + "/summary.txt")) {
            w.printf("Program: %s%n", prog.getName());
            w.printf("Language: %s%n", prog.getLanguageID());
            w.printf("Compiler: %s%n", prog.getCompilerSpec().getCompilerSpecID());
            w.printf("Image base: 0x%08x%n", prog.getImageBase().getOffset());
            w.println("Memory blocks:");
            for (MemoryBlock b : mem.getBlocks()) {
                w.printf("  %s: 0x%08x - 0x%08x  (%d bytes) r=%s w=%s x=%s%n",
                    b.getName(), b.getStart().getOffset(), b.getEnd().getOffset(),
                    b.getSize(), b.isRead(), b.isWrite(), b.isExecute());
            }
            w.printf("%nFunction count: %d%n",
                prog.getFunctionManager().getFunctionCount());
        }

        // ── strings.txt ────────────────────────────────────────────────
        try (PrintWriter w = new PrintWriter(OUT_DIR + "/strings.txt")) {
            Iterator<Data> di = listing.getDefinedData(true).iterator();
            while (di.hasNext()) {
                Data d = di.next();
                String dt = d.getDataType().getName().toLowerCase();
                if (!(dt.contains("string") || dt.contains("char"))) continue;
                Object val = d.getValue();
                if (val == null) continue;
                String s = val.toString().replace("\n", "\\n").replace("\r", "\\r");
                if (s.length() < 4) continue;
                StringBuilder xr = new StringBuilder();
                int cnt = 0;
                for (Reference r : refs.getReferencesTo(d.getAddress())) {
                    if (cnt++ > 0) xr.append(",");
                    xr.append(String.format("0x%08x", r.getFromAddress().getOffset()));
                    if (cnt >= 8) break;
                }
                w.printf("0x%08x  %-60s  xrefs=[%s]%n",
                    d.getAddress().getOffset(),
                    s.length() > 60 ? s.substring(0, 60) : s,
                    xr.toString());
            }
        }

        // ── functions.txt (decompiled C) ───────────────────────────────
        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(prog);
        ConsoleTaskMonitor monitor = new ConsoleTaskMonitor();

        try (PrintWriter w = new PrintWriter(OUT_DIR + "/functions.txt")) {
            int total = prog.getFunctionManager().getFunctionCount();
            w.printf("# %d functions%n%n", total);
            int ok = 0, fail = 0;
            FunctionIterator fi = prog.getFunctionManager().getFunctions(true);
            while (fi.hasNext()) {
                Function fn = fi.next();
                try {
                    DecompileResults res = decomp.decompileFunction(fn, 30, monitor);
                    if (res == null || !res.decompileCompleted()) {
                        w.printf("// FAIL: %s @ 0x%08x%n%n",
                            fn.getName(), fn.getEntryPoint().getOffset());
                        fail++;
                        continue;
                    }
                    w.printf("// %s @ 0x%08x%n",
                        fn.getName(), fn.getEntryPoint().getOffset());
                    w.println(res.getDecompiledFunction().getC());
                    w.println();
                    ok++;
                } catch (Exception e) {
                    w.printf("// EXC %s: %s%n%n", fn.getName(), e.getMessage());
                    fail++;
                }
            }
            println(String.format("Decompiled %d/%d (failed %d)", ok, total, fail));
        }

        println("[OK] Wrote " + OUT_DIR + "/{summary,strings,functions}.txt");
    }
}
