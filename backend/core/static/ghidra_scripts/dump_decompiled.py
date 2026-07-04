# Garudatva v3 — Ghidra headless post-script
# Runs under Ghidra's bundled Jython interpreter (invoked via
# analyzeHeadless ... -postScript dump_decompiled.py <out_path>).
# Decompiles every function in the just-analyzed program to C-like
# pseudocode and writes it all to <out_path>, so a normal Python
# process (ghidra_analyzer.py) can SAST-scan the plain text afterward
# without needing the Ghidra API itself at scan time.

from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
out_path = args[0] if args else (currentProgram.getName() + ".decompiled.c")

decompiler = DecompInterface()
decompiler.openProgram(currentProgram)
monitor = ConsoleTaskMonitor()

out_file = open(out_path, "w")
try:
    fm = currentProgram.getFunctionManager()
    for func in fm.getFunctions(True):
        try:
            result = decompiler.decompileFunction(func, 60, monitor)
            if result and result.decompileCompleted():
                out_file.write("// -- %s --\n" % func.getName())
                out_file.write(result.getDecompiledFunction().getC())
                out_file.write("\n\n")
        except Exception, e:
            out_file.write("// decompile failed for %s: %s\n" % (func.getName(), e))
finally:
    out_file.close()
    decompiler.dispose()
