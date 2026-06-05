# @author  pcode-dumper
# @category Analysis
# @keybinding
# @menupath
# @toolbar
# @runtime Jython

import os
import sys
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.task import ConsoleTaskMonitor

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------
FUNC_ADDR = 0x18190c2a0

try:
    _script_dir = os.path.dirname(os.path.abspath(str(getSourceFile())))
except Exception:
    _script_dir = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.normpath(os.path.join(_script_dir, "..", "output"))

# ---------------------------------------------------------------------------

_out_file = None

def log(msg):
    sys.stdout.write(str(msg) + "\n")
    if _out_file is not None:
        _out_file.write((str(msg) + "\n").encode("utf-8"))

def make_addr(offset):
    return currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(offset)

def op_name(op):
    return PcodeOp.getMnemonic(op.getOpcode())

def vn_str(vn):
    if vn is None:
        return "null"
    if vn.isConstant():
        return "const:0x%x" % vn.getOffset()
    if vn.isRegister():
        reg = currentProgram.getLanguage().getRegister(vn.getAddress(), vn.getSize())
        return reg.getName() if reg else "reg@%s" % vn.getAddress()
    if vn.isUnique():
        return "tmp:0x%x" % vn.getOffset()
    if vn.getAddress().isStackAddress():
        off = vn.getOffset()
        if off > 0x7FFFFFFFFFFFFFFF:
            off -= 0x10000000000000000
        return "stack:0x%x" % off
    return "mem@%s" % vn.getAddress()

def run():
    target = make_addr(FUNC_ADDR)
    func = currentProgram.getFunctionManager().getFunctionContaining(target)
    if func is None:
        log("[ERROR] no function at 0x%x" % FUNC_ADDR)
        return

    log("[INFO] function: %s  entry=0x%x" % (
        func.getName(),
        func.getEntryPoint().getOffset()
    ))

    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.openProgram(currentProgram)
    try:
        mon = monitor
    except NameError:
        mon = ConsoleTaskMonitor()

    res = ifc.decompileFunction(func, 60, mon)
    if not res.decompileCompleted():
        log("[ERROR] decompile failed: %s" % res.getErrorMessage())
        return

    high = res.getHighFunction()

    #  High PCode op   
    log("")
    log("=== All High PCode ops in function ===")
    all_ops = list(high.getPcodeOps())
    log("total ops: %d" % len(all_ops))
    log("")

    prev_addr = None
    for op in all_ops:
        try:
            addr_val = op.getSeqnum().getTarget().getOffset()
            addr_str = "0x%x" % addr_val
        except Exception:
            addr_str = "unknown"

        if addr_str != prev_addr:
            log("--- %s ---" % addr_str)
            prev_addr = addr_str

        out = op.getOutput()
        ins = [vn_str(i) for i in op.getInputs()]
        log("  %-12s  out=%-20s  in=%s" % (op_name(op), vn_str(out), ins))

if not os.path.exists(OUTPUT_DIR):
    os.makedirs(OUTPUT_DIR)

out_path = os.path.join(OUTPUT_DIR, "pcode_dump_0x%x.txt" % FUNC_ADDR)
_out_file = open(out_path, "wb")
try:
    run()
finally:
    _out_file.close()

sys.stdout.write("[OUT] pcode dump -> %s\n" % out_path)
