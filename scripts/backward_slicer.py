# @author  backward-slicer
# @category Analysis
# @keybinding
# @menupath
# @toolbar
# @runtime Jython

import json
import os
import sys

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.pcode import PcodeOp
from ghidra.util.task import ConsoleTaskMonitor

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

ANCHOR_ADDRESS  = 0x18190c492
ANCHOR_ARG_IDX  = 2

OUTPUT_DIR = os.path.join(os.path.expanduser("~"), "ghidra_slicer_output")

MAX_DEPTH         = 200
MAX_CALL_DEPTH    = 10   # interprocedural recursion limit

# Functions whose parameters are external I/O origins - stop and tag as source
STOP_FUNCTIONS = {
    "recv", "WSARecv", "WSARecvFrom",
    "ReadFile", "ReadFileEx",
    "recvfrom", "recvmsg",
}

# Functions to skip entirely (il2cpp runtime glue, GC internals, etc.)
SKIP_FUNCTIONS = {
    "il2cpp_gc_alloc", "il2cpp_alloc",
    "il2cpp_object_new", "il2cpp_array_new",
    "il2cpp_runtime_invoke",
    "GC_malloc", "GC_malloc_atomic",
    "memcpy", "memmove", "memset",
}

# ---------------------------------------------------------------------------
# GLOBALS
# ---------------------------------------------------------------------------

visited  = set()   # (func_entry_hex, vn_addr_str, vn_offset, vn_size)
chain    = []
sources  = []

_decompile_cache = {}   # func_entry_offset -> HighFunction

# ---------------------------------------------------------------------------
# UTILS
# ---------------------------------------------------------------------------

def log(msg):
    sys.stdout.write(str(msg) + "\n")

def make_addr(offset):
    space = currentProgram.getAddressFactory().getDefaultAddressSpace()
    return space.getAddress(offset)

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
    addr = vn.getAddress()
    if addr.isStackAddress():
        off = vn.getOffset()
        if off > 0x7FFFFFFFFFFFFFFF:
            off = off - 0x10000000000000000
        return "stack:0x%x" % off
    return "mem@%s+0x%x" % (addr.getAddressSpace().getName(), vn.getOffset())

def op_addr_str(op):
    try:
        return "0x%x" % op.getSeqnum().getTarget().getOffset()
    except Exception:
        return "unknown"

def is_stack(vn):
    if vn.isRegister() or vn.isConstant() or vn.isUnique():
        return False
    return vn.getAddress().isStackAddress()

def func_name(func):
    if func is None:
        return "unknown"
    return func.getName()

# ---------------------------------------------------------------------------
# DECOMPILE (cached)
# ---------------------------------------------------------------------------

def get_high_function(func):
    key = func.getEntryPoint().getOffset()
    if key in _decompile_cache:
        return _decompile_cache[key]

    ifc = DecompInterface()
    ifc.setOptions(DecompileOptions())
    ifc.openProgram(currentProgram)
    try:
        mon = monitor
    except NameError:
        mon = ConsoleTaskMonitor()

    res = ifc.decompileFunction(func, 60, mon)
    if not res.decompileCompleted():
        log("[WARN] decompile failed for %s: %s" % (func_name(func), res.getErrorMessage()))
        _decompile_cache[key] = None
        return None

    high = res.getHighFunction()
    _decompile_cache[key] = high
    return high

# ---------------------------------------------------------------------------
# INTERPROCEDURAL STEP
#
# Called when backward_slice() hits a varnode with no defining op (SOURCE).
# If the varnode is a function parameter, find all call sites via XREF,
# locate the matching argument varnode at each call, and continue slicing.
# ---------------------------------------------------------------------------

def interprocedural_step(vn, containing_func, param_slot, depth, call_depth):
    if call_depth >= MAX_CALL_DEPTH:
        sources.append({
            "varnode":    vn_str(vn),
            "is_reg":     vn.isRegister(),
            "is_stack":   is_stack(vn),
            "depth":      depth,
            "note":       "interprocedural depth limit reached",
        })
        return

    callee_name = func_name(containing_func)
    callee_entry = containing_func.getEntryPoint()

    log("[INTERPROC] tracing param slot %d of %s (depth=%d, call_depth=%d)"
        % (param_slot, callee_name, depth, call_depth))

    ref_mgr = currentProgram.getReferenceManager()
    xrefs   = list(ref_mgr.getReferencesTo(callee_entry))
    call_refs = [r for r in xrefs if r.getReferenceType().isCall()]

    if not call_refs:
        log("[INTERPROC] no callers found for %s" % callee_name)
        sources.append({
            "varnode":  vn_str(vn),
            "is_reg":   vn.isRegister(),
            "is_stack": is_stack(vn),
            "depth":    depth,
            "note":     "no callers - root source in %s param[%d]" % (callee_name, param_slot),
        })
        return

    # param_slot is 0-based among formal parameters;
    # CALL op inputs: in[0]=fn_ptr, in[1]=arg0, in[2]=arg1, ...
    call_arg_idx = param_slot + 1

    for ref in call_refs:
        call_site = ref.getFromAddress()
        caller_func = currentProgram.getFunctionManager().getFunctionContaining(call_site)
        if caller_func is None:
            log("[INTERPROC] no function contains call site 0x%x" % call_site.getOffset())
            continue

        caller_name = func_name(caller_func)

        if caller_name in SKIP_FUNCTIONS:
            log("[INTERPROC] skipping %s (SKIP_FUNCTIONS)" % caller_name)
            continue

        high = get_high_function(caller_func)
        if high is None:
            continue

        ops_at_site = list(high.getPcodeOps(call_site))
        call_op = None
        for op in ops_at_site:
            if op.getOpcode() == PcodeOp.CALL or op.getOpcode() == PcodeOp.CALLIND:
                call_op = op
                break

        if call_op is None:
            log("[INTERPROC] no CALL op at 0x%x in %s" % (call_site.getOffset(), caller_name))
            continue

        inputs = list(call_op.getInputs())
        if call_arg_idx >= len(inputs):
            log("[INTERPROC] call at 0x%x: arg idx %d out of range (max %d)"
                % (call_site.getOffset(), call_arg_idx, len(inputs) - 1))
            continue

        arg_vn = inputs[call_arg_idx]
        log("[INTERPROC] -> caller=%s  call_site=0x%x  arg_vn=%s"
            % (caller_name, call_site.getOffset(), vn_str(arg_vn)))

        chain.append({
            "address": "0x%x" % call_site.getOffset(),
            "op":      "INTERPROC_CALL",
            "output":  vn_str(vn),
            "inputs":  [vn_str(arg_vn)],
            "depth":   depth,
            "note":    "cross-function: %s -> %s param[%d]" % (caller_name, callee_name, param_slot),
        })

        backward_slice_impl(arg_vn, caller_func, depth + 1, call_depth + 1)

# ---------------------------------------------------------------------------
# PARAM SLOT RESOLUTION
#
# Given a varnode that has no def-op in a HighFunction, determine if it is
# a formal parameter and return its 0-based slot index.
# Returns -1 if it cannot be identified as a parameter.
# ---------------------------------------------------------------------------

def resolve_param_slot(vn, high):
    # HighFunction exposes the HighSymbol for each parameter
    local_sym_map = high.getLocalSymbolMap()
    if local_sym_map is None:
        return -1

    num_params = local_sym_map.getNumParams()
    for i in range(num_params):
        param_sym = local_sym_map.getParamSymbol(i)
        if param_sym is None:
            continue
        # Each HighSymbol has one or more varnodes
        for rep in param_sym.getInstances():
            for pv in rep.getVarnodes():
                if (pv.getAddress() == vn.getAddress() and
                        pv.getOffset() == vn.getOffset() and
                        pv.getSize() == vn.getSize()):
                    return i
    return -1

# ---------------------------------------------------------------------------
# CORE - backward slice (interprocedural-aware)
# ---------------------------------------------------------------------------

def backward_slice_impl(vn, containing_func, depth, call_depth):
    if depth > MAX_DEPTH:
        chain.append({
            "address": "N/A",
            "op":      "DEPTH_LIMIT",
            "output":  vn_str(vn),
            "inputs":  [],
            "depth":   depth,
            "note":    "max depth exceeded",
        })
        return

    func_entry_hex = "0x%x" % containing_func.getEntryPoint().getOffset()
    key = (func_entry_hex, str(vn.getAddress()), vn.getOffset(), vn.getSize())
    if key in visited:
        return
    visited.add(key)

    def_op = vn.getDef()

    if def_op is None:
        # Check whether this varnode is a formal parameter
        high = get_high_function(containing_func)
        param_slot = -1
        if high is not None:
            param_slot = resolve_param_slot(vn, high)

        callee_name = func_name(containing_func)

        # Check STOP_FUNCTIONS before going interprocedural
        if callee_name in STOP_FUNCTIONS:
            sources.append({
                "varnode":  vn_str(vn),
                "is_reg":   vn.isRegister(),
                "is_stack": is_stack(vn),
                "depth":    depth,
                "note":     "[EXTERNAL SOURCE] %s param[%d]" % (callee_name, param_slot),
            })
            return

        if param_slot >= 0:
            # Recurse into callers
            interprocedural_step(vn, containing_func, param_slot, depth, call_depth)
        else:
            sources.append({
                "varnode":  vn_str(vn),
                "is_reg":   vn.isRegister(),
                "is_stack": is_stack(vn),
                "depth":    depth,
                "note":     "",
            })
        return

    inp_strs = [vn_str(i) for i in def_op.getInputs()]
    chain.append({
        "address": op_addr_str(def_op),
        "op":      op_name(def_op),
        "output":  vn_str(def_op.getOutput()),
        "inputs":  inp_strs,
        "depth":   depth,
        "note":    "",
    })

    for inp in def_op.getInputs():
        if not inp.isConstant():
            backward_slice_impl(inp, containing_func, depth + 1, call_depth)


def backward_slice(vn, containing_func):
    backward_slice_impl(vn, containing_func, 0, 0)

# ---------------------------------------------------------------------------
# ANCHOR FINDER
# ---------------------------------------------------------------------------

def find_anchor():
    target = make_addr(ANCHOR_ADDRESS)
    func = currentProgram.getFunctionManager().getFunctionContaining(target)
    if func is None:
        log("[ERROR] no function contains 0x%x" % ANCHOR_ADDRESS)
        return None, None

    high = get_high_function(func)
    if high is None:
        return None, None

    ops_at_target = list(high.getPcodeOps(target))
    call_op = None
    for op in ops_at_target:
        if op.getOpcode() == PcodeOp.CALL or op.getOpcode() == PcodeOp.CALLIND:
            call_op = op
            break

    if call_op is None:
        log("[ERROR] no CALL op found at 0x%x" % ANCHOR_ADDRESS)
        log("        ops at this address:")
        for op in ops_at_target:
            log("          %s  out=%s  in=%s" % (
                op_name(op), vn_str(op.getOutput()),
                [vn_str(i) for i in op.getInputs()]))
        log("        Run pcode_dumper.py to find the correct address.")
        return None, None

    inputs = list(call_op.getInputs())
    log("[INFO] CALL op at 0x%x has %d inputs:" % (ANCHOR_ADDRESS, len(inputs)))
    for i, inp in enumerate(inputs):
        marker = " <-- anchor" if i == ANCHOR_ARG_IDX else ""
        log("  in[%d] = %s%s" % (i, vn_str(inp), marker))

    if ANCHOR_ARG_IDX >= len(inputs):
        log("[ERROR] ANCHOR_ARG_IDX=%d out of range (max %d)" % (
            ANCHOR_ARG_IDX, len(inputs) - 1))
        return None, None

    anchor = inputs[ANCHOR_ARG_IDX]
    log("[INFO] anchor = %s  in function %s" % (vn_str(anchor), func_name(func)))
    return anchor, func

# ---------------------------------------------------------------------------
# SAVE
# ---------------------------------------------------------------------------

def save():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)

    name = currentProgram.getName().replace(" ", "_")

    result = {
        "binary":         name,
        "anchor_address": "0x%x" % ANCHOR_ADDRESS,
        "anchor_arg_idx": ANCHOR_ARG_IDX,
        "source_count":   len(sources),
        "chain_count":    len(chain),
        "sources":        sources,
        "chain":          chain,
    }
    json_path = os.path.join(OUTPUT_DIR, "%s_slice.json" % name)
    with open(json_path, "w") as f:
        json.dump(result, f, indent=2)
    log("[OUT] JSON  -> %s" % json_path)

    chain_path = os.path.join(OUTPUT_DIR, "%s_chain.csv" % name)
    with open(chain_path, "wb") as f:
        f.write("depth,address,op,output,inputs,note\n")
        for n in chain:
            row = "%d,%s,%s,%s,%s,%s\n" % (
                n["depth"],
                n["address"],
                n["op"],
                n["output"],
                " | ".join(n["inputs"]),
                n["note"],
            )
            f.write(row.encode("utf-8"))
    log("[OUT] chain -> %s" % chain_path)

    src_path = os.path.join(OUTPUT_DIR, "%s_sources.csv" % name)
    with open(src_path, "wb") as f:
        f.write("depth,varnode,is_reg,is_stack,note\n")
        for s in sources:
            row = "%d,%s,%s,%s,%s\n" % (
                s["depth"],
                s["varnode"],
                s["is_reg"],
                s["is_stack"],
                s.get("note", ""),
            )
            f.write(row.encode("utf-8"))
    log("[OUT] src   -> %s" % src_path)

    log("")
    log("=" * 50)
    log("SUMMARY")
    log("  chain ops : %d" % len(chain))
    log("  sources   : %d" % len(sources))
    log("-" * 50)
    for s in sources:
        note = s.get("note", "")
        if "[EXTERNAL SOURCE]" in note:
            tag = note
        elif s["is_reg"]:
            tag = "[REG - caller must be traced]"
        elif s["is_stack"]:
            tag = "[STACK]"
        else:
            tag = "[MEM - global/heap]"
        log("  depth=%-3d  %-30s  %s" % (s["depth"], s["varnode"], tag))
    log("=" * 50)

# ---------------------------------------------------------------------------
# ENTRY
# ---------------------------------------------------------------------------

def run():
    log("=" * 50)
    log("Backward Slicer (interprocedural)")
    log("  anchor addr : 0x%x" % ANCHOR_ADDRESS)
    log("  anchor arg  : in[%d]" % ANCHOR_ARG_IDX)
    log("  max depth   : %d" % MAX_DEPTH)
    log("  max calls   : %d" % MAX_CALL_DEPTH)
    log("=" * 50)

    anchor, anchor_func = find_anchor()
    if anchor is None:
        log("[ABORT] anchor not found. Check ANCHOR_ADDRESS / ANCHOR_ARG_IDX.")
        return

    backward_slice(anchor, anchor_func)
    save()
    log("done.")

run()
