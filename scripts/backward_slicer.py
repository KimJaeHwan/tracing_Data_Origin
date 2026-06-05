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

ANCHOR_ADDRESS  = 0x180410e26
ANCHOR_ARG_IDX  = 1

try:
    _script_dir = os.path.dirname(os.path.abspath(str(getSourceFile())))
except Exception:
    _script_dir = os.path.dirname(os.path.abspath(__file__))
OUTPUT_DIR = os.path.normpath(os.path.join(_script_dir, "..", "output"))

MAX_DEPTH            = 200
MAX_CALL_STACK_DEPTH = 10   # max function boundaries crossed going upward (like backtrace depth)

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
    "il2cpp_codegen_initialize_runtime_metadata",
    "il2cpp_codegen_initialize_runtime_metadata_inline",
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

def interprocedural_step(vn, containing_func, param_slot, depth, path_funcs=None, call_stack_depth=0):
    # path_funcs: set of function entry offsets on the current handle_indirect path.
    # Non-empty means we entered containing_func via handle_indirect, so only follow
    # callers that are already on that path (avoids XREF fanout from generic callees).
    callee_name = func_name(containing_func)
    callee_entry = containing_func.getEntryPoint()

    if call_stack_depth >= MAX_CALL_STACK_DEPTH:
        sources.append({
            "varnode":  vn_str(vn),
            "is_reg":   vn.isRegister(),
            "is_stack": is_stack(vn),
            "depth":    depth,
            "note":     "call stack depth limit (%d) reached in %s param[%d]" % (MAX_CALL_STACK_DEPTH, callee_name, param_slot),
        })
        return

    log("[INTERPROC] tracing param slot %d of %s (depth=%d, call_stack=%d, path_restricted=%s)"
        % (param_slot, callee_name, depth, call_stack_depth, path_funcs is not None and len(path_funcs) > 0))

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

    call_arg_idx = param_slot + 1

    for ref in call_refs:
        call_site = ref.getFromAddress()
        caller_func = currentProgram.getFunctionManager().getFunctionContaining(call_site)
        if caller_func is None:
            continue

        caller_name = func_name(caller_func)

        if caller_name in SKIP_FUNCTIONS:
            continue

        # path restriction: only follow callers on the handle_indirect path
        if path_funcs:
            caller_entry_off = caller_func.getEntryPoint().getOffset()
            if caller_entry_off not in path_funcs:
                log("[INTERPROC] skip %s (not on path)" % caller_name)
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

        # path_funcs is not propagated upward: once we're back in a known-path
        # function, normal (unrestricted) tracing resumes
        backward_slice_impl(arg_vn, caller_func, depth + 1, call_stack_depth=call_stack_depth + 1)

# ---------------------------------------------------------------------------
# INDIRECT HANDLER
#
# INDIRECT op means: output_vn was modified as a side effect of a CALL.
# Strategy:
#   1. Find the causing CALL op at the same address.
#   2. Identify which argument is the pointer to output_vn (stack offset match).
#   3. Decompile the callee; find all STORE ops through that parameter pointer.
#   4. Trace each stored value backward.
# ---------------------------------------------------------------------------

def _find_iop_call(def_op, high):
    addr = def_op.getSeqnum().getTarget()
    for op in high.getPcodeOps(addr):
        if op.getOpcode() == PcodeOp.CALL or op.getOpcode() == PcodeOp.CALLIND:
            return op
    return None

def _get_callee_func(call_op):
    if call_op.getOpcode() != PcodeOp.CALL:
        return None
    try:
        callee_addr = call_op.getInput(0).getAddress()
        return currentProgram.getFunctionManager().getFunctionAt(callee_addr)
    except Exception:
        return None

def _vn_points_to_stack_offset(ptr_vn, target_off):
    """Return True if ptr_vn's def chain computes a pointer to stack offset target_off."""
    seen = set()
    worklist = [ptr_vn]
    while worklist:
        vn = worklist.pop()
        if vn is None or vn.isConstant():
            continue
        k = (str(vn.getAddress()), vn.getOffset(), vn.getSize())
        if k in seen:
            continue
        seen.add(k)
        d = vn.getDef()
        if d is None:
            continue
        opc = d.getOpcode()
        if opc == PcodeOp.PTRSUB or opc == PcodeOp.PTRADD:
            c = d.getInput(1)
            if c.isConstant():
                off = c.getOffset()
                if off > 0x7FFFFFFFFFFFFFFF:
                    off = off - 0x10000000000000000
                if off == target_off:
                    return True
            worklist.append(d.getInput(0))
        elif opc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT):
            worklist.append(d.getInput(0))
        elif opc == PcodeOp.MULTIEQUAL:
            for inp in d.getInputs():
                worklist.append(inp)
        elif opc == PcodeOp.INT_ADD:
            c = d.getInput(1)
            if c.isConstant():
                off = c.getOffset()
                if off > 0x7FFFFFFFFFFFFFFF:
                    off = off - 0x10000000000000000
                if off == target_off:
                    return True
            worklist.append(d.getInput(0))
            worklist.append(d.getInput(1))
    return False

def _collect_ptr_derived(callee_high, seed_keys):
    """Forward-propagate seed_keys through copy/cast/ptr ops; return reachable key set."""
    reachable = set(seed_keys)
    changed = True
    while changed:
        changed = False
        for op in callee_high.getPcodeOps():
            out = op.getOutput()
            if out is None:
                continue
            out_k = (str(out.getAddress()), out.getOffset(), out.getSize())
            if out_k in reachable:
                continue
            opc = op.getOpcode()
            if opc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT,
                       PcodeOp.PTRSUB, PcodeOp.PTRADD, PcodeOp.INT_ADD, PcodeOp.MULTIEQUAL):
                for inp in op.getInputs():
                    k = (str(inp.getAddress()), inp.getOffset(), inp.getSize())
                    if k in reachable:
                        reachable.add(out_k)
                        changed = True
                        break
    return reachable

def find_stores_to_stack_addr(ptrsub_op, containing_func):
    """
    Given PTRSUB(RSP, offset) op, find all non-stack values that ultimately
    flow into that stack location, following stack-to-stack copies recursively.
    """
    off_vn = ptrsub_op.getInput(1)
    if not off_vn.isConstant():
        return []

    stack_off = off_vn.getOffset()
    if stack_off > 0x7FFFFFFFFFFFFFFF:
        stack_off -= 0x10000000000000000

    high = get_high_function(containing_func)
    if high is None:
        return []

    return _trace_stack_offset(high, stack_off, set(), set())


def _trace_stack_offset(high, stack_off, seen_vals, seen_offs):
    """
    Recursively collect non-stack varnodes that flow into stack_off.
    seen_offs prevents infinite loops on circular stack copies.
    seen_vals deduplicates results by (addr, offset, size).
    """
    if stack_off in seen_offs:
        return []
    seen_offs.add(stack_off)

    result = []

    for op in high.getPcodeOps():
        opc = op.getOpcode()

        # Case 1: STORE [ptr], val  where ptr -> stack_off
        if opc == PcodeOp.STORE:
            ptr_vn = op.getInput(1)
            if _vn_points_to_stack_offset(ptr_vn, stack_off):
                val_vn = op.getInput(2)
                if not val_vn.isConstant():
                    _add_stack_source(high, val_vn, result, seen_vals, seen_offs)
            continue

        # Case 2: direct SSA stack varnode assignment
        out = op.getOutput()
        if out is None or not is_stack(out):
            continue
        off = out.getOffset()
        if off > 0x7FFFFFFFFFFFFFFF:
            off -= 0x10000000000000000
        if off != stack_off:
            continue
        for inp in op.getInputs():
            if not inp.isConstant():
                _add_stack_source(high, inp, result, seen_vals, seen_offs)

    return result


def _add_stack_source(high, vn, result, seen_vals, seen_offs):
    """
    If vn is a stack varnode, recurse into it.
    Otherwise add it to result (deduped by seen_vals).
    """
    if is_stack(vn):
        sub_off = vn.getOffset()
        if sub_off > 0x7FFFFFFFFFFFFFFF:
            sub_off -= 0x10000000000000000
        sub = _trace_stack_offset(high, sub_off, seen_vals, seen_offs)
        result.extend(sub)
    else:
        k = (str(vn.getAddress()), vn.getOffset(), vn.getSize())
        if k not in seen_vals:
            seen_vals.add(k)
            result.append(vn)

def _find_output_param_stores(callee_high, param_slot):
    """Return list of value-varnodes STOREd through callee's param[param_slot] pointer."""
    local_map = callee_high.getLocalSymbolMap()
    if local_map is None or param_slot >= local_map.getNumParams():
        return []
    param_sym = local_map.getParamSymbol(param_slot)
    if param_sym is None:
        return []

    seed_keys = set()
    high_var = param_sym.getHighVariable()
    if high_var is None:
        return []
    for pv in high_var.getInstances():
        seed_keys.add((str(pv.getAddress()), pv.getOffset(), pv.getSize()))

    reachable = _collect_ptr_derived(callee_high, seed_keys)

    stored = []
    for op in callee_high.getPcodeOps():
        if op.getOpcode() == PcodeOp.STORE:
            # STORE: in[0]=addrspace, in[1]=pointer, in[2]=value
            ptr_vn = op.getInput(1)
            k = (str(ptr_vn.getAddress()), ptr_vn.getOffset(), ptr_vn.getSize())
            if k in reachable:
                stored.append(op.getInput(2))
    return stored

def _vn_is_addr_of_global(ptr_vn, target_vn):
    """
    Return True if ptr_vn represents the address of a global/heap varnode.
    i.e., ptr_vn is a constant whose value equals target_vn's offset in RAM.
    """
    try:
        if target_vn.getAddress().getAddressSpace().getName() not in ("ram", "DATA"):
            return False
    except Exception:
        return False
    target_offset = target_vn.getOffset()
    seen = set()
    worklist = [ptr_vn]
    while worklist:
        vn = worklist.pop()
        if vn is None:
            continue
        if vn.isConstant():
            if vn.getOffset() == target_offset:
                return True
            continue
        k = (str(vn.getAddress()), vn.getOffset(), vn.getSize())
        if k in seen:
            continue
        seen.add(k)
        d = vn.getDef()
        if d is None:
            continue
        opc = d.getOpcode()
        if opc in (PcodeOp.COPY, PcodeOp.CAST, PcodeOp.INT_ZEXT, PcodeOp.INT_SEXT):
            worklist.append(d.getInput(0))
        elif opc == PcodeOp.MULTIEQUAL:
            for inp in d.getInputs():
                worklist.append(inp)
    return False


def handle_indirect(def_op, output_vn, containing_func, depth, path_funcs=None, call_stack_depth=0):
    """
    Follow an INDIRECT op into the callee that wrote to output_vn.
    Handles both stack variables and heap/global objects.
    Returns True if the callee was successfully entered, False to fall back.
    path_funcs: propagated from caller context (None at top level).
    """
    if is_stack(output_vn):
        return _handle_indirect_stack(def_op, output_vn, containing_func, depth, path_funcs, call_stack_depth)
    else:
        return _handle_indirect_heap(def_op, output_vn, containing_func, depth, path_funcs, call_stack_depth)


def _handle_indirect_stack(def_op, output_vn, containing_func, depth, path_funcs, call_stack_depth):

    high = get_high_function(containing_func)
    if high is None:
        return False

    call_op = _find_iop_call(def_op, high)
    if call_op is None:
        return False

    callee_func = _get_callee_func(call_op)
    if callee_func is None:
        return False

    callee_name = func_name(callee_func)

    if callee_name in STOP_FUNCTIONS:
        sources.append({
            "varnode":  vn_str(output_vn),
            "is_reg":   False,
            "is_stack": True,
            "depth":    depth,
            "note":     "[EXTERNAL SOURCE] %s (output param)" % callee_name,
        })
        return True

    if callee_name in SKIP_FUNCTIONS:
        return False

    # Match CALL arg to output_vn by stack offset
    target_off = output_vn.getOffset()
    if target_off > 0x7FFFFFFFFFFFFFFF:
        target_off = target_off - 0x10000000000000000

    inputs = list(call_op.getInputs())
    ptr_arg_idx = -1
    for i in range(1, len(inputs)):
        if _vn_points_to_stack_offset(inputs[i], target_off):
            ptr_arg_idx = i
            break

    if ptr_arg_idx < 0:
        log("[INDIRECT] could not match ptr arg for %s stack:0x%x - trying all pointer args"
            % (callee_name, target_off))
        # Fallback: try param slots one by one and pick first that has stores
        callee_high = get_high_function(callee_func)
        if callee_high is None:
            return False
        local_map = callee_high.getLocalSymbolMap()
        num = local_map.getNumParams() if local_map else 0
        for slot in range(num):
            stores = _find_output_param_stores(callee_high, slot)
            if stores:
                ptr_arg_idx = slot + 1
                break
        if ptr_arg_idx < 0:
            return False

    param_slot = ptr_arg_idx - 1
    callee_high = get_high_function(callee_func)
    if callee_high is None:
        return False

    stores = _find_output_param_stores(callee_high, param_slot)
    log("[INDIRECT] %s param[%d] -> %d store(s) found" % (callee_name, param_slot, len(stores)))

    chain.append({
        "address": op_addr_str(def_op),
        "op":      "INDIRECT->CALL",
        "output":  vn_str(output_vn),
        "inputs":  [callee_name],
        "depth":   depth,
        "note":    "output param[%d] written by %s (%d stores)" % (param_slot, callee_name, len(stores)),
    })

    if not stores:
        sources.append({
            "varnode":  vn_str(output_vn),
            "is_reg":   False,
            "is_stack": True,
            "depth":    depth,
            "note":     "no STORE found in %s param[%d]" % (callee_name, param_slot),
        })
        return True

    # path_funcs: containing_func (the one with INDIRECT) + callee_func (we're entering)
    # interprocedural_step inside callee will only follow callers in this set,
    # preventing XREF fanout through unrelated callers of generic methods
    new_path = frozenset([
        containing_func.getEntryPoint().getOffset(),
        callee_func.getEntryPoint().getOffset(),
    ])
    for stored_vn in stores:
        # handle_indirect goes DOWN into callee - call_stack_depth does not increase
        backward_slice_impl(stored_vn, callee_func, depth + 1, path_funcs=new_path, call_stack_depth=call_stack_depth)

    return True


def _handle_indirect_heap(def_op, output_vn, containing_func, depth, path_funcs, call_stack_depth):
    """
    Handle INDIRECT op for heap/global objects.
    Finds which CALL argument is a pointer TO output_vn's global address,
    enters the callee, and traces STORE ops through that parameter.
    """
    if call_stack_depth >= MAX_CALL_STACK_DEPTH:
        return False

    high = get_high_function(containing_func)
    if high is None:
        return False

    call_op = _find_iop_call(def_op, high)
    if call_op is None:
        return False

    callee_func = _get_callee_func(call_op)
    if callee_func is None:
        return False

    callee_name = func_name(callee_func)

    if callee_name in STOP_FUNCTIONS:
        sources.append({
            "varnode":  vn_str(output_vn),
            "is_reg":   False,
            "is_stack": False,
            "depth":    depth,
            "note":     "[EXTERNAL SOURCE] %s (heap output param)" % callee_name,
        })
        return True

    if callee_name in SKIP_FUNCTIONS:
        return False

    # Find which CALL input is a pointer to output_vn's global address
    inputs = list(call_op.getInputs())
    ptr_arg_idx = -1
    for i in range(1, len(inputs)):
        if _vn_is_addr_of_global(inputs[i], output_vn):
            ptr_arg_idx = i
            break

    if ptr_arg_idx < 0:
        log("[INDIRECT-HEAP] could not match ptr arg for %s @%s"
            % (callee_name, vn_str(output_vn)))
        return False

    param_slot = ptr_arg_idx - 1
    callee_high = get_high_function(callee_func)
    if callee_high is None:
        return False

    stores = _find_output_param_stores(callee_high, param_slot)
    log("[INDIRECT-HEAP] %s param[%d] -> %d store(s) found"
        % (callee_name, param_slot, len(stores)))

    chain.append({
        "address": op_addr_str(def_op),
        "op":      "INDIRECT->CALL",
        "output":  vn_str(output_vn),
        "inputs":  [callee_name],
        "depth":   depth,
        "note":    "heap output param[%d] written by %s (%d stores)" % (param_slot, callee_name, len(stores)),
    })

    if not stores:
        sources.append({
            "varnode":  vn_str(output_vn),
            "is_reg":   False,
            "is_stack": False,
            "depth":    depth,
            "note":     "no STORE found in %s param[%d]" % (callee_name, param_slot),
        })
        return True

    new_path = frozenset([
        containing_func.getEntryPoint().getOffset(),
        callee_func.getEntryPoint().getOffset(),
    ])
    for stored_vn in stores:
        backward_slice_impl(stored_vn, callee_func, depth + 1,
                           path_funcs=new_path, call_stack_depth=call_stack_depth)
    return True


# ---------------------------------------------------------------------------
# PARAM SLOT RESOLUTION
#
# Given a varnode that has no def-op in a HighFunction, determine if it is
# a formal parameter and return its 0-based slot index.
# Returns -1 if it cannot be identified as a parameter.
# ---------------------------------------------------------------------------

def resolve_param_slot(vn, high):
    # Match by SSA identity (hashCode) first - exact same varnode object.
    # This prevents false matches where multiple SSA versions of the same
    # physical register (e.g. RCX_v1=param, RCX_v2=local copy) share the
    # same (address, offset, size) but are different SSA nodes.
    local_sym_map = high.getLocalSymbolMap()
    if local_sym_map is None:
        return -1

    try:
        target_hash = vn.hashCode()
    except Exception:
        target_hash = None

    num_params = local_sym_map.getNumParams()
    for i in range(num_params):
        param_sym = local_sym_map.getParamSymbol(i)
        if param_sym is None:
            continue
        high_var = param_sym.getHighVariable()
        if high_var is None:
            continue
        for pv in high_var.getInstances():
            if target_hash is not None:
                if pv.hashCode() == target_hash:
                    return i
            else:
                # fallback: position-based match
                if (pv.getAddress() == vn.getAddress() and
                        pv.getOffset() == vn.getOffset() and
                        pv.getSize() == vn.getSize()):
                    return i
    return -1

# ---------------------------------------------------------------------------
# CORE - backward slice (interprocedural-aware)
# ---------------------------------------------------------------------------

def backward_slice_impl(vn, containing_func, depth, path_funcs=None, call_stack_depth=0):
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
    # Include SSA-unique identifier (Java hashCode) to distinguish multiple SSA
    # versions of the same physical location (pre-call vs post-call, loop carries, etc.)
    try:
        ssa_id = vn.hashCode()
    except Exception:
        ssa_id = id(vn)
    key = (func_entry_hex, str(vn.getAddress()), vn.getOffset(), vn.getSize(), ssa_id)
    if key in visited:
        chain.append({
            "address": "N/A",
            "op":      "CYCLE",
            "output":  vn_str(vn),
            "inputs":  [],
            "depth":   depth,
            "note":    "already visited in func@%s" % func_entry_hex,
        })
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
            interprocedural_step(vn, containing_func, param_slot, depth, path_funcs, call_stack_depth)
        else:
            sources.append({
                "varnode":  vn_str(vn),
                "is_reg":   vn.isRegister(),
                "is_stack": is_stack(vn),
                "depth":    depth,
                "note":     "",
            })
        return

    # INDIRECT: output_vn was written as a side effect of a CALL
    # Try to enter the callee and trace its STORE ops before falling back
    if def_op.getOpcode() == PcodeOp.INDIRECT:
        if handle_indirect(def_op, vn, containing_func, depth, path_funcs, call_stack_depth):
            return
        # Fallback behavior differs by varnode type:
        #   Stack  : trace pre-call value (may be meaningful for loop-carry patterns)
        #   Non-stack: callee couldn't be resolved AND pre-call value = same global
        #             -> tracing further just loops. Stop and record as source.
        if not is_stack(vn):
            sources.append({
                "varnode":  vn_str(vn),
                "is_reg":   vn.isRegister(),
                "is_stack": False,
                "depth":    depth,
                "note":     "heap/global INDIRECT - callee not resolved",
            })
            return
        inp0 = def_op.getInput(0)
        chain.append({
            "address": op_addr_str(def_op),
            "op":      "INDIRECT(fallback)",
            "output":  vn_str(def_op.getOutput()),
            "inputs":  [vn_str(def_op.getInput(0))],
            "depth":   depth,
            "note":    "callee not resolved - tracing pre-call value",
        })
        if not inp0.isConstant():
            backward_slice_impl(inp0, containing_func, depth + 1, path_funcs, call_stack_depth)
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

    # For CALL/CALLIND, in[0] is the callee/function pointer (structural, not data).
    # Skip it to avoid tracing irrelevant function pointer globals.
    opc = def_op.getOpcode()
    inputs_to_trace = def_op.getInputs()
    if opc == PcodeOp.CALL or opc == PcodeOp.CALLIND:
        inputs_to_trace = list(inputs_to_trace)[1:]

    for inp in inputs_to_trace:
        if not inp.isConstant():
            backward_slice_impl(inp, containing_func, depth + 1, path_funcs, call_stack_depth)

    # Stack STORE tracking:
    # PTRSUB(RSP, offset) computes &stack_var.
    # Find what was written to that stack location (STORE or direct SSA assignment).
    if def_op.getOpcode() == PcodeOp.PTRSUB:
        base_vn = def_op.getInput(0)
        if base_vn.getDef() is None and base_vn.isRegister():
            reg = currentProgram.getLanguage().getRegister(
                base_vn.getAddress(), base_vn.getSize())
            if reg is not None and reg.getName() == "RSP":
                stores = find_stores_to_stack_addr(def_op, containing_func)
                if stores:
                    log("[STACK-STORE] %d source(s) at %s in %s"
                        % (len(stores), vn_str(vn), func_name(containing_func)))
                    for stored_vn in stores:
                        if not stored_vn.isConstant():
                            backward_slice_impl(stored_vn, containing_func, depth + 1, path_funcs, call_stack_depth)

    # MULTIEQUAL loop-carry check:
    # If MULTIEQUAL's inputs are all already visited (self-referential loop),
    # the varnode may be a parameter whose def was never reached interprocedurally.
    if def_op.getOpcode() == PcodeOp.MULTIEQUAL:
        def _inp_visited(inp):
            if inp.isConstant():
                return True
            try:
                s = inp.hashCode()
            except Exception:
                s = id(inp)
            return (func_entry_hex, str(inp.getAddress()), inp.getOffset(), inp.getSize(), s) in visited
        all_inputs_visited = all(_inp_visited(inp) for inp in def_op.getInputs())
        if all_inputs_visited:
            high = get_high_function(containing_func)
            if high is not None:
                param_slot = resolve_param_slot(vn, high)
                callee_name = func_name(containing_func)
                if param_slot >= 0 and callee_name not in STOP_FUNCTIONS:
                    log("[MULTIEQUAL-LOOP] %s param[%d] detected as loop-carry, tracing interprocedurally"
                        % (callee_name, param_slot))
                    interprocedural_step(vn, containing_func, param_slot, depth,
                                        path_funcs, call_stack_depth)


def backward_slice(vn, containing_func):
    backward_slice_impl(vn, containing_func, 0)

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
    log("  max depth        : %d" % MAX_DEPTH)
    log("  max call stack   : %d" % MAX_CALL_STACK_DEPTH)
    log("=" * 50)

    anchor, anchor_func = find_anchor()
    if anchor is None:
        log("[ABORT] anchor not found. Check ANCHOR_ADDRESS / ANCHOR_ARG_IDX.")
        return

    backward_slice(anchor, anchor_func)
    save()
    log("done.")

run()
