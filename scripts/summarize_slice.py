#!/usr/bin/env python3
# summarize_slice.py
# Run outside Ghidra with Python 3
# Usage: python summarize_slice.py [slice_json_path]
#
# Reads backward_slicer output JSON and writes a human-readable Markdown report.

import json
import os
import re
import sys
from collections import defaultdict, OrderedDict

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

DEFAULT_JSON = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "output", "GameAssembly.dll_slice.json"
)

# ---------------------------------------------------------------------------
# LOAD
# ---------------------------------------------------------------------------

def load(path):
    with open(path, "r") as f:
        return json.load(f)

# ---------------------------------------------------------------------------
# PARSE HELPERS
# ---------------------------------------------------------------------------

def parse_interproc_note(note):
    """
    'cross-function: FuncA -> FuncB param[N]'
    -> (caller, callee, param_slot)
    """
    m = re.match(r"cross-function:\s*(\S+)\s*->\s*(\S+)\s*param\[(\d+)\]", note)
    if m:
        return m.group(1), m.group(2), int(m.group(3))
    return None, None, None

def parse_indirect_note(note):
    """
    'output param[N] written by FuncName (M stores)'
    -> (param_slot, callee_name, store_count)
    """
    m = re.match(r"output param\[(\d+)\] written by (\S+) \((\d+) stores\)", note)
    if m:
        return int(m.group(1)), m.group(2), int(m.group(3))
    return None, None, None

def shorten(name, maxlen=60):
    if len(name) <= maxlen:
        return name
    return name[:maxlen - 3] + "..."

def vn_type(vn):
    if vn.startswith("const:"):    return "CONST"
    if vn.startswith("stack:"):    return "STACK"
    if vn.startswith("tmp:"):      return "TMP"
    if vn.startswith("mem@"):      return "MEM"
    return "REG"

# ---------------------------------------------------------------------------
# BUILD FUNCTION CALL FLOW
# ---------------------------------------------------------------------------

def build_call_flow(chain):
    """
    Extract function-level transitions from the chain.
    Returns list of transition dicts in order encountered.
    """
    transitions = []
    seen = set()

    for op in chain:
        op_type = op["op"]
        note    = op.get("note", "")
        depth   = op["depth"]
        addr    = op["address"]
        inputs  = op.get("inputs", [])
        output  = op.get("output", "")

        if op_type == "INTERPROC_CALL":
            caller, callee, slot = parse_interproc_note(note)
            if caller and callee:
                key = ("INTERPROC", caller, callee, slot)
                if key not in seen:
                    seen.add(key)
                    transitions.append({
                        "type":     "INTERPROC",
                        "caller":   caller,
                        "callee":   callee,
                        "slot":     slot,
                        "arg":      inputs[0] if inputs else "?",
                        "depth":    depth,
                        "address":  addr,
                    })

        elif op_type == "INDIRECT->CALL":
            slot, callee, stores = parse_indirect_note(note)
            callee_name = inputs[0] if inputs else callee or "?"
            context = output  # the stack varnode being written
            key = ("INDIRECT", callee_name, context)
            if key not in seen:
                seen.add(key)
                transitions.append({
                    "type":    "INDIRECT",
                    "callee":  callee_name,
                    "slot":    slot,
                    "stores":  stores,
                    "output":  context,
                    "depth":   depth,
                    "address": addr,
                })

        elif op_type == "MULTIEQUAL-LOOP" or (op_type == "MULTIEQUAL" and "loop" in note.lower()):
            pass  # handled via INTERPROC that follows

    return transitions

# ---------------------------------------------------------------------------
# PER-FUNCTION DATA ACCESS SUMMARY
# ---------------------------------------------------------------------------

def build_func_accesses(chain):
    """
    For each function appearing in transition notes, collect notable ops:
    LOADs, PTRSUBs, STACKs, register inputs.
    Keyed by function name.
    """
    func_accesses = defaultdict(lambda: {
        "loads": [],
        "ptrsubs": [],
        "calls": [],
        "stack_accesses": [],
        "registers": set(),
    })

    # Track current function context via INTERPROC transitions
    # We reconstruct context from notes
    for op in chain:
        note   = op.get("note", "")
        op_type = op["op"]
        inputs  = op.get("inputs", [])
        output  = op.get("output", "")
        addr    = op.get("address", "?")

        # Extract function context from note if available
        func_ctx = None
        m = re.search(r"in func@(0x[0-9a-f]+)", note)
        if m:
            func_ctx = m.group(1)

        # INTERPROC_CALL: note tells us caller and callee
        if op_type == "INTERPROC_CALL":
            caller, callee, slot = parse_interproc_note(note)
            if caller:
                arg_vn = inputs[0] if inputs else "?"
                func_accesses[caller]["calls"].append(
                    "param[%d] -> %s  (arg=%s  @%s)" % (slot, shorten(callee, 40), arg_vn, addr)
                )

        # LOAD: memory read
        elif op_type == "LOAD" and len(inputs) >= 2:
            ptr = inputs[1]
            func_accesses["_all"]["loads"].append(
                "@%s  LOAD [%s] -> %s" % (addr, ptr, output)
            )

        # PTRSUB / PTRADD: address calculation
        elif op_type in ("PTRSUB", "PTRADD") and inputs:
            base = inputs[0]
            off  = inputs[1] if len(inputs) > 1 else "?"
            func_accesses["_all"]["ptrsubs"].append(
                "@%s  %s(%s, %s) -> %s" % (addr, op_type, base, off, output)
            )

        # Register sources in any op
        for vn in inputs + [output]:
            if vn and vn_type(vn) == "REG" and vn not in ("null",):
                if func_ctx:
                    func_accesses[func_ctx]["registers"].add(vn)

    return func_accesses

# ---------------------------------------------------------------------------
# SOURCE CATEGORIZATION
# ---------------------------------------------------------------------------

def categorize_sources(sources):
    cats = {
        "EXTERNAL": [],   # recv, ReadFile
        "REG":      [],   # registers needing further trace
        "MEM":      [],   # global / heap addresses
        "STACK":    [],   # unresolved stack vars
        "CONST":    [],   # constants
        "OTHER":    [],
    }
    for s in sources:
        vn   = s["varnode"]
        note = s.get("note", "")
        depth = s["depth"]
        entry = {"varnode": vn, "depth": depth, "note": note}

        if "[EXTERNAL SOURCE]" in note:
            cats["EXTERNAL"].append(entry)
        elif vn_type(vn) == "REG":
            cats["REG"].append(entry)
        elif vn_type(vn) == "MEM":
            cats["MEM"].append(entry)
        elif vn_type(vn) == "STACK":
            cats["STACK"].append(entry)
        elif vn_type(vn) == "CONST":
            cats["CONST"].append(entry)
        else:
            cats["OTHER"].append(entry)
    return cats

# ---------------------------------------------------------------------------
# TREE RENDERER
# ---------------------------------------------------------------------------

def _classify_leaf_tag(arg, caller, sources):
    """
    Determine why a leaf transition stopped and return a tag string.

    Tags:
      [BLOCKED-virtual-dispatch]  : reg source with 'no callers' - il2cpp virtual dispatch
      [BLOCKED-no-callers]        : reg source, no XREF found
      [BLOCKED-depth-limit]       : hit MAX_CALL_STACK_DEPTH
      [SOURCE-metadata]           : il2cpp RuntimeMethod / class pointer (global, not data)
      [SOURCE-data ★]             : meaningful data origin to investigate further
      [SOURCE-const]              : constant value
      [SOURCE-stack]              : unresolved stack variable
    """
    # Constants
    if arg.startswith("const:"):
        return "[SOURCE-const]"

    # Global MEM - check if it looks like a RuntimeMethod/metadata pointer
    if arg.startswith("mem@"):
        # Known metadata pattern: read as pointer from IDA confirmed RuntimeMethod_var etc.
        return "[SOURCE-metadata]"

    # Register sources - match against sources list
    if vn_type(arg) == "REG":
        for s in sources:
            note = s.get("note", "")
            if "no callers" in note and caller and caller[:30] in note:
                if "virtual" in note.lower() or "AdjustorThunk" in note:
                    return "[BLOCKED-virtual-dispatch]"
                return "[BLOCKED-no-callers]"
        # Generic no-callers (lambda with virtual dispatch pattern)
        if any(x in caller for x in ("U3CU3Ec", "Lambda", "lambda")):
            return "[BLOCKED-virtual-dispatch ★next-anchor]"
        return "[BLOCKED-no-callers]"

    # Stack
    if arg.startswith("stack:"):
        return "[SOURCE-stack]"

    return ""


def _render_tree(transitions, lines, sources):
    """
    Build an ASCII tree from the flat transitions list.
    Leaf nodes (no children) get a tag showing why tracing stopped.
    """
    if not transitions:
        return

    W = lines.append

    # Assign each transition a tree-parent index
    parents = []
    for i, t in enumerate(transitions):
        p = -1
        for j in range(i - 1, -1, -1):
            if transitions[j]["depth"] < t["depth"]:
                p = j
                break
        parents.append(p)

    # Count children per node
    child_count = defaultdict(int)
    for p in parents:
        if p >= 0:
            child_count[p] += 1

    # Compute tree level
    levels = []
    for i, p in enumerate(parents):
        if p < 0:
            levels.append(0)
        else:
            levels.append(levels[p] + 1)

    # Track sibling indices
    sibling_idx = defaultdict(int)

    for i, t in enumerate(transitions):
        lvl    = levels[i]
        p      = parents[i]
        is_leaf = child_count[i] == 0

        indent = "  " * lvl

        branch_label = ""
        if p >= 0 and child_count[p] > 1:
            sibling_idx[p] += 1
            branch_label = "[branch %d] " % sibling_idx[p]

        if t["type"] == "INDIRECT":
            callee = shorten(t["callee"], 55)
            slot   = t["slot"] if t["slot"] is not None else "?"
            stores = t["stores"] if t["stores"] is not None else "?"
            out    = t["output"]
            tag    = ""
            if is_leaf:
                tag = "  " + _classify_leaf_tag(out, t["callee"], sources)
            W("%s%s▼ INDIRECT  %s%s" % (indent, branch_label, callee, tag))
            W("%s          param[%s] out-param → writes to %s  (%s stores)  @%s" % (
                indent, slot, out, stores, t["address"]))
        else:
            caller = shorten(t["caller"], 45)
            callee = shorten(t["callee"], 45)
            slot   = t["slot"]
            arg    = t["arg"]
            tag    = ""
            if is_leaf:
                tag = "  " + _classify_leaf_tag(arg, t["caller"], sources)
            W("%s%s▲ INTERPROC  %s%s" % (indent, branch_label, caller, tag))
            W("%s          → %s  param[%d]  arg=%s  @%s" % (
                indent, callee, slot, arg, t["address"]))

# ---------------------------------------------------------------------------
# RENDER MARKDOWN
# ---------------------------------------------------------------------------

def render(data, out_path):
    j          = data
    chain      = j["chain"]
    sources    = j["sources"]
    anchor     = j["anchor_address"]
    arg_idx    = j["anchor_arg_idx"]
    binary     = j["binary"]
    chain_cnt  = j["chain_count"]
    src_cnt    = j["source_count"]

    transitions = build_call_flow(chain)
    src_cats    = categorize_sources(sources)

    lines = []
    W = lines.append

    W("# Backward Slice Summary")
    W("")
    W("| Key | Value |")
    W("|-----|-------|")
    W("| Binary       | %s |" % binary)
    W("| Anchor       | %s  in[%d] |" % (anchor, arg_idx))
    W("| Chain ops    | %d |" % chain_cnt)
    W("| Sources      | %d |" % src_cnt)
    W("")

    # -----------------------------------------------------------------------
    W("---")
    W("")
    W("## 1. Function Call Flow (Tree)")
    W("")
    W("```")
    W("anchor  %s  in[%d]" % (anchor, arg_idx))
    _render_tree(transitions, lines, sources)
    W("```")
    W("")
    W("### Legend")
    W("- `▼ INDIRECT` : callee 가 포인터 arg 를 통해 내 스택 변수를 **채워줌** (아래로 진입)")
    W("- `▲ INTERPROC`: 현재 함수의 파라미터를 **누가 넘겼는지** caller 탐색 (위로 추적)")
    W("- `[branch N]` : 동일 depth 에서 갈라진 독립 브랜치 (DFS 순서로 나열)")
    W("")

    # -----------------------------------------------------------------------
    W("---")
    W("")
    W("## 2. Notable PCode Operations")
    W("")

    # LOAD ops
    load_ops = [(op["address"], op["inputs"], op["output"], op.get("note",""))
                for op in chain if op["op"] == "LOAD"]
    if load_ops:
        W("### Memory Reads (LOAD)")
        W("")
        W("| Depth | Address | Pointer | Result |")
        W("|-------|---------|---------|--------|")
        for op in chain:
            if op["op"] == "LOAD" and len(op["inputs"]) >= 2:
                W("| %d | %s | %s | %s |" % (
                    op["depth"], op["address"],
                    op["inputs"][1], op["output"]))
        W("")

    # PTRSUB / PTRADD ops (address calculations)
    ptr_ops = [op for op in chain if op["op"] in ("PTRSUB", "PTRADD")]
    if ptr_ops:
        W("### Address Calculations (PTRSUB / PTRADD)")
        W("")
        W("| Depth | Address | Op | Base | Offset | Result |")
        W("|-------|---------|-----|------|--------|--------|")
        for op in ptr_ops:
            base = op["inputs"][0] if op["inputs"] else "?"
            off  = op["inputs"][1] if len(op["inputs"]) > 1 else "?"
            W("| %d | %s | %s | %s | %s | %s |" % (
                op["depth"], op["address"], op["op"],
                base, off, op["output"]))
        W("")

    # CALL ops (non-INTERPROC)
    call_ops = [op for op in chain if op["op"] == "CALL"]
    if call_ops:
        W("### Direct Calls (CALL)")
        W("")
        W("| Depth | Address | Target | Result |")
        W("|-------|---------|--------|--------|")
        for op in call_ops:
            target = op["inputs"][0] if op["inputs"] else "?"
            W("| %d | %s | %s | %s |" % (
                op["depth"], op["address"], target, op["output"]))
        W("")

    # -----------------------------------------------------------------------
    W("---")
    W("")
    W("## 3. Data Sources")
    W("")

    if src_cats["EXTERNAL"]:
        W("### External I/O Sources")
        W("")
        for s in src_cats["EXTERNAL"]:
            W("- depth=%-3d  `%s`  %s" % (s["depth"], s["varnode"], s["note"]))
        W("")

    if src_cats["REG"]:
        W("### Register Sources  _(caller must be traced further)_")
        W("")
        W("| Depth | Register | Note |")
        W("|-------|----------|------|")
        for s in src_cats["REG"]:
            W("| %d | `%s` | %s |" % (s["depth"], s["varnode"], s["note"]))
        W("")

    if src_cats["MEM"]:
        W("### Global / Heap Sources")
        W("")
        # dedupe by address
        seen_mem = OrderedDict()
        for s in src_cats["MEM"]:
            addr = s["varnode"]
            if addr not in seen_mem:
                seen_mem[addr] = s
        W("| Depth | Address | Note |")
        W("|-------|---------|------|")
        for addr, s in seen_mem.items():
            W("| %d | `%s` | %s |" % (s["depth"], addr, s["note"]))
        W("")

    if src_cats["STACK"]:
        W("### Unresolved Stack Sources")
        W("")
        for s in src_cats["STACK"]:
            W("- depth=%-3d  `%s`  %s" % (s["depth"], s["varnode"], s["note"]))
        W("")

    if src_cats["CONST"]:
        W("### Constant Sources")
        W("")
        const_vals = list(set(s["varnode"] for s in src_cats["CONST"]))
        W(", ".join("`%s`" % v for v in sorted(const_vals)))
        W("")

    # -----------------------------------------------------------------------
    W("---")
    W("")
    W("## 4. Cycle / Depth-Limit Hits")
    W("")
    cycles = [op for op in chain if op["op"] in ("CYCLE", "DEPTH_LIMIT")]
    if cycles:
        by_func = defaultdict(int)
        for op in cycles:
            note = op.get("note","")
            m = re.search(r"func@(0x[0-9a-f]+)", note)
            key = m.group(1) if m else "unknown"
            by_func[key] += 1
        W("| Function (entry) | Cycles / Limits |")
        W("|-----------------|----------------|")
        for func, cnt in sorted(by_func.items(), key=lambda x: -x[1]):
            W("| `%s` | %d |" % (func, cnt))
    else:
        W("None.")
    W("")

    # -----------------------------------------------------------------------
    W("---")
    W("")
    W("## 5. Raw Sources List")
    W("")
    W("| Depth | Varnode | Category | Note |")
    W("|-------|---------|----------|------|")
    for s in sources:
        vn   = s["varnode"]
        note = s.get("note","")
        cat  = vn_type(vn)
        if "[EXTERNAL SOURCE]" in note:
            cat = "EXTERNAL"
        W("| %d | `%s` | %s | %s |" % (s["depth"], vn, cat, note))
    W("")

    txt = "\n".join(lines)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(txt)
    return out_path

# ---------------------------------------------------------------------------
# ENTRY
# ---------------------------------------------------------------------------

def main():
    json_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_JSON

    if not os.path.exists(json_path):
        print("[ERROR] file not found: %s" % json_path)
        sys.exit(1)

    print("[INFO] loading %s" % json_path)
    data = load(json_path)

    out_path = json_path.replace("_slice.json", "_summary.md")
    render(data, out_path)
    print("[OUT]  summary -> %s" % out_path)

if __name__ == "__main__":
    main()
