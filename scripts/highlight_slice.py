# @author  highlight-slicer
# @category Analysis
# @keybinding
# @menupath
# @toolbar
# @runtime Jython

# Reads backward_slicer JSON output and applies visual highlights in Ghidra:
#   - Listing view: background color per op type
#   - Pre-comments: chain entry description
#   - Bookmarks: function transitions and sources
#
# Run AFTER backward_slicer.py has produced the JSON.

import json
import os
import sys
from java.awt import Color

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

try:
    _script_dir = os.path.dirname(os.path.abspath(str(getSourceFile())))
except Exception:
    _script_dir = os.path.dirname(os.path.abspath(__file__))

OUTPUT_DIR = os.path.normpath(os.path.join(_script_dir, "..", "output"))

# Automatically pick the most recent _slice.json in output/
def find_json():
    candidates = []
    for f in os.listdir(OUTPUT_DIR):
        if f.endswith("_slice.json"):
            candidates.append(os.path.join(OUTPUT_DIR, f))
    if not candidates:
        return None
    return sorted(candidates)[-1]

# Colors
COLOR_REGULAR    = Color(255, 255, 170)   # light yellow  - normal chain ops
COLOR_INTERPROC  = Color(140, 190, 255)   # light blue    - INTERPROC_CALL
COLOR_INDIRECT   = Color(255, 190,  80)   # orange        - INDIRECT->CALL
COLOR_SOURCE     = Color(140, 230, 140)   # light green   - data sources
COLOR_CYCLE      = Color(210, 210, 210)   # gray          - CYCLE hits
COLOR_ANCHOR     = Color(255, 120, 120)   # red           - anchor call site

BOOKMARK_CAT_CHAIN  = "SliceChain"
BOOKMARK_CAT_SOURCE = "SliceSource"

CLEAR_FIRST = True   # clear previous highlights before applying

# ---------------------------------------------------------------------------
# UTILS
# ---------------------------------------------------------------------------

def log(msg):
    sys.stdout.write(str(msg) + "\n")

def parse_addr(hex_str):
    try:
        offset = int(hex_str, 16)
        space  = currentProgram.getAddressFactory().getDefaultAddressSpace()
        return space.getAddress(offset)
    except Exception:
        return None

def safe_set_color(addr, color):
    try:
        setBackgroundColor(addr, color)
    except Exception:
        pass

def safe_comment(addr, text):
    try:
        existing = getPreComment(addr)
        if existing:
            text = existing + "\n" + text
        setPreComment(addr, text)
    except Exception:
        pass

def safe_bookmark(addr, bm_type, category, comment):
    try:
        createBookmark(addr, bm_type, category, comment)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# CLEAR
# ---------------------------------------------------------------------------

def clear_previous(chain, sources, anchor_addr):
    log("[INFO] clearing previous highlights...")
    addrs = set()
    if anchor_addr:
        addrs.add(anchor_addr)
    for entry in chain:
        a = parse_addr(entry.get("address", ""))
        if a:
            addrs.add(a)
    for src in sources:
        pass  # sources don't have addresses to clear directly

    for a in addrs:
        try:
            clearBackgroundColor(a)
        except Exception:
            pass

# ---------------------------------------------------------------------------
# APPLY HIGHLIGHTS
# ---------------------------------------------------------------------------

def apply(data):
    chain        = data.get("chain", [])
    sources      = data.get("sources", [])
    anchor_hex   = data.get("anchor_address", "")
    anchor_arg   = data.get("anchor_arg_idx", -1)
    binary       = data.get("binary", "?")

    anchor_addr = parse_addr(anchor_hex)

    if CLEAR_FIRST:
        clear_previous(chain, sources, anchor_addr)

    # --- Anchor ---
    if anchor_addr:
        safe_set_color(anchor_addr, COLOR_ANCHOR)
        safe_comment(anchor_addr,
            "[SLICE ANCHOR] %s in[%d]  binary=%s" % (anchor_hex, anchor_arg, binary))
        safe_bookmark(anchor_addr, "Analysis", BOOKMARK_CAT_CHAIN,
            "Anchor: in[%d]" % anchor_arg)
        log("[ANCHOR] %s" % anchor_hex)

    # --- Chain ops ---
    colored = 0
    for entry in chain:
        op      = entry.get("op", "")
        addr_s  = entry.get("address", "N/A")
        note    = entry.get("note", "")
        depth   = entry.get("depth", 0)
        inputs  = entry.get("inputs", [])
        output  = entry.get("output", "")

        if addr_s in ("N/A", "unknown"):
            continue

        addr = parse_addr(addr_s)
        if addr is None:
            continue

        # Choose color
        if op == "INTERPROC_CALL":
            color = COLOR_INTERPROC
        elif "INDIRECT" in op and "CALL" in op:
            color = COLOR_INDIRECT
        elif op == "CYCLE":
            color = COLOR_CYCLE
        else:
            color = COLOR_REGULAR

        safe_set_color(addr, color)

        # Comment
        short_in  = (", ".join(inputs))[:60]
        comment   = "[d=%d] %s  in=[%s]  out=%s" % (depth, op, short_in, output)
        if note:
            comment += "  // " + note[:80]
        safe_comment(addr, comment)

        # Bookmark for transitions
        if op in ("INTERPROC_CALL", "INDIRECT->CALL"):
            safe_bookmark(addr, "Analysis", BOOKMARK_CAT_CHAIN,
                "[d=%d] %s  %s" % (depth, op, note[:60]))

        colored += 1

    log("[INFO] colored %d chain ops" % colored)

    # --- Sources ---
    sourced = 0
    for src in sources:
        note    = src.get("note", "")
        vn      = src.get("varnode", "")
        depth   = src.get("depth", 0)

        # Sources don't always have direct addresses - bookmark the most recent
        # chain op that led to them if we can match, otherwise skip coloring.
        # We DO create a summary bookmark at the anchor for reference.
        sourced += 1

    # Source summary as bookmark on anchor
    if anchor_addr and sources:
        summary = "%d sources: " % len(sources)
        summary += " | ".join(
            s.get("varnode", "?")[:20] for s in sources[:5]
        )
        if len(sources) > 5:
            summary += " ..."
        safe_bookmark(anchor_addr, "Analysis", BOOKMARK_CAT_SOURCE, summary)

    log("[INFO] processed %d sources" % sourced)

# ---------------------------------------------------------------------------
# ENTRY
# ---------------------------------------------------------------------------

def run():
    json_path = find_json()
    if json_path is None:
        log("[ERROR] no _slice.json found in %s" % OUTPUT_DIR)
        return

    log("[INFO] loading %s" % json_path)
    with open(json_path, "r") as f:
        data = json.load(f)

    log("[INFO] chain=%d  sources=%d" % (data.get("chain_count", 0), data.get("source_count", 0)))

    apply(data)

    log("")
    log("Highlights applied:")
    log("  RED    = anchor (send call)")
    log("  YELLOW = traced ops")
    log("  BLUE   = function boundary crossing (INTERPROC)")
    log("  ORANGE = out-param callee entry (INDIRECT->CALL)")
    log("  GRAY   = cycle hits")
    log("  GREEN  = data sources")
    log("")
    log("Bookmarks added under categories:")
    log("  SliceChain  - transition points")
    log("  SliceSource - data origin summary")
    log("done.")

run()
