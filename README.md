# Ghidra PCode Backward Slicer

Interprocedural backward slicer for Ghidra (Jython 2.7).  
Traces the buffer argument of a `send()`-family call back to its data origin, crossing function boundaries.

## Scripts

| File | Role |
|------|------|
| `scripts/backward_slicer.py` | Core slicer - run this in Ghidra Script Manager |
| `scripts/pcode_dumper.py`    | Debug helper - dumps all High PCode ops in a function |

## Quick Start

1. Open the target binary in Ghidra and run Auto Analysis.
2. Use `pcode_dumper.py` to find the exact address of the `send` CALL op and confirm argument indices.
3. Set `ANCHOR_ADDRESS` and `ANCHOR_ARG_IDX` in `backward_slicer.py`.
4. Run `backward_slicer.py` via Script Manager (Window > Script Manager > Run).
5. Results are written to `~/ghidra_slicer_output/`.

## Output Files

| File | Contents |
|------|----------|
| `<binary>_slice.json`   | Full result: chain ops + sources |
| `<binary>_chain.csv`    | Every PCode op visited during the slice |
| `<binary>_sources.csv`  | Leaf varnodes (data origins) |

## Config (backward_slicer.py)

```python
ANCHOR_ADDRESS  = 0x18190c492   # address of the CALL instruction
ANCHOR_ARG_IDX  = 2             # 0-based index into CALL inputs (0 = fn ptr, 1 = arg0, ...)

MAX_DEPTH       = 200           # intra-function recursion guard
MAX_CALL_DEPTH  = 10            # interprocedural crossing limit

STOP_FUNCTIONS  = { "recv", "WSARecv", ... }   # tag as [EXTERNAL SOURCE] and stop
SKIP_FUNCTIONS  = { "il2cpp_gc_alloc", ... }   # ignore these callers
```

## Tested On

- Binary: `GameAssembly.dll` (il2cpp, x64)
- Ghidra 12.0 / Jython 2.7
- Trace path: `Socket_BeginSendCallback -> Socket_Send_internal -> Socket::Send -> SocketImpl::Send -> WS2_32::send`

## Directory Layout

```
08_tracing_Data_Origin/
├── scripts/
│   ├── backward_slicer.py
│   └── pcode_dumper.py
├── output/           # gitignored - place slicer JSON/CSV here for review
└── README.md
```
