# Backward Slice Summary

| Key | Value |
|-----|-------|
| Binary       | GameAssembly.dll |
| Anchor       | 0x180410e26  in[1] |
| Chain ops    | 38 |
| Sources      | 10 |

---

## 1. Function Call Flow (Tree)

```
anchor  0x180410e26  in[1]
▲ INTERPROC  ClientSocket_SendPacket_m68C1B768E4A4D63C2...
          → ClientSocket_HandleSendPacket_m4B08B9DAD7C...  param[0]  arg=RCX  @0x1804126db
  [branch 1] ▲ INTERPROC  PacketBuilder_FlushWithWaitingResponsePack...  
            → ClientSocket_SendPacket_m68C1B768E4A4D63C2...  param[0]  arg=tmp:0x10000715  @0x18062252f
  [branch 2] ▲ INTERPROC  PacketBuilder_Flush_mD411D32F93974B7476661...  
            → ClientSocket_SendPacket_m68C1B768E4A4D63C2...  param[0]  arg=tmp:0x10000110  @0x180622783
  [branch 3] ▲ INTERPROC  PacketBuilder_Flush_m9C449297749F469960CE5...  
            → ClientSocket_SendPacket_m68C1B768E4A4D63C2...  param[0]  arg=tmp:0x10000091  @0x1806226b6
▲ INTERPROC  ClientSocket_FlushReservedNGSPacket_mCA4DC...
          → ClientSocket_HandleSendPacket_m4B08B9DAD7C...  param[0]  arg=RCX  @0x180410a80
  ▲ INTERPROC  ClientSocket_Update_mDAF01584BB8BCA1D792E1...  [BLOCKED-no-callers]
            → ClientSocket_FlushReservedNGSPacket_mCA4DC...  param[0]  arg=RCX  @0x180413144
```

### Legend
- `▼ INDIRECT` : callee 가 포인터 arg 를 통해 내 스택 변수를 **채워줌** (아래로 진입)
- `▲ INTERPROC`: 현재 함수의 파라미터를 **누가 넘겼는지** caller 탐색 (위로 추적)
- `[branch N]` : 동일 depth 에서 갈라진 독립 브랜치 (DFS 순서로 나열)

---

## 2. Notable PCode Operations

### Memory Reads (LOAD)

| Depth | Address | Pointer | Result |
|-------|---------|---------|--------|
| 1 | 0x180410e19 | tmp:0x10000455 | tmp:0x11f00 |
| 7 | 0x180410d48 | tmp:0x4880 | tmp:0x100003e1 |
| 12 | 0x180622515 | tmp:0x1000070d | tmp:0x11f00 |
| 12 | 0x180622763 | tmp:0x10000108 | tmp:0x11f00 |
| 12 | 0x18062269b | tmp:0x10000089 | tmp:0x11f00 |

### Address Calculations (PTRSUB / PTRADD)

| Depth | Address | Op | Base | Offset | Result |
|-------|---------|-----|------|--------|--------|
| 2 | 0x180410e19 | PTRSUB | tmp:0x1000026e | const:0x0 | tmp:0x10000455 |
| 3 | 0x180410e19 | PTRSUB | tmp:0x4780 | const:0x0 | tmp:0x1000026e |
| 4 | 0x180410e19 | PTRADD | RAX | const:0x1 | tmp:0x4780 |
| 8 | 0x180410d48 | PTRSUB | RCX | const:0x98 | tmp:0x4880 |
| 13 | 0x180622515 | PTRSUB | tmp:0x1000058e | const:0x0 | tmp:0x1000070d |
| 14 | 0x180622515 | PTRSUB | tmp:0x4880 | const:0x0 | tmp:0x1000058e |
| 15 | 0x180622515 | PTRADD | RAX | const:0xb | tmp:0x4880 |
| 13 | 0x180622763 | PTRSUB | tmp:0x100000d0 | const:0x0 | tmp:0x10000108 |
| 14 | 0x180622763 | PTRSUB | tmp:0x4880 | const:0x0 | tmp:0x100000d0 |
| 15 | 0x180622763 | PTRADD | RAX | const:0xb | tmp:0x4880 |
| 13 | 0x18062269b | PTRSUB | tmp:0x10000069 | const:0x0 | tmp:0x10000089 |
| 14 | 0x18062269b | PTRSUB | tmp:0x4880 | const:0x0 | tmp:0x10000069 |
| 15 | 0x18062269b | PTRADD | RAX | const:0xb | tmp:0x4880 |

### Direct Calls (CALL)

| Depth | Address | Target | Result |
|-------|---------|--------|--------|
| 5 | 0x180410d5f | mem@ram+0x180ad9720 | RAX |
| 16 | 0x1806224fe | mem@ram+0x180b870b0 | RAX |
| 16 | 0x180622754 | mem@ram+0x180b870b0 | RAX |
| 16 | 0x18062268c | mem@ram+0x180b870b0 | RAX |

---

## 3. Data Sources

### Register Sources  _(caller must be traced further)_

| Depth | Register | Note |
|-------|----------|------|
| 11 | `RCX` | no callers - root source in ClientSocket_Update_mDAF01584BB8BCA1D792E10CD8DE6AFEDBB09F54A param[0] |

### Global / Heap Sources

| Depth | Address | Note |
|-------|---------|------|
| 18 | `mem@ram+0x182f48238` | heap/global INDIRECT - callee not resolved |
| 8 | `mem@ram+0x182f3c928` |  |

---

## 4. Cycle / Depth-Limit Hits

None.

---

## 5. Raw Sources List

| Depth | Varnode | Category | Note |
|-------|---------|----------|------|
| 18 | `mem@ram+0x182f48238` | MEM | heap/global INDIRECT - callee not resolved |
| 18 | `mem@ram+0x182f48238` | MEM | heap/global INDIRECT - callee not resolved |
| 18 | `mem@ram+0x182f48238` | MEM | heap/global INDIRECT - callee not resolved |
| 18 | `mem@ram+0x182f48238` | MEM | heap/global INDIRECT - callee not resolved |
| 18 | `mem@ram+0x182f48238` | MEM |  |
| 18 | `mem@ram+0x182f48238` | MEM | heap/global INDIRECT - callee not resolved |
| 11 | `RCX` | REG | no callers - root source in ClientSocket_Update_mDAF01584BB8BCA1D792E10CD8DE6AFEDBB09F54A param[0] |
| 8 | `mem@ram+0x182f3c928` | MEM |  |
| 8 | `mem@ram+0x182f3c928` | MEM | heap/global INDIRECT - callee not resolved |
| 7 | `mem@ram+0x182f3c928` | MEM | heap/global INDIRECT - callee not resolved |
