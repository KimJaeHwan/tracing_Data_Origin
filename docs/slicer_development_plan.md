# Slicer 개발 계획서

## 1. 배경 및 목적

### 1.1 현재 상황

`backward_slicer.py`는 실제 바이너리(GameAssembly.dll 등)에서 데이터 흐름을 역추적하기 위해
임시로 개발한 Ghidra GUI 스크립트다. 동작 자체는 검증됐으나 다음 한계가 있다.

- `ANCHOR_ADDRESS`: 분석 대상마다 수동으로 주소를 하드코딩해야 함
- `STOP_FUNCTIONS`: recv/ReadFile 등 실제 I/O 함수 고정 — 다른 용도에 재사용 불가
- 테스트 방법 없음: 슬라이서가 올바른 결과를 냈는지 검증할 수단이 없음
- GUI 전용: Script Manager에서만 실행 가능, 자동화 불가
- 반복 분석 비용: 함수 경계마다 그때그때 decompile → 동일 함수를 앵커가 바뀔 때마다 재처리

### 1.2 최종 목표

```
단계 목표:  slicer_core를 두 개의 테스트베드로 검증/강화한다.
장기 목표:  검증된 slicer_core를 엔진으로 삼아 함수별 데이터 흐름을
            사전 계산(Pre-computed Flow Graph)으로 구축하고,
            실제 분석을 빠른 그래프 탐색으로 대체한다.
```

---

## 2. 전체 아키텍처 (최종)

```
 ┌─────────────────────────────────────────────────────────────────┐
 │                        slicer_core.py                           │
 │                                                                 │
 │  run_slice()              backward_slice_impl()                 │
 │  interprocedural_step()   handle_indirect()                     │
 │  find_stores_to_stack_addr()   resolve_param_slot()             │
 │                                                                 │
 │  → 순수 PCode backward slice 엔진.                              │
 │    모든 상위 도구가 이 엔진을 공유한다.                          │
 └────┬──────────────┬───────────────────┬────────────────────────┘
      │              │                   │
      │         [검증/강화]          [사전 계산]
      │              │                   │
 ┌────▼────┐  ┌──────▼──────┐   ┌────────▼────────┐
 │dfbench  │  │ fiobench    │   │ graph_builder   │
 │_adapter │  │ _adapter    │   │ .py             │
 │         │  │             │   │                 │
 │경로 추적 │  │함수 I/O     │   │함수별 Flow Node │
 │PASS/FAIL│  │분류 검증    │   │사전 계산 및 저장│
 └────┬────┘  └──────┬──────┘   └────────┬────────┘
      │              │                   │
      ▼              ▼                   ▼
 DataFlowBench   FuncIOBench      flow_graph.json
 (09_tdo_testbed) (10_fio_testbed) (Pre-computed)
                                         │
                                 ┌───────▼────────┐
                                 │ analysis_      │
                                 │ adapter.py     │
                                 │                │
                                 │그래프 탐색으로 │
                                 │실전 분석 수행  │
                                 └───────┬────────┘
                                         │
                                 ┌───────▼────────┐
                                 │ ida_highlight  │
                                 │ .py            │
                                 │ (IDAPython)    │
                                 └────────────────┘
```

### 2.1 두 테스트베드의 역할 분담

| | DataFlowBench (DFB) | FuncIOBench (FIO) |
|---|---|---|
| **검증 대상** | slicer_core의 경로 추적 정확도 | slicer_core의 함수 I/O 분류 정확도 |
| **케이스 단위** | source → sink 전체 경로 | 함수 1개의 input/output 패턴 1가지 |
| **expected** | `{found_sources: [dfb_source_A, ...]}` | `{call_edges: [...], out_params: [...], return_sources: [...]}` |
| **graph_builder와의 관계** | 간접 — 경로 정확도가 Node 품질을 보장 | 직접 — Node 내용(I/O 분류)을 직접 검증 |
| **케이스 수** | 55개 (확정) | 미정 (약 80~100개 예상) |

---

## 3. 컴포넌트 상세 명세

### 3.1 slicer_core.py

**역할**: PCode 기반 backward slice 엔진. 모든 상위 도구가 공유하는 핵심 모듈.
slicer_core가 단단할수록 dfbench_adapter, fiobench_adapter, graph_builder 전부가 신뢰할 수 있다.

**Ghidra Jython 모듈**로 작성. `-scriptPath`로 지정된 디렉토리에 두면
같은 디렉토리 내 스크립트에서 `import slicer_core`로 사용 가능.

#### 공개 인터페이스

```python
def run_slice(anchor_op, arg_idx, func, config):
    """
    anchor_op : Ghidra PcodeOp  — 시작점 CALL/CALLIND op
    arg_idx   : int             — anchor_op의 몇 번째 인자를 추적할지
    func      : Ghidra Function — anchor가 속한 함수
    config    : SliceConfig
    returns   : SliceResult
    """

class SliceConfig:
    source_functions : set[str]  # 슬라이스 종료 — 이 함수 CALL을 소스로 기록
    stop_functions   : set[str]  # 즉시 종료 — EXTERNAL SOURCE 기록 후 중단
    skip_functions   : set[str]  # INDIRECT 처리 건너뜀 (memcpy 등)
    max_depth        : int       # 기본 200
    max_call_stack   : int       # 기본 10

class SliceResult:
    anchor_address : str
    anchor_arg_idx : int
    chain          : list[dict]  # op별 추적 기록
    sources        : list[dict]  # 종료 지점 목록
    found_sources  : set[str]    # source_functions 중 실제 도달한 함수명
    errors         : list[str]

    def to_json(self) -> dict
```

#### 핵심 내부 함수

- `_backward_slice_impl(vn, func, depth, state)` — 재귀 추적 본체
- `_interprocedural_step(vn, func, depth, state)` — 파라미터 → XREF caller 탐색
- `_handle_indirect(op, func, depth, state)` — INDIRECT op 처리
  - `_handle_indirect_stack()` — 스택 outparam
  - `_handle_indirect_heap()` — 힙/글로벌 outparam
- `_find_stores_to_stack_addr(func, offset, state)` — 스택 주소 STORE 탐색
- `_resolve_param_slot(vn, func)` — SSA hashCode 기반 파라미터 슬롯 식별

---

### 3.2 dfbench_adapter.py — DataFlowBench 연결 어댑터

**역할**: DataFlowBench 바이너리에서 slicer_core를 실행하고
expected.json과 비교해 경로 추적 PASS/FAIL 측정.

**실행 방식**: Ghidra Headless Analyzer

```bat
analyzeHeadless C:\ghidra_projects DFBench_WinCore ^
    -process dfbench_win_core.exe ^
    -postScript dfbench_adapter.py ^
    -scriptPath D:\01_gitproject\08_tracing_Data_Origin\scripts
```

#### 동작 흐름

```
1. expected.json 로드
2. SOURCE_FUNCTIONS = {dfb_source_A, dfb_source_B, dfb_source_C}
3. case_DFB* 함수 자동 발견 (심볼 prefix 검색)
4. 각 케이스 함수에서 dfb_sink_int CALL op 탐색 → anchor 설정
5. slicer_core.run_slice() 실행
6. result.found_sources vs. expected_sources 비교 → PASS/FAIL
7. output/dfbench_eval_result.json 출력
```

#### 출력 형식

```json
{
  "binary": "dfbench_win_core.exe",
  "summary": {"total": 50, "pass": 0, "fail": 0, "error": 0},
  "cases": [
    {
      "id": "DFB001",
      "verdict": "PASS",
      "expected_sources": ["dfb_source_A.ret"],
      "found_sources": ["dfb_source_A"],
      "slice": { }
    }
  ]
}
```

---

### 3.3 fiobench_adapter.py — FuncIOBench 연결 어댑터

**역할**: FuncIOBench 바이너리에서 각 함수의 I/O 분류가 올바른지 검증.
slicer_core의 함수 경계 처리 정확도를 측정한다.
graph_builder가 생성하는 Flow Node와 동일한 정보를 검증하는 셈이다.

**실행 방식**: Ghidra Headless Analyzer

```bat
analyzeHeadless C:\ghidra_projects FIOBench ^
    -process fiobench.exe ^
    -postScript fiobench_adapter.py ^
    -scriptPath D:\01_gitproject\08_tracing_Data_Origin\scripts
```

#### 동작 흐름

```
1. expected_records.json 로드 (FuncIOBench 레포의 expected/)
2. fio_* 함수 자동 발견
3. 각 함수에 대해 slicer_core로 I/O 분류 실행:
   - 각 파라미터에 대해 run_slice() 실행 → call_edges 분류
   - return value 역추적 → return_sources 분류
   - STORE op 탐색 → out_params 분류
4. 결과 vs. expected_records 비교 → PASS/FAIL
5. output/fiobench_eval_result.json 출력
```

#### FuncIOBench expected 형식

```json
{
  "function": "fio_param_to_return",
  "call_edges": [
    {
      "callee": "inner_func",
      "param_slot": 0,
      "src_type": "PARAM",
      "src_detail": "param[0]"
    }
  ],
  "out_params": [],
  "return_sources": [
    {"src_type": "PARAM", "src_detail": "param[0]"}
  ]
}
```

---

### 3.4 graph_builder.py — Pre-computed Flow Graph 구축기

**역할**: 바이너리 전체(또는 anchor 도달 가능 범위)에 대해
slicer_core를 함수별로 사전 실행하고, 결과를 Flow Node 그래프로 저장.
일회성 실행. 이후 모든 분석 쿼리는 이 그래프를 사용한다.

#### Flow Node 구조

```json
{
  "func_addr": "0x18190c2a0",
  "func_name": "PacketBuilder__Build",
  "param_count": 3,

  "flows": [
    {
      "from": {"type": "param",           "slot": 0},
      "to":   {"type": "return"},
      "confidence": "definite"
    },
    {
      "from": {"type": "param",           "slot": 1},
      "to":   {"type": "outparam",        "slot": 2, "field_offset": 4},
      "confidence": "definite"
    },
    {
      "from": {"type": "external_source", "func": "recv"},
      "to":   {"type": "return"},
      "confidence": "conditional"
    }
  ],

  "internal_sources": [
    {"func": "recv", "addr": "0x181901234"}
  ],

  "unresolved": [
    {"reason": "CALLIND", "addr": "0x181905678"}
  ],

  "coverage": "full"
}
```

`confidence`:
- `definite` — 항상 이 흐름이 존재
- `conditional` — 조건 분기에 따라 존재할 수 있음 (over-approx)
- `unknown` — 분석 실패

`coverage`:
- `full` — 함수 내부 전체 분석 완료
- `partial` — CALLIND 등으로 일부 미해결
- `failed` — decompile 실패

#### 구축 전략

```
전략 A (전체): 바이너리 모든 함수 순회
  → 시간 오래 걸리나 가장 완전한 그래프 생성

전략 B (도달 가능 범위): anchor 기준 backward reachability
  → send() XREF를 역으로 따라가며 도달 가능 함수만 처리
  → 전체의 10~30% 수준으로 범위 축소 가능

권장: 초기는 전략 B로 빠르게 구축,
     이후 분석 요구에 따라 범위 확장
```

#### 실행 방식

```bat
analyzeHeadless C:\ghidra_projects MyProject ^
    -process target.dll ^
    -postScript graph_builder.py "mode=reachable,anchor=send" ^
    -scriptPath D:\01_gitproject\08_tracing_Data_Origin\scripts
```

#### UNRESOLVED 처리 정책

```
우선순위 1: graph에서 해결 (graph 내 다른 Node로 연결)
우선순위 2: runtime fallback (analysis_adapter가 해당 Node만 slicer_core 실행)
우선순위 3: UNCERTAIN 표시 후 계속 (결과에 경고 포함)
```

---

### 3.5 analysis_adapter.py — 실전 분석 어댑터

**역할**: Pre-computed Flow Graph를 탐색하여 anchor → source 경로를 추출.
그래프로 해결 안 되는 UNRESOLVED Node는 slicer_core로 runtime fallback.

**실행 방식**: Ghidra Headless (graph가 없을 때 on-demand 빌드 포함)

#### 동작 흐름 (최종 시나리오)

```
1. anchor 설정 (anchor_function 이름으로 CALL 사이트 탐색)

2. anchor가 속한 함수 내부를 slicer_core로 역추적
   → 함수 경계(파라미터)에 도달 시:

3. flow_graph에서 해당 함수 Node 조회
   a. coverage=full + flows에 경로 있음
      → 그래프가 가리키는 param/source로 점프 (decompile 없음)
   b. internal_sources 있음
      → 추적 중인 데이터와 연결 여부 flows로 판단
      → 연결됨: 해당 source를 슬라이스 결과에 추가
   c. unresolved 있음
      → runtime fallback: slicer_core로 해당 함수 직접 분석
   d. Node 없음 (그래프 미구축 함수)
      → runtime fallback

4. param까지 도달 시 XREF로 모든 caller 탐색
   → 각 caller에 대해 2~3 반복

5. stop_functions 도달 시 종료 → EXTERNAL SOURCE 기록
```

#### 설정 파일 (analysis_config.json)

```json
{
  "anchor_function":  "send",
  "anchor_arg_idx":   1,
  "stop_functions":   ["recv", "WSARecv", "ReadFile", "recvfrom"],
  "skip_functions":   ["memcpy", "memmove", "memset", "il2cpp_array_new"],
  "flow_graph_path":  "output/target_flow_graph.json",
  "fallback_runtime": true,
  "output_dir":       "output"
}
```

---

### 3.6 ida_highlight.py — IDA Pro 하이라이팅

**역할**: analysis_adapter.py 출력 JSON을 IDA Pro에서 읽어 하이라이팅 적용.
Ghidra와 IDA의 image base 차이를 **심볼명 + 함수 내 오프셋**으로 해소.

```python
ea = idc.get_name_ea_simple("PacketBuilder__Build")
if ea != idc.BADADDR:
    target_ea = ea + entry["func_offset"]
    idc.set_color(target_ea, idc.CIC_ITEM, 0xAAFFAA)
```

| 색상 | 의미 |
|------|------|
| 빨강 (0xFF8080) | Anchor |
| 노랑 (0xFFFF88) | 일반 체인 op |
| 파랑 (0x88BBFF) | 함수 경계 crossing (INTERPROC) |
| 주황 (0xFFBB50) | outparam 처리 (INDIRECT→CALL) |
| 초록 (0x88E888) | 소스 도달 |
| 회색 (0xCCCCCC) | 사이클/깊이 제한 |
| 보라 (0xCC88FF) | 그래프 Node 조회로 건너뜀 (graph shortcut) |

---

## 4. FuncIOBench 테스트베드 설계

### 4.1 목적

slicer_core가 함수 경계에서 I/O를 올바르게 분류하는지 검증.
graph_builder가 생성하는 Flow Node의 정확도를 보장하는 단위 테스트 하네스.

### 4.2 케이스 분류 체계

케이스 = **src_type(분류 방식)** × **Subject(데이터 형태)** 조합

#### src_type (INPUT — call_edges)

| 분류 | 설명 |
|---|---|
| PARAM | 인자를 그대로 전달 |
| LOAD_PARAM | 포인터 인자 역참조 (`s->field`) |
| LOAD_LOAD | 이중 역참조 (`s->inner->field`) |
| LOAD_GLOBAL | 글로벌 변수 읽어서 전달 |
| CONST | 상수 전달 |
| RETURN | 다른 함수 반환값 전달 |
| STACK_PTR | 로컬 변수 주소 전달 (`&local`) |
| HEAP_PTR | 힙 객체 주소 전달 |
| ALLOC | malloc/new 결과 전달 |
| CALL_FIELD | 반환값의 필드 전달 (`bar()->field`) |
| INDIRECT_CALL | 함수 포인터 반환값 전달 |
| CAST_PARAM | param을 cast 후 전달 |
| PHI_PARAM | 조건 분기 거친 param 전달 |
| COMPUTED | param 연산 결과 전달 (`a + b`) |

#### src_type (OUTPUT — out_params / return_sources)

| 분류 | 설명 |
|---|---|
| RETURN_PARAM | param 그대로 반환 |
| RETURN_LOAD | 포인터 역참조 반환 |
| RETURN_CONST | 상수 반환 |
| RETURN_CALL | 다른 함수 반환값을 그대로 반환 |
| RETURN_PHI | 조건부 반환 (여러 source 가능) |
| RETURN_ALLOC | malloc/new 결과 반환 |
| OUTPARAM_STACK | 스택 outparam 쓰기 (`*out = x`) |
| OUTPARAM_FIELD | struct outparam 필드 쓰기 |
| OUTPARAM_MULTI | 복수 outparam 동시 쓰기 |
| GLOBAL_WRITE | 글로벌 변수 쓰기 |

#### Subject (추적 데이터 형태)

| # | Subject | 예시 |
|---|---|---|
| S1 | 스칼라 | `int x` |
| S2 | 스칼라 포인터 | `int *p` |
| S3 | 배열 base 포인터 | `int arr[]` |
| S4 | 배열 원소 값 | `arr[2]`, `arr[i]` |
| S5 | 구조체 포인터 | `MyStruct *s` |
| S6 | 구조체 필드 값 | `s->field` |
| S7 | 구조체 값 (by value) | sret / hidden pointer |
| S8 | void 포인터 | `void *buf` |
| S9 | 이중 포인터 | `int **pp` |
| S10 | size+pointer 쌍 | `(void *buf, size_t len)` |

### 4.3 DataFlowBench와의 관계

DFB 케이스들은 FIO 패턴을 **경로 중간에 내포**하고 있다.
FIO는 그 패턴을 **고립된 단일 함수**로 분리해 경계 분류만 검증한다.

```
DFB056 (arg_to_ret_summary): param[0] → return  [경로 전체 테스트]
FIO_RETURN_PARAM_S1:         param[0] → return  [경계 분류만 테스트]

→ 동일 패턴이나 검증 관점이 다름. 겹치지 않음.
```

DFB에 없어서 FIO에서 새로 필요한 패턴:
- LOAD_LOAD, ALLOC, CAST_PARAM, PHI_PARAM, COMPUTED (INPUT)
- RETURN_PHI, RETURN_ALLOC, OUTPARAM_MULTI (OUTPUT)
- S4 (배열 원소), S7 (sret), S9 (이중 포인터), S10 (buffer+len 쌍)

---

## 5. 레포지토리 레이아웃

### 5.1 이 레포 (08_tracing_Data_Origin)

```
08_tracing_Data_Origin/
├── scripts/
│   ├── slicer_core.py          ← [신규 Phase 1] 슬라이스 엔진
│   ├── dfbench_adapter.py      ← [신규 Phase 2] DataFlowBench 어댑터
│   ├── fiobench_adapter.py     ← [신규 Phase 3] FuncIOBench 어댑터
│   ├── graph_builder.py        ← [신규 Phase 5] Flow Graph 구축기
│   ├── analysis_adapter.py     ← [신규 Phase 6] 실전 분석 어댑터
│   ├── ida_highlight.py        ← [신규 Phase 6] IDA Pro 하이라이팅
│   │
│   ├── backward_slicer.py      ← [기존] 유지 (참조용 GUI 도구)
│   ├── highlight_slice.py      ← [기존] 유지
│   ├── summarize_slice.py      ← [기존] 유지
│   └── pcode_dumper.py         ← [기존] 유지
│
├── output/
└── docs/
    ├── slicer_development_plan.md
    ├── backward_slicer_dfbench_eval.md
    ├── db_builder_design.md
    └── output_guide.md
```

### 5.2 테스트베드 레포들

```
09_tdo_testbed/   ← DataFlowBench (기존, 경로 추적 검증용)
10_fio_testbed/   ← FuncIOBench   (신규, 함수 I/O 분류 검증용)
```

---

## 6. JSON 인터페이스

### 6.1 SliceResult (slicer_core 출력, 기존 포맷 확장)

```json
{
  "binary"         : "target.dll",
  "anchor_address" : "0x18190c2a0",
  "anchor_func"    : "PacketBuilder__Build",
  "anchor_arg_idx" : 0,
  "chain_count"    : 42,
  "source_count"   : 3,
  "found_sources"  : ["recv"],
  "chain": [
    {
      "op"          : "CALL",
      "address"     : "0x18190c2a0",
      "func_name"   : "PacketBuilder__Build",
      "func_offset" : 120,
      "depth"       : 2,
      "inputs"      : ["param:0:4:RAX"],
      "output"      : "tmp:0:4",
      "note"        : ""
    }
  ],
  "sources": [
    {"varnode": "tmp:0:4", "depth": 15, "note": "[EXTERNAL SOURCE] recv"}
  ]
}
```

### 6.2 Flow Node (graph_builder 출력)

```json
{
  "func_addr"   : "0x18190c2a0",
  "func_name"   : "PacketBuilder__Build",
  "param_count" : 3,
  "flows": [
    {
      "from"       : {"type": "param", "slot": 0},
      "to"         : {"type": "return"},
      "confidence" : "definite"
    },
    {
      "from"       : {"type": "external_source", "func": "recv"},
      "to"         : {"type": "return"},
      "confidence" : "conditional"
    }
  ],
  "internal_sources" : [{"func": "recv", "addr": "0x181901234"}],
  "unresolved"       : [{"reason": "CALLIND", "addr": "0x181905678"}],
  "coverage"         : "partial"
}
```

`confidence`: `definite` | `conditional` | `unknown`
`coverage`:   `full` | `partial` | `failed`

---

## 7. 개발 순서

```
Phase 1  slicer_core.py 작성
         backward_slicer.py 핵심 엔진을 SliceConfig/SliceResult 인터페이스로 재작성
         검증: GUI Script Manager에서 기존 결과와 비교

Phase 2  dfbench_adapter.py 작성
         DataFlowBench 50개 케이스 자동 평가
         검증: 예상 PASS 16개 기준으로 엔진 상태 측정

Phase 3  slicer_core.py 1차 개선
         FAIL/UNCERTAIN 케이스 분석 → 개선 가능한 것부터 수정
         우선순위: DFB024~026(글로벌), DFB040~045(구조체/배열), DFB053/057(sret)
         목표: PASS 30개 이상

Phase 4  FuncIOBench 테스트베드 구축 (10_fio_testbed)
         함수 I/O 패턴 케이스 설계 및 C 소스 작성
         expected_records.json 작성

Phase 5  fiobench_adapter.py 작성
         FuncIOBench 케이스별 I/O 분류 검증
         검증: slicer_core의 함수 경계 분류 정확도 측정
         → 여기서 slicer_core 2차 개선 반복

Phase 6  graph_builder.py 작성
         함수별 Flow Node 사전 계산 및 저장
         검증: fiobench_adapter가 검증한 I/O 분류 = graph_builder Node 내용 일치

Phase 7  analysis_adapter.py + ida_highlight.py 작성
         그래프 탐색 기반 실전 분석 파이프라인 완성
         UNRESOLVED 시 slicer_core runtime fallback
```

### Phase별 slicer_core 품질 목표

| Phase | 목표 | 측정 지표 |
|---|---|---|
| Phase 1 | 기존 backward_slicer.py와 동등 | 수동 대조 |
| Phase 2 | DFB PASS 16개 이상 확인 | dfbench_adapter 결과 |
| Phase 3 | DFB PASS 30개 이상 | dfbench_adapter 결과 |
| Phase 5 | FIO PASS 80% 이상 | fiobench_adapter 결과 |
| Phase 6 | graph_builder UNKNOWN 비율 20% 이하 | coverage 통계 |

---

## 8. 기존 도구와의 관계

| 파일 | 상태 | 비고 |
|------|------|------|
| `backward_slicer.py` | 유지 | GUI용 실전 도구. slicer_core 개발 참조 소스. |
| `highlight_slice.py` | 유지 | Ghidra GUI 하이라이팅. analysis_adapter 결과에도 활용 가능. |
| `summarize_slice.py` | 유지 | JSON → Markdown 리포트. 출력 포맷 호환 유지. |
| `pcode_dumper.py` | 유지 | 디버깅 보조 도구. |
| `db_builder_design.md` | 참조 | graph_builder 설계 시 참고. 기존 DB 스키마는 Flow Node 구조로 흡수. |

---

## 9. 실행 환경 요구사항

| 항목 | 내용 |
|------|------|
| Ghidra | 10.x 이상 (High PCode API 필요) |
| 실행 방식 | Headless Analyzer (`analyzeHeadless`) |
| Python 런타임 | Jython 2.7 (Ghidra 내장) |
| IDA Pro | 7.x 이상 (ida_highlight.py용) |
| DFB 바이너리 | `09_tdo_testbed/build/win-debug/dfbench_win_core.exe` |
| FIO 바이너리 | `10_fio_testbed/build/win-debug/fiobench.exe` (Phase 4에서 구축) |

> Ghidra headless에서 `-scriptPath`로 지정된 디렉토리가 Jython `sys.path`에
> 자동 추가되므로 `import slicer_core`가 동작한다.
