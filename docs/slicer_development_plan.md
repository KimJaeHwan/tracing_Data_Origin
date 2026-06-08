# Slicer 개발 계획서

## 1. 배경 및 목적

### 1.1 현재 상황

`backward_slicer.py`는 실제 바이너리(GameAssembly.dll 등)에서 데이터 흐름을 역추적하기 위해
임시로 개발한 Ghidra GUI 스크립트다. 동작 자체는 검증됐으나 다음 한계가 있다.

- `ANCHOR_ADDRESS`: 분석 대상마다 수동으로 주소를 하드코딩해야 함
- `STOP_FUNCTIONS`: recv/ReadFile 등 실제 I/O 함수 고정 — 다른 용도에 재사용 불가
- 테스트 방법 없음: 슬라이서가 올바른 결과를 냈는지 검증할 수단이 없음
- GUI 전용: Script Manager에서만 실행 가능, 자동화 불가

### 1.2 목표

```
slicer_core.py 를 테스트베드(09_tdo_testbed)로 검증/강화하여
실전 바이너리 분석에 적용할 수 있는 신뢰할 수 있는 엔진을 만든다.
```

테스트베드(DataFlowBench, DFB)는 55개의 명확한 정답(expected.json)이 있는 바이너리를 제공한다.
dfbench_adapter가 이 바이너리를 slicer_core에 연결해 케이스별 PASS/FAIL을 측정한다.
slicer_core가 충분히 단단해지면 analysis_adapter를 통해 실전 바이너리에 적용한다.

---

## 2. 전체 아키텍처

```
┌──────────────────────────────────────────────────────────────────┐
│                         slicer_core.py                           │
│                                                                  │
│  backward_slice_impl()    interprocedural_step()                 │
│  handle_indirect()        find_stores_to_stack_addr()            │
│  resolve_param_slot()     ...                                    │
│                                                                  │
│  → 순수 슬라이스 엔진. 특정 바이너리/도구에 무관하게 동작.       │
│    JSON 직렬화 가능한 SliceResult 반환.                          │
└─────────────────┬────────────────────────┬───────────────────────┘
                  │                        │
    ┌─────────────▼──────────┐  ┌──────────▼───────────────────┐
    │   dfbench_adapter.py   │  │    analysis_adapter.py        │
    │   (테스트베드 연결)     │  │    (실전 바이너리 분석)        │
    │                        │  │                               │
    │ SOURCE_FUNCTIONS =     │  │ STOP_FUNCTIONS = I/O 함수들   │
    │   dfb_source_A/B/C     │  │ ANCHOR = 설정파일 or 수동 지정 │
    │                        │  │                               │
    │ · case_DFB* 자동 순회  │  │ · 단일 슬라이스 실행           │
    │ · dfb_sink_int 자동 탐색│  │ · JSON 출력                   │
    │ · expected.json 비교   │  │ · IDA 하이라이팅 연동          │
    │ · PASS/FAIL 리포트 출력│  │                               │
    └────────────────────────┘  └───────────────────────────────┘
              ▲                              ▲
    dfbench_win_core.exe              실제 분석 대상 바이너리
    (Ghidra headless)                 (Ghidra headless)
                                            │
                                            ▼
                                   ida_highlight.py
                                   (IDA Pro IDAPython)
                                   · JSON 읽어 EA 해석
                                   · set_color() 하이라이팅
```

---

## 3. 레포지토리 레이아웃

### 3.1 이 레포 (08_tracing_Data_Origin)

```
08_tracing_Data_Origin/
├── scripts/
│   ├── slicer_core.py          ← [신규] 슬라이스 엔진 (Ghidra Jython)
│   ├── dfbench_adapter.py      ← [신규] 테스트베드 어댑터 (Ghidra Jython)
│   ├── analysis_adapter.py     ← [신규] 실전 분석 어댑터 (Ghidra Jython)
│   ├── ida_highlight.py        ← [신규] IDA Pro 하이라이팅 (IDAPython)
│   │
│   ├── backward_slicer.py      ← [기존] 유지 (참조용, 실전 GUI 도구)
│   ├── highlight_slice.py      ← [기존] Ghidra GUI 하이라이팅 (유지)
│   ├── summarize_slice.py      ← [기존] JSON → Markdown 리포트 (유지)
│   └── pcode_dumper.py         ← [기존] PCode 덤프 도구 (유지)
│
├── output/                     ← 슬라이스 결과 JSON 출력 디렉토리
└── docs/
    ├── slicer_development_plan.md  ← 이 문서
    ├── db_builder_design.md
    └── output_guide.md
```

### 3.2 테스트베드 레포 (09_tdo_testbed) — 읽기 전용 참조

```
09_tdo_testbed/
├── build/win-debug/
│   └── dfbench_win_core.exe    ← dfbench_adapter의 분석 대상
├── expected/
│   └── dfbench_win_core.expected.json  ← PASS/FAIL 판정 기준
└── manifests/
    └── cases_manifest.json     ← 케이스 메타데이터
```

---

## 4. 컴포넌트 상세 명세

### 4.1 slicer_core.py

**역할**: PCode 기반 backward slice 엔진. 호출자(어댑터)가 설정을 주입하고 결과를 받아간다.

**Ghidra Jython 모듈**로 작성. 어댑터에서 `execfile()` 또는 같은 scripts 디렉토리에 두고
`sys.path` 경유로 import.

#### 주요 함수 (공개 인터페이스)

```python
def run_slice(anchor_op, arg_idx, func, config):
    """
    anchor_op : Ghidra PcodeOp  — 시작점이 되는 CALL/CALLIND op
    arg_idx   : int             — anchor_op의 몇 번째 인자를 추적할지
    func      : Ghidra Function — anchor가 속한 함수
    config    : SliceConfig     — SOURCE_FUNCTIONS, STOP_FUNCTIONS 등
    returns   : SliceResult
    """

class SliceConfig:
    source_functions  : set[str]   # 슬라이스 종료 조건 — 이 함수 CALL을 만나면 소스로 기록
    stop_functions    : set[str]   # 즉시 종료 — EXTERNAL SOURCE 기록 후 중단
    skip_functions    : set[str]   # 무시 — INDIRECT 처리 건너뜀 (memcpy 등)
    max_depth         : int        # 기본 200
    max_call_stack    : int        # 기본 10

class SliceResult:
    anchor_address  : str          # hex string
    anchor_arg_idx  : int
    chain           : list[dict]   # op별 추적 기록 (기존 포맷 유지)
    sources         : list[dict]   # 종료 지점 목록
    found_sources   : set[str]     # source_functions 중 실제로 도달한 함수명
    errors          : list[str]    # 처리 중 예외/경고 메시지

    def to_json(self) -> dict      # 직렬화
```

#### 핵심 내부 함수 (private)

- `_backward_slice_impl(vn, func, depth, state)` — 재귀 추적 본체
- `_interprocedural_step(vn, func, depth, state)` — 파라미터 → XREF 기반 caller 탐색
- `_handle_indirect(op, func, depth, state)` — INDIRECT op 처리
  - `_handle_indirect_stack()` — 스택 outparam
  - `_handle_indirect_heap()` — 힙/글로벌 outparam
- `_find_stores_to_stack_addr(func, offset, state)` — 스택 주소의 STORE 탐색
- `_resolve_param_slot(vn, func)` — SSA hashCode로 파라미터 슬롯 식별

> **backward_slicer.py와의 관계**
> slicer_core.py는 backward_slicer.py의 핵심 로직을 정리/재작성한 것이다.
> backward_slicer.py는 기존대로 독립적으로 유지하며 건드리지 않는다.

---

### 4.2 dfbench_adapter.py

**역할**: DataFlowBench 바이너리를 대상으로 slicer_core를 실행하고
expected.json과 비교해 PASS/FAIL을 판정한다.

**실행 방식**: Ghidra Headless Analyzer

```bat
analyzeHeadless C:\ghidra_projects DFBench_WinCore ^
    -import D:\01_gitproject\09_tdo_testbed\build\win-debug\dfbench_win_core.exe ^
    -postScript dfbench_adapter.py ^
    -scriptPath D:\01_gitproject\08_tracing_Data_Origin\scripts ^
    -log dfbench_eval.log
```

또는 이미 분석된 프로젝트가 있을 경우:

```bat
analyzeHeadless C:\ghidra_projects DFBench_WinCore ^
    -process dfbench_win_core.exe ^
    -postScript dfbench_adapter.py ^
    -scriptPath D:\01_gitproject\08_tracing_Data_Origin\scripts
```

#### 동작 흐름

```
1. expected.json 로드
   └─ D:\01_gitproject\09_tdo_testbed\expected\dfbench_win_core.expected.json

2. SOURCE_FUNCTIONS = {"dfb_source_A", "dfb_source_B", "dfb_source_C"}
   STOP_FUNCTIONS   = {}  (dfbench에서는 사용 안 함)
   SKIP_FUNCTIONS   = {"memcpy", "memmove", "memset"}

3. case_DFB* 함수 자동 발견
   └─ currentProgram.getFunctionManager()에서 이름이 "case_DFB"로 시작하는 함수 열거

4. 각 케이스 함수에 대해:
   a. 함수 내 PCode에서 dfb_sink_int / dfb_sink_str CALL op 탐색
   b. anchor_op = 해당 CALL, arg_idx = 0 (첫 번째 데이터 인자)
   c. slicer_core.run_slice(anchor_op, arg_idx, func, config) 실행
   d. result.found_sources vs. expected_sources 비교
      - found_sources ⊇ expected_sources  AND
        found_sources ∩ forbidden_sources = ∅
        → PASS
      - 그 외 → FAIL

5. 결과 출력
   └─ output/dfbench_eval_result.json   (케이스별 PASS/FAIL + 상세 체인)
   └─ stdout: 진행 상황 및 요약 테이블
```

#### 출력 형식 (dfbench_eval_result.json)

```json
{
  "binary": "dfbench_win_core.exe",
  "timestamp": "2026-06-08T...",
  "summary": {"total": 50, "pass": 16, "fail": 20, "error": 5, "uncertain": 9},
  "cases": [
    {
      "id": "DFB001",
      "name": "direct_value",
      "verdict": "PASS",
      "expected_sources": ["dfb_source_A.ret"],
      "found_sources": ["dfb_source_A"],
      "forbidden_sources": [],
      "found_forbidden": [],
      "chain_count": 3,
      "error": null,
      "slice": { ... }   // SliceResult.to_json()
    },
    ...
  ]
}
```

---

### 4.3 analysis_adapter.py

**역할**: 실제 분석 대상 바이너리에 slicer_core를 적용한다.
설정 파일 또는 스크립트 인자로 ANCHOR와 SOURCE/STOP 함수를 지정받는다.

**실행 방식**: Ghidra Headless Analyzer (또는 GUI Script Manager)

```bat
analyzeHeadless C:\ghidra_projects MyProject ^
    -process target.dll ^
    -postScript analysis_adapter.py "config=analysis_config.json" ^
    -scriptPath D:\01_gitproject\08_tracing_Data_Origin\scripts
```

#### 설정 파일 (analysis_config.json)

```json
{
  "anchor_function": "send",
  "anchor_arg_idx": 1,
  "stop_functions": ["recv", "WSARecv", "ReadFile", "ReadFileEx",
                     "recvfrom", "recvmsg", "WSARecvFrom"],
  "skip_functions": ["memcpy", "memmove", "memset",
                     "il2cpp_array_new", "GC_malloc"],
  "source_functions": [],
  "max_depth": 200,
  "max_call_stack": 10,
  "output_dir": "output"
}
```

#### 동작 흐름

```
1. 설정 파일 로드
2. anchor_function 이름으로 모든 CALL 사이트 탐색 (XREF 활용)
   └─ 여러 call site가 있는 경우 전체 실행 (또는 필터링)
3. 각 call site에 대해 slicer_core.run_slice() 실행
4. 결과 JSON 저장 → output/{binary}_{anchor}_{addr}_slice.json
5. IDA 하이라이팅용 데이터 포함 (함수명 + 함수 내 오프셋)
```

#### 출력에 포함되는 IDA 주소 정보

기존 `highlight_slice.py`는 Ghidra 절대 주소를 사용했다.
`analysis_adapter.py`는 IDA에서 재사용 가능하도록 **함수명 + 오프셋** 형식도 함께 출력한다.

```json
{
  "chain": [
    {
      "op": "CALL",
      "address": "0x18190c2a0",
      "func_name": "PacketBuilder__Build",
      "func_offset": 120,
      ...
    }
  ]
}
```

---

### 4.4 ida_highlight.py

**역할**: analysis_adapter.py가 출력한 JSON을 IDA Pro에서 읽어 하이라이팅 적용.

**실행 방식**: IDA Pro IDAPython (`File → Script file`)

#### 주소 매핑 전략

IDA와 Ghidra의 image base가 다를 수 있으므로 **심볼 이름 + 함수 내 오프셋** 기반으로 매핑.

```python
# 예시
ea = idc.get_name_ea_simple("PacketBuilder__Build")
if ea != idc.BADADDR:
    target_ea = ea + entry["func_offset"]
    idc.set_color(target_ea, idc.CIC_ITEM, 0xAAFFAA)  # light green
```

#### 컬러 규칙

| 색상 | 의미 |
|------|------|
| 빨강 (0xFF8080) | Anchor — 슬라이스 시작점 |
| 노랑 (0xFFFF88) | 일반 체인 op |
| 파랑 (0x88BBFF) | 함수 경계 crossing (INTERPROC) |
| 주황 (0xFFBB50) | outparam 처리 (INDIRECT→CALL) |
| 초록 (0x88E888) | 소스 도달 (SOURCE_FUNCTIONS hit) |
| 회색 (0xCCCCCC) | 사이클/깊이 제한 |

---

## 5. JSON 인터페이스 (슬라이스 결과 포맷)

slicer_core, dfbench_adapter, analysis_adapter가 공유하는 공통 포맷.
기존 backward_slicer.py 출력 포맷을 기준으로 확장.

```
{
  "binary"         : str,          // 바이너리 파일명
  "anchor_address" : str,          // hex — Ghidra 절대 주소
  "anchor_func"    : str,          // 앵커가 속한 함수 이름
  "anchor_arg_idx" : int,          // 추적한 인자 인덱스
  "chain_count"    : int,
  "source_count"   : int,
  "found_sources"  : [str],        // SOURCE_FUNCTIONS 중 실제 도달한 함수명
  "chain": [
    {
      "op"          : str,         // PCode op 이름 or 특수 레이블
      "address"     : str,         // hex
      "func_name"   : str,         // 해당 주소가 속한 함수 이름
      "func_offset" : int,         // 함수 시작으로부터의 바이트 오프셋
      "depth"       : int,
      "inputs"      : [str],       // varnode 문자열
      "output"      : str,
      "note"        : str
    }
  ],
  "sources": [
    {
      "varnode" : str,
      "depth"   : int,
      "note"    : str
    }
  ]
}
```

---

## 6. 개발 순서

### Phase 1 — slicer_core.py 작성

목표: backward_slicer.py의 핵심 엔진을 SliceConfig/SliceResult 인터페이스로 재작성.

1. SliceConfig, SliceResult 클래스 정의
2. `_backward_slice_impl()` 이식 (SOURCE_FUNCTIONS 종료 조건 추가)
3. `_interprocedural_step()` 이식
4. `_handle_indirect()` (stack + heap) 이식
5. `_find_stores_to_stack_addr()` 이식
6. `run_slice()` 공개 진입점 작성
7. `to_json()` 직렬화에 `func_name`, `func_offset` 필드 추가

검증: Ghidra GUI Script Manager에서 slicer_core를 직접 import해 기존
backward_slicer.py와 동일한 결과가 나오는지 확인.

### Phase 2 — dfbench_adapter.py 작성

목표: 테스트베드 50개 케이스 자동 평가.

1. case_DFB* 함수 자동 발견 로직
2. dfb_sink_int CALL op 탐색
3. expected.json 로드 + 비교 판정
4. dfbench_eval_result.json 출력
5. stdout 요약 테이블 출력

검증: Phase 1 평가표 (PASS 16개 / FAIL 20개 / UNCERTAIN 19개)와
실제 결과를 비교하여 slicer_core의 능력/한계를 수치로 확인.

### Phase 3 — slicer_core.py 개선

목표: dfbench_adapter 결과에서 FAIL/UNCERTAIN 케이스를 분석하여
개선 가능한 것부터 수정.

우선순위 (UNCERTAIN → PASS 전환 가능성 높은 것):
1. `DFB024~026` 글로벌 변수 흐름 — INDIRECT heap 로직 개선
2. `DFB040~045` 구조체/배열 상수 오프셋 — PTRSUB 체인 추적 개선
3. `DFB053, 057` 구조체 반환/필드 요약 — hidden pointer 처리
4. `DFB052` 컨텍스트 비민감 — over-approximation 허용 여부 결정

### Phase 4 — analysis_adapter.py + ida_highlight.py 작성

목표: slicer_core가 충분히 검증된 후 실전 바이너리 분석 파이프라인 완성.

1. analysis_config.json 설계 및 파싱
2. CALL site 자동 탐색 (XREF 기반)
3. 결과 JSON에 func_name + func_offset 포함
4. ida_highlight.py — 심볼명 기반 주소 매핑 + set_color()

---

## 7. 기존 도구와의 관계

| 파일 | 상태 | 비고 |
|------|------|------|
| `backward_slicer.py` | 유지 | GUI용 실전 도구로 현행 유지. slicer_core 개발 시 참조 소스. |
| `highlight_slice.py` | 유지 | Ghidra GUI 하이라이팅. analysis_adapter 결과에도 사용 가능. |
| `summarize_slice.py` | 유지 | JSON → Markdown 리포트. 출력 포맷 호환 유지. |
| `pcode_dumper.py` | 유지 | 디버깅 보조 도구. |

---

## 8. 실행 환경 요구사항

| 항목 | 내용 |
|------|------|
| Ghidra 버전 | 10.x 이상 (High PCode API 필요) |
| Ghidra 실행 방식 | Headless Analyzer (`analyzeHeadless`) |
| Python 런타임 | Jython 2.7 (Ghidra 내장) |
| IDA Pro | 7.x 이상 (IDAPython 지원) |
| 테스트베드 바이너리 | `09_tdo_testbed/build/win-debug/dfbench_win_core.exe` (Debug 빌드, 심볼 있음) |

> Ghidra headless에서 같은 `scripts/` 디렉토리에 있는 `.py` 파일은
> `sys.path`에 자동 추가되므로 `import slicer_core` 가 동작한다.
> (단, Ghidra가 실행 중인 JVM의 Jython classpath에 해당 디렉토리가 포함되어야 한다.
> `-scriptPath` 인자로 명시적으로 지정 권장.)
