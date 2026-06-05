# DB Builder Design Document

## 프로젝트 컨텍스트

### 목표
Ghidra Script (Jython 2.7) 기반 interprocedural backward slicer.  
`send()` 계열 함수의 버퍼 인자를 앵커로 잡아 함수 경계를 넘어 데이터 원점까지 역추적.

### 현재 방식의 문제
`backward_slicer.py`는 앵커에서 출발해 함수 경계를 만날 때마다 **런타임에 디컴파일**을 수행한다.

```
함수 경계 도달
  → getReferencesTo() XREF 수집
  → caller 함수 디컴파일 (DecompInterface)
  → CALL op에서 arg varnode 추출
  → 반복
```

같은 바이너리를 반복 분석하거나 앵커를 바꿀 때마다 동일한 디컴파일 비용이 발생한다.

### DB 방식의 목표
함수 경계 횡단 비용을 **일회성 전처리**로 분리한다.

```
[전처리] db_builder.py
  모든 함수 디컴파일 → call graph + param 매핑 → SQLite 저장

[실행]   backward_slicer.py (DB 모드)
  함수 내부: 기존과 동일 (High PCode varnode 추적)
  함수 경계: DB 쿼리 (디컴파일 없음)
```

---

## 추출 데이터 명세

### 1. call_edges — 함수 호출 시 인자 출처

함수 F가 G를 호출할 때, G의 각 파라미터가 F 내부에서 어디서 왔는지 분류한다.

```
caller        : F의 진입점 주소
call_site     : CALL op 주소
callee        : G의 진입점 주소
param_slot    : G의 파라미터 번호 (0-based)
src_type      : PARAM / LOAD / CONST / RETURN / STACK_PTR / UNKNOWN
src_detail    : "param[1]" / "param[0]+0x50" / "0x0" / "@0x181912960" 등
```

**src_type 분류 기준**

| src_type   | 조건                                              |
|------------|---------------------------------------------------|
| PARAM      | arg varnode가 F의 formal parameter에서 직접 옴   |
| LOAD       | arg varnode가 `LOAD [param[N]+offset]` 형태       |
| CONST      | arg varnode가 상수                                |
| RETURN     | arg varnode가 다른 CALL의 반환값 (RAX)            |
| STACK_PTR  | arg varnode가 `PTRSUB(RSP, offset)` — 스택 out-param |
| HEAP_PTR   | arg varnode가 힙/전역 객체 주소 — 힙 out-param   |
| CALL_FIELD | `PTRADD(CALL_result, idx, stride)` — 반환값의 필드 접근 |
| INDIRECT_CALL | 함수 포인터 경유 간접 호출 반환값               |
| UNKNOWN    | 위 패턴에 해당하지 않음                           |

### 2. out_params — 포인터로 받아서 내부에서 STORE하는 파라미터

스택과 힙/전역 객체 모두 포함한다.

```
func          : 함수 진입점
param_slot    : 포인터를 받는 파라미터 번호
param_kind    : STACK / HEAP / GLOBAL  — 어떤 종류의 포인터인지
store_src_type  : 위 src_type과 동일
store_src_detail: 저장되는 값의 출처
```

### 3. return_sources — 반환값 출처

```
func          : 함수 진입점
src_type      : PARAM / LOAD / CONST / CALL_RESULT / UNKNOWN
src_detail    : 구체적 출처
```

### 4. functions — 기본 정보

```
entry         : 진입점 주소 (TEXT, PK)
name          : 함수명
num_params    : 파라미터 수
is_external   : 외부 함수 여부 (STOP_FUNCTIONS 포함 여부)
```

---

## SQLite 스키마

```sql
CREATE TABLE functions (
    entry        TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    num_params   INTEGER DEFAULT 0,
    is_external  INTEGER DEFAULT 0   -- 1 = recv/ReadFile 등 STOP_FUNCTIONS
);

CREATE TABLE call_edges (
    caller       TEXT NOT NULL,
    call_site    TEXT NOT NULL,
    callee       TEXT NOT NULL,
    param_slot   INTEGER NOT NULL,
    src_type     TEXT NOT NULL,
    src_detail   TEXT DEFAULT ''
);

CREATE TABLE out_params (
    func             TEXT NOT NULL,
    param_slot       INTEGER NOT NULL,
    param_kind       TEXT DEFAULT 'STACK',  -- STACK / HEAP / GLOBAL
    store_src_type   TEXT NOT NULL,
    store_src_detail TEXT DEFAULT ''
);

CREATE TABLE return_sources (
    func        TEXT NOT NULL,
    src_type    TEXT NOT NULL,
    src_detail  TEXT DEFAULT ''
);

-- 간접 호출 반환값 추적: CALLIND로 얻은 반환값의 필드 접근 패턴
-- read_via_call(func, call_site, callee_fptr, field_offset) → src
CREATE TABLE indirect_call_fields (
    func         TEXT NOT NULL,   -- 해당 패턴이 나타나는 함수
    call_site    TEXT NOT NULL,   -- CALLIND 주소
    fptr_src     TEXT NOT NULL,   -- 함수 포인터 출처 (varnode 표현)
    field_offset TEXT NOT NULL,   -- PTRADD offset (반환값 + 몇 번째 필드)
    src_type     TEXT NOT NULL,
    src_detail   TEXT DEFAULT ''
);

-- 역방향 조회 인덱스 (interprocedural_step 대체용)
CREATE INDEX idx_callee_param      ON call_edges(callee, param_slot);
CREATE INDEX idx_caller            ON call_edges(caller);
CREATE INDEX idx_out_params        ON out_params(func, param_slot);
CREATE INDEX idx_collection_writes ON collection_writes(collection);
```

---

## 추출 방법 (db_builder.py)

### 전체 흐름

```
for func in all_functions:
    high = decompile(func)
    if high is None: continue

    extract_call_edges(func, high)   → call_edges
    extract_out_params(func, high)   → out_params
    extract_return_source(func, high) → return_sources

commit()
```

### classify_arg_source(arg_vn, high)

CALL op의 입력 varnode를 분류한다.

```
arg_vn.isConstant()               → CONST        / detail = "0x{val}"
arg_vn.getDef() == None           → PARAM        / detail = "param[N]"
def_op = LOAD [param[N]+offset]   → LOAD         / detail = "param[N]+0x{off}"
def_op = CALL (직접 호출 반환값)   → RETURN       / detail = "0x{callee_addr}"
def_op = PTRSUB(RSP, offset)      → STACK_PTR    / detail = "rsp+0x{off}"
def_op = PTRSUB(heap_obj, offset) → HEAP_PTR     / detail = "heap+0x{off}"
def_op = PTRADD(CALL_result, idx) → CALL_FIELD   / detail = "call@0x{addr}[{idx}]"
def_op = CALLIND (간접 호출 반환) → INDIRECT_CALL / detail = "fptr@{vn}"
else                              → UNKNOWN
```

### extract_out_params(func, high)

스택과 힙 객체 모두 처리한다.

```
# 스택 out-param: PTRSUB(RSP, offset) 를 통해 접근
# 힙 out-param: 전역/상수 주소를 포인터로 받아 STORE

for op in high.getPcodeOps():
    if op.getOpcode() != STORE: continue
    ptr_vn = op.getInput(1)

    # 스택 케이스
    param_slot = ptr_derives_from_param(ptr_vn, high)
    if param_slot >= 0:
        src = classify_arg_source(op.getInput(2), high)
        → out_params(func, param_slot, kind='STACK', ...) 저장
        continue

    # 힙/전역 케이스: ptr_vn이 상수 주소를 가리키는 경우
    global_addr = resolve_global_ptr_target(ptr_vn)
    if global_addr is not None:
        src = classify_arg_source(op.getInput(2), high)
        → out_params(func, param_slot=-1, kind='GLOBAL', detail=global_addr, ...) 저장
```

```
for op in high.getPcodeOps():
    if op.getOpcode() != STORE: continue
    ptr_vn = op.getInput(1)
    param_slot = ptr_derives_from_param(ptr_vn, high)  # 기존 _find_output_param_stores 로직 활용
    if param_slot < 0: continue
    src = classify_arg_source(op.getInput(2), high)
    → out_params에 저장
```

### 성능 고려

- 함수 수: GameAssembly.dll 기준 수만 개
- 예상 소요: 수 시간 (일회성)
- 진행 상황 로그: 1000함수마다 출력
- 에러 처리: 디컴파일 실패 함수는 건너뛰고 계속 진행
- 중간 저장: 배치(500개)마다 commit

---

## DB 사용 방법 — backward_slicer 통합

### interprocedural_step 대체

현재:
```
getReferencesTo(callee_entry) → caller 디컴파일 → CALL op arg 추출
```

DB 방식:
```sql
SELECT caller, call_site, src_type, src_detail
FROM call_edges
WHERE callee = ? AND param_slot = ?
```

`src_type = PARAM`이면 caller의 해당 param을 재귀 추적.  
`src_type = LOAD`이면 caller 내 LOAD 체인을 High PCode로 계속 추적.  
`src_type = CONST / RETURN`이면 source로 기록.

### handle_indirect 대체

현재:
```
callee 디컴파일 → STORE op 탐색 → 저장 값 추적
```

DB 방식:
```sql
SELECT store_src_type, store_src_detail
FROM out_params
WHERE func = ? AND param_slot = ?
```

---

## 하이브리드 동작 모드

DB가 있으면 DB 사용, 없으면 기존 런타임 방식 fallback.

```python
USE_DB = True
DB_PATH = os.path.join(OUTPUT_DIR, "GameAssembly_callgraph.db")

def interprocedural_step(vn, containing_func, param_slot, depth, ...):
    if USE_DB and os.path.exists(DB_PATH):
        return interprocedural_step_db(...)
    else:
        return interprocedural_step_runtime(...)   # 현재 방식
```

---

## 구현 순서

```
1단계  db_builder.py 작성
       - 전체 함수 순회 + call_edges 추출
       - classify_arg_source 구현
       - SQLite 저장
       - 실행 및 결과 검증

2단계  out_params / return_sources 추출 추가
       - _find_output_param_stores 로직 재활용
       - 배치 commit 성능 최적화

3단계  backward_slicer에 DB 모드 통합
       - interprocedural_step DB 버전 구현
       - handle_indirect DB 버전 구현
       - USE_DB 플래그로 모드 전환

4단계  검증
       - 기존 결과(runtime 모드)와 DB 모드 결과 비교
       - 누락 경로 / 추가 경로 분석
```

---

## 환경 제약

| 항목 | 제약 |
|------|------|
| 런타임 | Ghidra 12.0 / Jython 2.7 |

| 헤더 | `# @runtime Jython` 필수 |
| 인코딩 | 한글/em dash 등 non-ASCII 금지 |
| 출력 | `print()` 대신 `sys.stdout.write()` |
| 파일 쓰기 | `open("wb")` + `.encode("utf-8")` |
| 포맷 | `%` 포맷 사용 (`.format()` 금지) |
| SQLite | Jython 표준 라이브러리 `sqlite3` 사용 가능 확인 필요<br>불가 시 Java JDBC SQLite 드라이버 사용 |

### SKIP_FUNCTIONS (노이즈 제거)

분석 중 확인된 건너뛰어야 할 함수 패턴:

```python
SKIP_FUNCTIONS = {
    # il2cpp 런타임 초기화 — TypeInfo 전역 변수를 INDIRECT로 수정하지만 데이터 흐름 무관
    "il2cpp_codegen_initialize_runtime_metadata",
    "il2cpp_codegen_initialize_runtime_metadata_inline",
    # GC/메모리 관리
    "il2cpp_gc_alloc", "il2cpp_alloc",
    "il2cpp_object_new", "il2cpp_array_new",
    "GC_malloc", "GC_malloc_atomic",
    # 메모리 복사 (힙 write tracking 구현 시 별도 처리)
    "memcpy", "memmove", "memset",
}
```

DB 전처리 시 이 함수들이 callee로 나오면 해당 call_edge를 저장하지 않거나 `src_type = SKIP`으로 표시한다.

### SQLite Jython 호환성 주의

Jython 2.7은 CPython `sqlite3` 모듈을 지원하지 않을 수 있다.  
대안:
1. Java의 `sqlite-jdbc` JAR를 Ghidra 라이브러리에 추가 후 JDBC 사용
2. 또는 JSON 파일로 저장 후 외부 Python 3 스크립트로 SQLite 변환

---

## 디렉토리 구조

```
08_tracing_Data_Origin/
├── scripts/
│   ├── backward_slicer.py   -- 현재 동작 중인 슬라이서
│   ├── pcode_dumper.py      -- 디버깅용 PCode 덤퍼
│   └── db_builder.py        -- [미구현] DB 전처리 스크립트
├── output/
│   ├── GameAssembly.dll_slice.json
│   ├── GameAssembly.dll_chain.csv
│   ├── GameAssembly.dll_sources.csv
│   ├── pcode_dump_0x*.txt
│   └── GameAssembly_callgraph.db  -- [미생성] DB 파일
├── docs/
│   └── db_builder_design.md       -- 이 문서
└── README.md
```
