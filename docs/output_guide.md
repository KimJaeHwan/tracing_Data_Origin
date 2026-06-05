# 결과 파일 읽는 방법

backward_slicer.py 실행 후 `output/` 폴더에 생성되는 파일들의 구조와 해석 방법.

---

## 파일 목록

```
output/
  <binary>_slice.json     -- 전체 분석 결과 (메인 파일)
  <binary>_chain.csv      -- 체인 ops 목록
  <binary>_sources.csv    -- 데이터 원점 목록
  <binary>_summary.md     -- 요약 리포트 (summarize_slice.py 생성)
  pcode_dump_0x<addr>.txt -- PCode 덤프 (pcode_dumper.py 생성)
```

---

## 1. _slice.json 구조

```json
{
  "binary":         "GameAssembly.dll",
  "anchor_address": "0x18190c492",
  "anchor_arg_idx": 2,
  "chain_count":    120,
  "source_count":   9,
  "chain":  [ ... ],
  "sources": [ ... ]
}
```

### chain 배열 — 추적 경로

앵커에서 출발해 역방향으로 거친 모든 PCode op.

```json
{
  "depth":   0,
  "address": "0x18190c40c",
  "op":      "COPY",
  "inputs":  ["stack:0x-a8"],
  "output":  "tmp:0x100004c2",
  "note":    ""
}
```

| 필드 | 설명 |
|------|------|
| `depth` | 앵커에서 PCode op 역추적 횟수. 낮을수록 앵커에 가까움 |
| `address` | 해당 PCode op의 명령어 주소 (Ghidra에서 직접 이동 가능) |
| `op` | PCode 연산자 또는 슬라이서 특수 연산자 |
| `inputs` | 입력 varnode 목록 |
| `output` | 출력 varnode |
| `note` | 슬라이서가 추가한 설명 |

**슬라이서 특수 op**

| op | 의미 |
|----|------|
| `INTERPROC_CALL` | 함수 경계를 위로 횡단 (파라미터 → caller 탐색) |
| `INDIRECT->CALL` | out-param callee로 아래 진입 (포인터로 받아 내부 STORE) |
| `CYCLE` | 이미 방문한 varnode — 루프 감지 후 중단 |
| `DEPTH_LIMIT` | MAX_DEPTH 초과 |
| `INDIRECT(fallback)` | 스택 INDIRECT callee 미해결 — pre-call 값으로 대체 추적 |

### sources 배열 — 데이터 원점

추적이 멈춘 말단 노드 목록.

```json
{
  "depth":    11,
  "varnode":  "RDX",
  "is_reg":   true,
  "is_stack": false,
  "note":     "no callers - root source in FuncName param[1]"
}
```

| note 패턴 | 의미 |
|-----------|------|
| `(빈 문자열)` | 정의 op 없고 파라미터도 아닌 varnode (전역/힙) |
| `no callers - root source in Func param[N]` | 파라미터인데 해당 함수 caller 없음 (가상 디스패치 등) |
| `[EXTERNAL SOURCE] recv param[N]` | STOP_FUNCTIONS에 걸린 외부 I/O 함수 |
| `call stack depth limit reached` | MAX_CALL_STACK_DEPTH 초과 |
| `heap/global INDIRECT - callee not resolved` | 힙 객체 INDIRECT callee 미해결 |

---

## 2. _chain.csv 구조

JSON의 chain 배열을 CSV로 변환한 것.

```
depth,address,op,output,inputs,note
0,0x18190c40c,COPY,tmp:0x100004c2,stack:0x-a8,
1,0x18190c40c,INDIRECT->CALL,stack:0x-a8,...,...
```

엑셀이나 pandas로 열어 depth/op 기준으로 필터링하기 편하다.

---

## 3. _sources.csv 구조

```
depth,varnode,is_reg,is_stack,note
11,RDX,True,False,no callers - root source in ...
```

---

## 4. _summary.md 구조

`summarize_slice.py`가 생성하는 Markdown. 섹션별 내용:

### Section 1: Function Call Flow (Tree)

함수 경계를 넘은 전환만 추출해서 ASCII 트리로 표현.

```
anchor  0x18190c492  in[2]
▼ INDIRECT  Memory_1_Pin_...
          param[0] out-param -> writes to stack:0x-a8  (9 stores)  @0x18190c40c
  [branch 1] ▲ INTERPROC  Socket_BeginSendCallback...
              -> Memory_1_Pin_...  param[1]  arg=tmp:0x5300  @0x18190c40c
```

- `▼ INDIRECT` : callee가 out-param으로 내 스택을 채워줌 (아래로 진입)
- `▲ INTERPROC` : 파라미터 출처를 찾아 caller로 올라감
- `[branch N]` : 같은 부모에서 갈라진 독립 브랜치
- 리프 노드 태그: `[BLOCKED-no-callers]`, `[SOURCE-metadata]`, `[SOURCE-const]` 등

### Section 2: Notable PCode Operations

추적 중 발견된 주요 LOAD, PTRSUB/PTRADD, CALL 목록.

- **LOAD** : 메모리 읽기 — 포인터 경로 파악에 사용
- **PTRSUB/PTRADD** : 주소 계산 — `PTRSUB(RCX, 0x50)` = `this->field_0x50`
- **CALL** : 직접 함수 호출

### Section 3: Data Sources

추적이 멈춘 말단 노드를 유형별 분류.

- `[EXTERNAL SOURCE]` : recv 등 외부 I/O
- `[REG - no callers]` : 가상 디스패치 등으로 더 올라갈 수 없는 레지스터 — 다음 anchor 후보
- `[MEM - global/heap]` : 전역/힙 주소
- `[SOURCE-metadata]` : 런타임 메타데이터 (il2cpp TypeInfo 등) — 노이즈

### Section 4: Cycle / Depth-Limit Hits

어느 함수에서 CYCLE이 많이 발생했는지 집계.  
빈도 높은 함수 = 여러 경로가 수렴하는 핵심 함수.

---

## 5. pcode_dump_0x<addr>.txt 구조

해당 주소를 포함하는 함수의 High PCode op 전체 목록.

```
--- 0x18190c3ef ---
  COPY          out=stack:0x-58    in=['stack:0x-a8']
  COPY          out=stack:0x-50    in=[EAX]
--- 0x18190c3ff ---
  PTRSUB        out=tmp:0x5300     in=[RSP, const:0x-58]
```

슬라이서 결과에서 특정 주소의 동작이 이상할 때 이 파일로 직접 확인한다.

---

## 6. 분석 워크플로우

```
1. backward_slicer.py 실행
       ↓
2. _summary.md Section 1 트리 확인
   → 어떤 함수 경로를 거쳤는지 파악
       ↓
3. [BLOCKED-no-callers] 태그 있는 리프 확인
   → 이게 다음 anchor 후보
       ↓
4. [SOURCE-metadata] / const 등은 노이즈로 무시
       ↓
5. Section 2의 PTRSUB 오프셋으로 객체 필드 레이아웃 추정
   예: PTRSUB(RCX, 0x80) = ClientSocket.m_SendBufferNotDecode
       ↓
6. highlight_slice.py로 Ghidra에서 시각 확인
   → Bookmark > SliceChain 에서 전환 지점 목록 확인
       ↓
7. 필요 시 anchor 변경 후 반복
```

---

## 7. varnode 표기 설명

| 표기 | 의미 |
|------|------|
| `RCX`, `RDX`, `RAX` ... | 레지스터 |
| `tmp:0x11f00` | SSA 임시 varnode |
| `stack:0x-a8` | 스택 변수 (RSP 기준 음수 오프셋) |
| `mem@ram+0x182f48238` | RAM 절대 주소 (전역/힙) |
| `const:0x0` | 상수 |
