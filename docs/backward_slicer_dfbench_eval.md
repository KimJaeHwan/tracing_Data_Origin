# backward_slicer.py — DataFlowBench 커버리지 평가

## 개요

`backward_slicer.py`(현재 버전)를 DataFlowBench 61개 케이스에 대해
코드 정적 분석으로 평가한 결과다. 실제 바이너리 실행 없이 슬라이서의
PCode 처리 로직과 각 케이스의 데이터 흐름 패턴을 대조하여 판정했다.

> **주의**: 이 평가는 정적 코드 분석 기반 예측이다.
> 실제 Ghidra headless 실행 결과(dfbench_adapter.py 완성 후)와 다를 수 있으며,
> 그 차이 자체가 slicer_core 개선 방향을 드러낸다.

---

## 슬라이서 핵심 능력 요약

### 처리 가능한 패턴

| PCode 패턴 | 처리 메커니즘 |
|---|---|
| COPY / CAST / INT_ZEXT / INT_SEXT | `backward_slice_impl` 직접 추적 |
| INT_ADD / INT_XOR 등 산술 연산 | 모든 입력 operand 재귀 추적 |
| MULTIEQUAL (PHI 노드) | 모든 incoming branch 추적 + loop-carry 감지 |
| 함수 경계 상향 추적 (파라미터) | `interprocedural_step` — XREF 기반 caller 탐색 |
| INDIRECT / outparam (스택) | `_handle_indirect_stack` — callee 내부 STORE 탐색 |
| INDIRECT / outparam (힙·글로벌) | `_handle_indirect_heap` — ptr arg 주소 매칭 |
| 스택 주소 STORE 추적 | `find_stores_to_stack_addr` (상수 오프셋 한정) |
| CALLIND (앵커) | `find_anchor`에서 CALLIND op 인식 |

### 구조적 한계

| 한계 | 영향 케이스 유형 |
|---|---|
| 변수 인덱스 stack offset 추적 불가 (상수만) | 변수 인덱스 배열 |
| `memcpy` / `memmove` / `memset` → SKIP_FUNCTIONS → INDIRECT fallback 실패 | 메모리 복사 API |
| CALLIND 칼리 내부 진입 불가 (함수 포인터 대상 미해석) | 함수 포인터, 가상 함수 |
| context-insensitive interprocedural (XREF 전체 탐색) | 다중 callsite 공유 함수 |
| setjmp / longjmp / C++ exception 미지원 | 비정상 흐름 |
| 스레드 간 데이터 흐름 미지원 | 멀티스레드 패턴 |
| 힙 base varnode 기반 raw 오프셋 추적 미구현 (RSP-relative만 지원) | 힙 포인터 산술 |
| STORE/LOAD 크기 기반 range 교집합 분석 미구현 | 타입 캐스트 오버랩, 부분 write |
| 비트필드 bit-range 분석 미구현 (SUBPIECE+shift+AND 패턴) | 비트필드 구조체 |

### 연동 이슈 (테스트베드 전용)

현재 `STOP_FUNCTIONS`에 `dfb_source_A/B/C`가 없어 이 함수들이
`sources` 리스트에 기록되지 않고 `chain` leaf로만 남는다.
dfbench_adapter 개발 시 `SOURCE_FUNCTIONS` 설정으로 해결 예정.

---

## 케이스별 평가

### 범례

| 판정 | 의미 |
|------|------|
| ✅ PASS | 슬라이서가 현재 로직으로 올바르게 소스를 추적할 수 있음 |
| ⚠️ 불확실 | 이론상 경로는 있으나 Ghidra decompiler 출력 방식 또는 에지케이스에 의존 |
| ❌ FAIL | 구조적 한계로 추적 불가 |

---

### dfbench_win_core (55 cases)

#### Basic (DFB001 ~ DFB003)

| ID | 이름 | 판정 | 근거 |
|---|---|:---:|---|
| DFB001 | direct_value | ✅ PASS | `dfb_source_A()` CALL leaf → trivial |
| DFB002 | arithmetic_value | ✅ PASS | INT_ADD → CALL 역추적 |
| DFB003 | cast_value | ✅ PASS | CAST / INT_SBEXT → CALL 역추적 |

#### Control Flow (DFB010 ~ DFB012)

| ID | 이름 | 판정 | 근거 |
|---|---|:---:|---|
| DFB010 | branch_phi | ✅ PASS | if/else → MULTIEQUAL, 양쪽 branch 모두 추적 |
| DFB011 | loop_phi | ✅ PASS | MULTIEQUAL loop-carry 감지 로직 존재 |
| DFB012 | switch_merge | ✅ PASS | switch 3-way merge → MULTIEQUAL 전체 추적 |

#### Stack (DFB020 ~ DFB026)

| ID | 이름 | 판정 | 근거 |
|---|---|:---:|---|
| DFB020 | stack_local | ✅ PASS | PTRSUB+STORE → `find_stores_to_stack_addr` |
| DFB021 | stack_outparam | ✅ PASS | INDIRECT → `_handle_indirect_stack` → callee STORE |
| DFB022 | arg_to_outparam | ✅ PASS | INDIRECT → callee STORE → param → caller arg |
| DFB023 | double_pointer_outparam | ⚠️ 불확실 | `**pp` 이중 역참조 — ptr_derived 전파가 따라가는지 불명확 |
| DFB024 | global_value_flow | ⚠️ 불확실 | 같은 함수 내 global write이면 SSA로 해결 가능. 함수 경계 시 pointer arg 없는 callee를 `_handle_indirect_heap`이 매칭 못 할 수 있음 |
| DFB025 | global_field_precise | ⚠️ 불확실 | 글로벌 struct 필드 오프셋 + `_vn_is_addr_of_global` 정확도 의존 |
| DFB026 | global_interproc_reader | ⚠️ 불확실 | DFB024보다 함수 경계 더 많음 |

#### Heap (DFB030 ~ DFB032)

| ID | 이름 | 판정 | 근거 |
|---|---|:---:|---|
| DFB030 | heap_field | ⚠️ 불확실 | malloc 힙 주소를 `_vn_is_addr_of_global`이 매칭하는지 Ghidra 표현 의존 |
| DFB031 | heap_realloc_preserve | ❌ FAIL | realloc이 포인터 교체 → 이전 힙 주소 무효화, 추적 불가 |
| DFB032 | heap_raw_offset | ❌ FAIL | `malloc` 반환 varnode + raw INT_ADD/PTRADD 오프셋 산술. `find_stores_to_stack_addr`는 RSP-relative 주소만 처리하며 힙 base varnode 기반 오프셋 매칭 미구현 |

#### Struct / Array (DFB040 ~ DFB046)

| ID | 이름 | 판정 | 근거 |
|---|---|:---:|---|
| DFB040 | struct_field_precise | ✅ PASS | 스택 struct, 상수 오프셋 STORE/LOAD — 처리 가능 |
| DFB041 | pointer_arithmetic_field | ⚠️ 불확실 | `char*` 캐스트 후 오프셋 산술 — `_vn_points_to_stack_offset`의 INT_ADD 분기 처리 가능하나 체인 복잡도 의존 |
| DFB042 | union_alias | ⚠️ 불확실 | union은 동일 스택 주소 공유, SSA에서 같은 오프셋이면 추적 가능하나 PCode 표현 방식 의존 |
| DFB043 | array_constant_index | ✅ PASS | 상수 인덱스 → 상수 오프셋 PTRADD → `find_stores_to_stack_addr` 처리 가능 |
| DFB044 | array_variable_index | ❌ FAIL | 변수 인덱스 → `_vn_points_to_stack_offset`이 상수 오프셋만 지원, 매칭 실패 |
| DFB045 | nested_aggregate_field | ⚠️ 불확실 | 중첩 struct 오프셋 누적 계산 — PTRADD 체인을 따라가는지 의존 |
| DFB046 | partial_overwrite_subfield | ❌ FAIL | 부분 write 후 전체 read — PCode에서 별도 SSA 노드로 분리, 연결 추적 불가 |

#### Offset Arithmetic / Bitfield (DFB034 ~ DFB035, DFB047 ~ DFB049)

오프셋 단위 추적의 경계 케이스를 검증하는 신규 그룹.
PTRSUB / INT_ADD / INT_SUB / SUBPIECE PCode 패턴과 슬라이서 한계 지점을 명시한다.

| ID | 이름 | 판정 | 근거 |
|---|---|:---:|---|
| DFB034 | bitfield_access | ❌ FAIL | **실측 확인.** 비초기화 bp → Ghidra가 `CALL out=null + INDIRECT out=stack:0x-38` 패턴으로 인코딩. source 반환값 varnode가 없고, sink는 undefined stack varnode를 수신. 슬라이서가 INDIRECT의 effect_host(CALL seqno)를 따라가는 로직 없어 소스 전혀 미탐지 |
| DFB035 | bitfield_access_zeroinit | ❌ FAIL | **실측 확인.** `bp = {0}` 초기화에도 PCode 구조 동일 — `CALL out=null + INDIRECT out=stack:0x-38`. seqno만 다름(0x12, 0x46). Ghidra의 비트필드 처리 방식이 초기화 여부와 무관하게 고정됨 확인 |
| DFB047 | struct_padding_offset | ✅ PASS | `char tag` + 3바이트 패딩 + `int value`. Ghidra decompiler가 ABI-correct 절대 오프셋(+4)을 계산해 PTRSUB에 직접 반영 → 슬라이서는 decompiler 제공 오프셋을 그대로 사용하므로 패딩 인식 불필요 |
| DFB048 | cast_range_overlap | ❌ FAIL | `*(int*)(buf+4) = src_A` → STORE size=4, offset=4 (covers bytes [4..7]). 읽기는 `buf[6]`(offset=6, size=1). 정확한 추적을 위해 `store_offset ≤ read_offset < store_offset + store_size` range 교집합 검사 필요 → 현재 슬라이서 exact offset 매칭으로 미탐 |
| DFB049 | negative_offset_arithmetic | ⚠️ 불확실 | `end = buf+30; *(end-10) = src`. 상수 피연산자 → Ghidra 상수 폴딩 시 INT_ADD(buf, 20) 단일 op → PASS. 비폴딩 시 INT_ADD(INT_ADD(buf, 30), -10) — INT_NEGATE/INT_2COMP 결합 필요 → FAIL |

**DFB034/035 실측 PCode 비교 (Ghidra headless, 2026-06-10):**
```
DFB034 (bp 비초기화):          DFB035 (bp = {0} 초기화):
CALL  out=null  [dfb_source_A]  CALL  out=null  [dfb_source_A]
INDIRECT  stack:0x-38  const:0xf    INDIRECT  stack:0x-38  const:0x12
CALL  out=null  [dfb_source_B]  CALL  out=null  [dfb_source_B]
INDIRECT  stack:0x-38  const:0x43   INDIRECT  stack:0x-38  const:0x46
CALL  out=null  [dfb_sink_int, stack:0x-38]    (동일)
```
→ seqno 값만 다르고 구조 완전 동일. **초기화 여부는 Ghidra High PCode 비트필드 표현에 영향 없음** 확정.

source 반환값 varnode가 생성되지 않으며, INDIRECT의 `const:seqno`가 원인 CALL을 가리킨다.
**→ 향후 개선 방향**: `INDIRECT` 처리 시 effect_host seqno로 원인 CALL을 찾아 callee를 SOURCE_FUNCTIONS에서 조회하는 경로 추가 (over-approximation으로 양쪽 source 모두 탐지. bit-range 분리는 여전히 불가)

#### Interprocedural (DFB050 ~ DFB060)

| ID | 이름 | 판정 | 근거 |
|---|---|:---:|---|
| DFB050 | identity_call | ✅ PASS | `interprocedural_step` → param[0] → caller arg |
| DFB051 | nested_call | ✅ PASS | call_stack_depth=10 이내, 중첩 interproc 처리 |
| DFB052 | callsite_context | ⚠️ 불확실 | context-insensitive XREF — 다른 callsite의 unrelated 소스도 함께 추적 (over-approximation) |
| DFB053 | large_struct_return | ⚠️ 불확실 | hidden pointer로 struct 반환 → INDIRECT 처리 가능하나 Ghidra decompiler 표현 의존 |
| DFB054 | status_outparam | ✅ PASS | INDIRECT → `_handle_indirect_stack`, 복수 output param 중 매칭 |
| DFB055 | deep_field_passthrough | ⚠️ 불확실 | 깊은 중첩 interproc + struct field — call_stack_depth 이내면 가능하나 경계 케이스 |
| DFB056 | arg_to_ret_summary | ✅ PASS | interprocedural param → COPY → return |
| DFB057 | struct_field_to_ret_summary | ⚠️ 불확실 | LOAD struct field → PTRADD + param → interproc |
| DFB058 | arg_to_outparam_summary | ✅ PASS | DFB022와 동일 패턴 |
| DFB059 | inout_field_update_summary | ⚠️ 불확실 | `s->field += val` in-out — LOAD+ADD+STORE 체인 + INDIRECT 조합 |
| DFB060 | recursion | ⚠️ 불확실 | visited set이 SSA-aware라 무한루프는 방지, 재귀 termination condition을 통한 소스 도달 여부 불명확 |

#### Function Pointers (DFB070 ~ DFB073)

| ID | 이름 | 판정 | 근거 |
|---|---|:---:|---|
| DFB070 | function_pointer | ❌ FAIL | CALLIND 칼리 내부 진입 불가 (`_get_callee_func` → None for CALLIND) |
| DFB071 | callback_registration | ❌ FAIL | 등록/호출 분리 패턴 — XREF 기반 추적으로 연결 불가 |
| DFB072 | function_pointer_table | ❌ FAIL | 테이블 기반 CALLIND |
| DFB073 | indirect_sink_wrapper | ⚠️ 불확실 | CALLIND가 앵커인 경우 `find_anchor`에서 인식은 하나, 소스가 직접 인자로 오면 추적 가능 |

#### Platform / ABI (DFB091, DFB100 ~ DFB102)

| ID | 이름 | 판정 | 근거 |
|---|---|:---:|---|
| DFB091 | tls_value | ⚠️ 불확실 | TLS 접근 시 FS 세그먼트 레지스터 경유 PCode — Ghidra 처리 방식 의존 |
| DFB100 | varargs | ⚠️ 불확실 | 스택 push 방식 vararg → STORE 추적 가능성 있으나 va_arg 내부 PCode 복잡 |
| DFB101 | tail_call_candidate | ⚠️ 불확실 | 최적화 시 BRANCH로 변환 → CALL op 소실로 interproc 추적 실패 가능 |
| DFB102 | signed_unsigned_boundary | ✅ PASS | INT_ZEXT / INT_SEXT / CAST 전부 처리 |

#### Exceptional Flow (DFB110)

| ID | 이름 | 판정 | 근거 |
|---|---|:---:|---|
| DFB110 | setjmp_longjmp | ❌ FAIL | non-local control flow — PCode에서 일반 분기로 표현되지 않음 |

#### Memory API (DFB120 ~ DFB123)

| ID | 이름 | 판정 | 근거 |
|---|---|:---:|---|
| DFB120 | memcpy_buffer | ❌ FAIL | `memcpy` ∈ SKIP_FUNCTIONS → INDIRECT skip → pre-call 값 추적 → 소스 도달 불가 |
| DFB121 | memmove_buffer | ❌ FAIL | `memmove` ∈ SKIP_FUNCTIONS — 동일 |
| DFB122 | strcpy_buffer | ⚠️ 불확실 | `strcpy` ∉ SKIP_FUNCTIONS → `_handle_indirect_stack` 시도하나 CRT 구현 decompile 품질 의존 |
| DFB123 | memset_partial_memcpy | ❌ FAIL | `memset` + `memcpy` 둘 다 SKIP → 데이터 흐름 끊김 |

#### Cross-DLL Import (DFB130 ~ DFB131)

| ID | 이름 | 판정 | 근거 |
|---|---|:---:|---|
| DFB130 | shared_import_arg_to_ret | ⚠️ 불확실 | 별도 DLL 함수 → Ghidra가 외부 함수로 처리 시 decompile 불가. 분석 설정에 따라 다름 |
| DFB131 | shared_import_outparam | ⚠️ 불확실 | DFB130 + INDIRECT 조합 — DLL 분석 여부 의존 |

#### Obfuscation (DFB200 ~ DFB201)

| ID | 이름 | 판정 | 근거 |
|---|---|:---:|---|
| DFB200 | obf_bcf_multistep | ✅ PASS | 가짜 분기(BCF)는 control flow 패턴 — backward slice는 data dependency만 추적하므로 dead branch 투명 |
| DFB201 | obf_fla_statemachine | ✅ PASS | FLA state machine의 `val` 변수가 MULTIEQUAL로 각 case 값을 merge — 슬라이서가 전체 추적. state 변수는 데이터 경로와 분리됨 |

---

### 다른 바이너리 (구조적 FAIL)

| ID | 바이너리 | 판정 | 근거 |
|---|---|:---:|---|
| DFB080 | dfbench_cpp | ❌ FAIL | C++ virtual call → CALLIND, vtable 대상 진입 불가 |
| DFB081 | dfbench_cpp | ❌ FAIL | lambda capture → closure struct 내부 접근, 미지원 |
| DFB090 | dfbench_posix_runtime | ❌ FAIL | thread 간 shared memory — 동기화/스케줄링 의미론 없음 |
| DFB092 | dfbench_posix_runtime | ❌ FAIL | condvar 기반 signaling — 동일 |
| DFB111 | dfbench_cpp_exceptions | ❌ FAIL | C++ exception unwind path — landing pad 이후 흐름 미포착 |

---

## 집계

| 판정 | 개수 | 케이스 |
|---|:---:|---|
| ✅ PASS | **17** | DFB001~003, DFB010~012, DFB020~022, DFB040, DFB043, DFB047, DFB050~051, DFB054, DFB056, DFB058, DFB102, DFB200~201 |
| ⚠️ 불확실 | **20** | DFB023~026, DFB030, DFB041~042, DFB045, DFB049, DFB052~053, DFB055, DFB057, DFB059~060, DFB073, DFB091, DFB100~101, DFB122, DFB130~131 |
| ❌ FAIL | **24** | DFB031~032, DFB034~035, DFB044, DFB046, DFB048, DFB070~072, DFB080~081, DFB090, DFB092, DFB110~111, DFB120~121, DFB123 |
| **합계** | **61** | |

---

## FAIL 원인 분류

| 원인 | 케이스 수 | 케이스 |
|---|:---:|---|
| CALLIND 칼리 진입 불가 (함수 포인터 / 가상 함수) | 5 | DFB070~072, DFB080~081 |
| SKIP_FUNCTIONS로 메모리 API 차단 | 3 | DFB120~121, DFB123 |
| 다른 바이너리 (스레드 / 예외) | 4 | DFB090, DFB092, DFB110~111 *(DFB110은 win_core)* |
| 변수 인덱스 배열 오프셋 미지원 | 1 | DFB044 |
| realloc 포인터 교체 | 1 | DFB031 |
| 부분 구조체 write 의미론 | 1 | DFB046 |
| 힙 base varnode raw 오프셋 추적 미구현 | 1 | DFB032 |
| STORE/LOAD range 교집합 분석 미구현 | 1 | DFB048 |
| 비트필드 bit-range 분석 미구현 | 1 | DFB034 |

---

## 불확실 케이스 — 개선 시 PASS 전환 가능성

| 우선순위 | 케이스 | 개선 방향 |
|---|---|---|
| 높음 | DFB024~026 (글로벌 변수) | `_handle_indirect_heap` 에서 pointer arg 없이 직접 전역 write하는 callee 추적 로직 추가 |
| 높음 | DFB040~045 (구조체/배열) | PTRADD 체인 오프셋 누적 계산 개선 |
| 중간 | DFB053, DFB057 (struct 반환/필드) | hidden pointer 반환 패턴 전용 INDIRECT 처리 |
| 중간 | DFB059 (in-out param) | LOAD+ADD+STORE 결합 패턴 처리 |
| 낮음 | DFB122 (strcpy) | CRT 함수 decompile 결과에 의존, 직접 개선 어려움 |
| 낮음 | DFB052 (context insensitive) | context-sensitive 확장은 복잡도 대비 실익 불명확 |

---

## 평가 기준 시점

- 평가 대상: `backward_slicer.py` (08_tracing_Data_Origin, commit `eac4637` 기준)
- 테스트베드: DataFlowBench v1.0 (09_tdo_testbed, 61 cases — offset arithmetic 그룹 DFB032/034~035/047~049 추가)
- DFB034 실측 PCode: Ghidra headless 덤프로 `CALL out=null + INDIRECT` 패턴 확인 (2026-06-10)
- 평가 방법: 코드 정적 분석 (Ghidra headless 실행 없음)
- 실측 검증: `dfbench_adapter.py` 완성 후 진행 예정
