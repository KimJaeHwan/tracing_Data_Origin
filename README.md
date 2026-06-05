# Ghidra PCode Backward Slicer

Ghidra (Jython 2.7) 기반 인터프로시저럴 역추적 도구.  
`send()` 계열 함수의 버퍼 인자를 앵커로 잡아 함수 경계를 넘어 데이터 원점까지 역추적한다.

---

## 스크립트 목록

| 파일 | 역할 |
|------|------|
| `scripts/backward_slicer.py` | 핵심 슬라이서 — Ghidra Script Manager에서 실행 |
| `scripts/pcode_dumper.py`    | 디버깅용 — 함수의 High PCode op 전체 덤프 |
| `scripts/highlight_slice.py` | Ghidra 시각화 — 추적 경로 색상/북마크 적용 |
| `scripts/summarize_slice.py` | 결과 요약 — JSON을 읽어 Markdown 리포트 생성 (Python 3) |

---

## 빠른 시작

1. Ghidra에서 바이너리를 열고 Auto Analysis 실행
2. `pcode_dumper.py`로 추적하려는 CALL op 주소와 인자 인덱스 확인
3. `backward_slicer.py`의 `ANCHOR_ADDRESS`, `ANCHOR_ARG_IDX` 설정
4. Script Manager에서 `backward_slicer.py` 실행
5. 결과물은 `scripts/../output/` 폴더에 저장
6. (선택) `highlight_slice.py`로 Ghidra Listing 뷰에 추적 경로 시각화
7. (선택) Python 3으로 `summarize_slice.py` 실행해서 요약 Markdown 생성

---

## 설정 (backward_slicer.py)

```python
ANCHOR_ADDRESS  = 0x18190c492  # 추적 시작 CALL 명령어 주소
ANCHOR_ARG_IDX  = 2            # CALL inputs 중 추적할 인자 번호 (0=fn ptr, 1=arg0, ...)

MAX_DEPTH           = 200   # 함수 내부 PCode 역추적 한도
MAX_CALL_STACK_DEPTH = 10   # 함수 경계 위로 올라가는 횟수 한도 (backtrace depth)

STOP_FUNCTIONS  = { "recv", "WSARecv", ... }              # 외부 I/O 원점으로 태깅 후 중단
SKIP_FUNCTIONS  = { "il2cpp_gc_alloc", "memcpy", ... }    # 무시할 함수 (내부 런타임 등)
```

---

## 출력 파일

| 파일 | 내용 |
|------|------|
| `<binary>_slice.json`   | 전체 결과: chain ops + sources |
| `<binary>_chain.csv`    | 추적 중 방문한 모든 PCode op |
| `<binary>_sources.csv`  | 추적이 멈춘 말단 노드 (데이터 원점 후보) |
| `<binary>_summary.md`   | 함수 호출 트리 + 주요 메모리 접근 요약 |
| `pcode_dump_0x<addr>.txt` | pcode_dumper 출력 |

결과 파일 읽는 방법은 [`docs/output_guide.md`](docs/output_guide.md) 참고.

---

## 동작 방식 요약

```
anchor varnode
  ├─ getDef() 역추적       : COPY / LOAD / CAST / PTRADD 등 PCode op 체인
  ├─ INDIRECT->CALL        : out-param callee 내부 STORE 추적 (스택 + 힙)
  ├─ INTERPROC (위로)      : 파라미터 SOURCE 발견 시 XREF로 caller 탐색
  └─ STACK-STORE           : PTRSUB(RSP, off) → 해당 스택 주소에 쓰인 값 추적
```

---

## 환경

- Ghidra 12.0 / Jython 2.7
- x64 바이너리 (Windows 기준, 다른 아키텍처는 calling convention 설정 필요)

---

## 디렉토리 구조

```
.
├── scripts/
│   ├── backward_slicer.py
│   ├── pcode_dumper.py
│   ├── highlight_slice.py
│   └── summarize_slice.py
├── docs/
│   ├── db_builder_design.md   -- 전처리 DB 설계 문서
│   └── output_guide.md        -- 결과 파일 읽는 방법
├── output/                    -- 슬라이서 결과물 (예시 포함)
└── README.md
```
