# Warrant — Design Document

- **Date:** 2026-08-22
- **Status:** Draft — awaiting author review
- **Author:** Badis Bouali
- **One-liner:** Reachability-aware dependency remediation for PyPI projects — a cited plan, not a wall of alerts.

---

## 1. Overview

Warrant ingests a Python project's lockfile and produces a ranked, cited remediation plan: which dependencies are vulnerable (directly or transitively), whether each vulnerability is **actually reachable** given how the code uses the package, the **minimal safe upgrade**, and **what that upgrade might break**.

It is deliberately *not* a scanner and *not* a Dependabot clone. Scanners produce undifferentiated alert lists; Warrant is the expert that reads that list and returns a decision. Its value rests on three pillars: **reachability reasoning**, **cited breaking-change assessment**, and a **rigorous evaluation harness**.

This is a portfolio project. The bar is not "it works" but "the author measured it, understood where the naive approach fails, and fixed it with evidence." The primary deliverable is a **before/after metrics table** showing quality climb as each component is added.

---

## 2. Goals and non-goals

### Goals
- Correctly classify each dependency as `not-affected` / `affected` / `affected-transitively` using **deterministic** version math.
- Judge **reachability** from advisory prose against code usage, with **explicit confidence**.
- Recommend the **minimal safe upgrade** and a **cited** breaking-change assessment.
- Ship an eval harness (3 tracks) with **hard negatives**, built before improvements, producing the before/after table.
- Keep the deterministic core and the RAG layer **cleanly and physically separated**.

### Non-goals
- Multiple ecosystems. **PyPI only.** No npm/Cargo/Go/Maven.
- Exhaustive corpus. A **bounded, curated** advisory/changelog set and a small fixture set of test repos.
- Guaranteed static-analysis reachability (full call-graph analysis). We do **advisory-condition reasoning** and report confidence, not a soundness proof.
- Any feature that cannot be tied to reachability, cited remediation, or the eval story.

---

## 3. Locked decisions

| Decision | Choice | Rationale |
| --- | --- | --- |
| Ecosystem | **PyPI** | Tool is Python (dogfoodable); PEP 440 is gnarlier than semver, sharpening the version-math artifact. |
| Version library | **`packaging`** (PEP 440) | Canonical, correct, well-understood. |
| Models | **Hosted LLM + local embeddings** | Hosted (Claude) for reasoning/judge quality; local embeddings (e.g. `bge-small` via `sentence-transformers`) keep RAG cheap and reproducible for the CI eval gate. |
| Infra timing | **Lean core first** | Phase 0 is Python + venv + eval harness. Docker/FastAPI/CI deferred to the deployment phase. |
| Orchestration | **LangGraph** | Justified by real conditional branches (short-circuit; multi-hop evidence). |

---

## 4. The architectural rule (non-negotiable)

> **Version-range math is deterministic. The LLM never decides whether a version is affected.**

OSV provides affected ranges as structured data. "Is `1.4.5` in `>=1.2.0 <1.4.5`?" is a resolver problem under PEP 440's exact rules, not a language problem. LLMs fail on boundary comparisons — inclusive/exclusive confusion, off-by-one — and fail confidently. In security that is a false alarm or a missed live vulnerability.

**Enforcement:** `src/warrant/core/` must never import or call an LLM. This is a review rule and will be covered by a lint/import check in the CI phase. The LLM is trusted only with reachability and breakage — both fuzzy, both over prose.

---

## 5. Architecture

### 5.1 Component separation

Two packages that meet in exactly one place (`agent/nodes.py`):

- **`core/` (facts, deterministic):** `parse`, `resolve`, `osv`, `depsdev`, `version_match`.
- **`rag/` (judgment, LLM):** `corpus`, `index`, `retrieve`, `reachability`, `breakage`.

This separation is not cosmetic: the two halves are measured on different eval tracks and fail for different reasons. Keeping them isolated keeps each independently testable and each unit small enough to reason about.

### 5.2 The LangGraph state machine

Nodes (deterministic unless marked LLM):

1. `parse_manifest` — lockfile → `[(ecosystem, name, version)]`.
2. `resolve_graph` — transitive graph from lockfile, or deps.dev when only a manifest exists.
3. `query_vulns` — batch OSV query; candidates carry CVE/GHSA/OSV aliases.
4. `check_applicability` — **PEP 440** range matching; discards versions outside affected ranges.
5. *conditional edge* — nothing affected → `clean_report`; else continue.
6. `retrieve_context` — hybrid BM25 + dense retrieval + rerank over the corpus.
7. `assess_reachability` *(LLM)* — reason over retrieved conditions vs. code usage; emit verdict + confidence. *Conditional edge:* if uncertain, route to `fetch_extra_evidence` (multi-hop), then re-assess.
8. `plan_remediation` — minimal safe version from OSV `fixed` events, cross-checked via deps.dev.
9. `assess_breakage` *(LLM/RAG)* — changelogs current → target.
10. `synthesize_report` *(LLM)* — compose the final cited plan.

### 5.3 Shared state schema (designed first)

```python
from typing import TypedDict, Literal

Tag = Literal["SELF", "DIRECT", "INDIRECT"]

class Package(TypedDict):
    ecosystem: str          # "PyPI"
    name: str
    version: str
    tag: Tag

class VulnCandidate(TypedDict):
    package: Package
    osv_id: str
    aliases: list[str]      # CVE / GHSA / OSV
    affected_ranges: list[dict]   # raw OSV affected.ranges
    fixed_versions: list[str]

class AffectedFinding(TypedDict):
    candidate: VulnCandidate
    verdict: Literal["affected", "affected-transitively"]

Verdict = Literal["reachable", "not-reachable", "uncertain"]

class Reachability(TypedDict):
    verdict: Verdict
    confidence: float           # 0..1, reported honestly
    condition: str              # the advisory condition, e.g. "calls Image.open()"
    evidence: list[str]         # cited chunk ids / code refs

class Remediation(TypedDict):
    target_version: str         # minimal safe
    confirmed_transitive: bool  # deps.dev cross-check
    fixed_ids: list[str]

class BreakageReport(TypedDict):
    breaking: bool
    notes: list[str]            # each grounded in a cited changelog chunk
    effort_hint: str

class WarrantState(TypedDict):
    lockfile_path: str
    packages: list[Package]
    candidates: list[VulnCandidate]
    affected: list[AffectedFinding]
    retrieved: dict[str, list[dict]]        # finding_id -> chunks
    reachability: dict[str, Reachability]
    remediation: dict[str, Remediation]
    breakage: dict[str, BreakageReport]
    report: dict | None
```

*(Field shapes may tighten during implementation; the contract is that state is the only channel between nodes.)*

---

## 6. Data sources

- **OSV.dev** — ground truth. `POST /v1/query` and `/v1/querybatch`. Aliases CVE ↔ GHSA ↔ OSV. **No range queries** — query exact versions or parse `affected.ranges`. **Empty response = "no record found," never "safe."** This distinction is encoded as a distinct state, not a boolean.
- **deps.dev** — transitive resolution without installing, used only when there is a manifest but no lockfile. Nodes tagged `SELF`/`DIRECT`/`INDIRECT`.
- **NVD** — deliberately *not* trusted as sole source (analysis backlog since early 2024). Rationale documented in README.

---

## 7. Evaluation strategy

Harness built **before** improvements. A deliberately naive baseline is measured first; each component earns its place by moving a number.

### Track 1 — Retrieval
- **Data:** 50–150 `query → gold chunk` pairs, ground truth inferable from OSV aliases.
- **Metrics:** recall@5, MRR, nDCG.

### Track 2 — End-to-end classification
- **Data:** `(lockfile, package, version) → not-affected / affected / affected-transitively`; labels free from OSV.
- **Hard negatives (deliberate):** close-name packages (`requests` vs `requests-oauthlib`), one patch above the fixed boundary, transitive-only cases.
- **Metrics:** precision, recall, F1.

### Track 3 — Remediation quality
- **Data:** LLM-as-judge rubric (correct target version? breakage grounded? hallucinated CVE?) + **small human gold set (~20–30)**.
- **Caveat (understood, not hidden):** judge evals are noisy (verbosity bias, inconsistency). Used as a directional signal cross-checked against the human set — never treated as precise.

### The killer artifact
Baseline LLM answering "is `1.4.5` affected by `>=1.2.0 <1.4.5`?" wrong a meaningful fraction of the time → deterministic resolver at ~100% → RAG lifting reachability accuracy. Rendered as the before/after table.

---

## 8. Phased build plan

| Phase | Deliverable | Number it moves |
| --- | --- | --- |
| **0** | Baseline + Tracks 1 & 2 harness; naive LLM version check + plain vector RAG | Baseline rows; boundary **failures** |
| **1** | Deterministic PEP 440 resolver | Boundary accuracy → ~100% (killer artifact) |
| **2** | OSV client (batch/aliases/empty≠safe) + transitive graph + deps.dev fallback | Track 2 gains transitive + close-name hard negatives |
| **3** | Hybrid BM25 + dense + rerank | Track 1 recall@5/MRR/nDCG climb (justifies BM25) |
| **4** | Reachability reasoning + clean-report short-circuit; hand-label reachability gold set | Reachability accuracy appears |
| **5** | Remediation + breakage + `synthesize_report`; Track 3 | Remediation-quality score; full plan |
| **6** | Multi-hop evidence fetch — **only if Phase 4 eval shows reachability is evidence-bottlenecked** | Reachability accuracy, if it actually lifts |
| **7** | FastAPI, Docker, caching (+ invalidation), tracing, **CI eval gate** | Engineering-discipline signal |

---

## 9. Risks and mitigations

| Risk | Mitigation |
| --- | --- |
| Reachability is the hardest feature to do honestly | Scope as *advisory-condition reasoning* with explicit confidence, not guaranteed reachability. Say so in output and README. |
| No free ground truth for reachability | Keep the hand-labeled gold set small (~20–30); budget for it, don't discover it late. |
| LLM-as-judge is noisy | Directional signal only, cross-checked against a human gold set; be ready to explain the noise. |
| Multi-hop branch may be over-engineering | Build linear path first; add the hop only if the eval demands it (Phase 6 is conditional). |
| OSV empty ≠ safe | Model "no record" as a distinct state, never a boolean `safe`. |
| PyPI name collision (`warrant` taken) | Portfolio repo unaffected; if published, distribute as `warrant-scan`, keep `warrant` command. |

---

## 10. Success criteria

- A committed before/after table showing measured improvement per phase.
- Deterministic resolver at ~100% on version-boundary cases vs. a measurably-failing LLM baseline.
- Reachability reasoning that reports confidence honestly and is validated against a human gold set.
- A CI eval gate that fails the build on metric regression.
- Every design decision explainable in an interview — if it can't be explained, it was built wrong.

---

## 11. Open questions

1. Repo/package name confirmed as **Warrant** (`warrant` command) — approved?
2. Is Phase 6 (multi-hop) acceptable as *conditional*, or required regardless for the LangGraph showcase?
3. Preferred lockfile format(s) to support first: `poetry.lock`, `uv.lock`, `requirements.txt` — one or all three in Phase 0?
4. Hosted LLM provider confirmation (Claude assumed) and embedding model choice (`bge-small` assumed).
