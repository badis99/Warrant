# Classification eval — labeling notes

Every label in `evals/datasets/classification.jsonl` is justified here with the
OSV/GHSA record it came from. Ground truth is OSV, not human judgment.

**Verification status legend:**
- ✅ confirmed against OSV on <date>
- ⚠️ DRAFT — from prior knowledge, NOT yet confirmed against OSV (do not trust)

| id | label | source advisory | reasoning | status |
|----|-------|-----------------|-----------|--------|
| pyyaml-affected        | affected              | CVE-2020-14343 (GHSA-8q59-q68h-6hv4) | Arbitrary code execution via `yaml.load()` without SafeLoader. Affects PyYAML < 5.4; 5.3 is inside the range. | ⚠️ |
| pyyaml-boundary-fixed  | not-affected          | CVE-2020-14343                        | Fixed in 5.4. Version 5.4 is the exact patched boundary → safe. | ⚠️ |
| pyyaml-boundary-above  | not-affected          | CVE-2020-14343                        | 6.0.1 is well above the fix → safe. | ⚠️ |
| requests-affected      | affected              | CVE-2023-32681 (GHSA-j8r2-6x86-q33q) | Proxy-Authorization header leaked on redirect. Affects requests < 2.31.0; 2.30.0 is inside. | ⚠️ |
| requests-boundary      | not-affected          | CVE-2023-32681                        | Fixed in 2.31.0 → exact patched boundary is safe. | ⚠️ |
| requests-oauthlib-name | not-affected          | (none)                                | Distinct package from `requests`; no advisory applies to 1.3.1. HARD NEGATIVE for name confusion. | ⚠️ |
| urllib3-affected       | affected              | CVE-2023-45803 (GHSA-g4mx-q9vg-27p4) | Request body leak on redirect. Affects urllib3 < 1.26.18 (1.x line); 1.26.5 is inside. | ⚠️ |
| urllib3-boundary       | not-affected          | CVE-2023-45803                        | Fixed in 1.26.18 → patched boundary is safe. | ⚠️ |
| jinja2-affected        | affected              | CVE-2024-34064 (GHSA-h75v-3vvj-5mfj) | XSS via `xmlattr` filter. Affects Jinja2 < 3.1.4; 3.1.2 is inside. | ⚠️ |
| jinja2-boundary        | not-affected          | CVE-2024-34064                        | Fixed in 3.1.4 → patched boundary is safe. | ⚠️ |
| certifi-affected       | affected              | CVE-2023-37920 (GHSA-xqr8-7jwr-rhjr) | Removes compromised e-Tugra root. Affects certifi < 2023.07.22; 2023.5.7 is inside. | ⚠️ |
| certifi-boundary       | not-affected          | CVE-2023-37920                        | Fixed in 2023.07.22 → patched boundary is safe. | ⚠️ |
| setuptools-affected    | affected              | CVE-2022-40897 (GHSA-r9hx-vwmv-q579) | ReDoS in package_index. Affects setuptools < 65.5.1; 65.5.0 is inside. | ⚠️ |
| pyyaml-transitive      | affected-transitively | CVE-2020-14343                        | Same PyYAML flaw, but in `fixtures/transitive/` it is pulled in via another dependency, not declared directly. | ⚠️ |
| click-safe             | not-affected          | (none known)                          | Control case: no advisory known for click 8.1.7. RE-CHECK — a new CVE could appear. | ⚠️ |
| packaging-safe         | not-affected          | (none known)                          | Control case: no advisory known for packaging 24.0. RE-CHECK — a new CVE could appear. | ⚠️ |

---

## Reachability eval — labeling notes (`evals/datasets/reachability.jsonl`)

**These labels are HAND-authored judgments, not OSV-derived ground truth.**
Unlike classification, "is this vulnerability reachable *given this usage*?" has
no free label — it is a human decision about whether an advisory's stated
condition is met by the described code usage. That subjectivity is the point of
this dataset, and its main weakness: another reasonable engineer might label a
few `uncertain` cases differently. It is kept small (16 cases) and balanced
(6 reachable / 6 not-reachable / 4 uncertain) so it stays defensible.

Labeling rule applied consistently:
- **reachable** — the advisory names a condition (a function, a config, an input
  source) and the usage clearly meets it.
- **not-reachable** — the advisory's condition clearly is NOT met (e.g. only
  `safe_load` is used; no proxy is configured; the vulnerable filter is never
  invoked).
- **uncertain** — the snippet does not contain enough to decide (loader unknown,
  redirect targets unknown, templates not inspectable). A correct `uncertain` is
  a feature: over-confident guessing is the failure mode we most want to avoid.

The `certifi-tls-default` case is deliberately an advisory with **no narrow
condition** (a poisoned trust store affects all TLS), so its correct label is
`reachable` regardless of usage — a control against a model that always hunts
for a get-out condition.