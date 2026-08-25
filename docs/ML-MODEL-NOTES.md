# NetSentinel — Shipped Model, and What It Cannot Do

> **Status:** Phase 3 (ML detection). This is a permanent record, not a
> changelog entry. Every limitation below is a measured result, not a
> hedge — read it before quoting any accuracy number from this project.

## The shipped model

**Isolation Forest, `behavioural_only` variant** — model version
`381419f9-9e71-452f-8e16-46d353dd6491`, threshold `-0.1386`.

Marked `is_active = true` in the `model_versions` table. **The database is
the single source of truth for which model ships**; `DISPLAY_ALGORITHM` /
`DISPLAY_VARIANT` in `backend/app/services/supabase_client.py` are only a
fallback for a fresh install with nothing marked yet. A partial unique
index enforces that at most one version can be active.

**Features (8, no timing or packet sizes):** `is_bidirectional`,
`handshake_true` / `handshake_false` / `handshake_not_applicable`,
`close_fin_fin` / `close_rst` / `close_timeout` / `close_eof`.

**Measured on 162 held-out normal flows + 1002 labelled scan flows:**

| metric | value |
|---|---|
| recall | 0.998 |
| precision | 0.995 |
| F1 | 0.9965 |
| ROC-AUC | 0.9884 |
| average precision | 0.9959 |
| FPR (held-out normals) | 0.0309 |
| inference | 22.5 ms / 1000 flows |

Trained on 647 normal flows; scan captures were never fitted on.

---

## Why model attribution is enforced, not a footnote

Two models scored **the same 996 closed-port scan flows** from
`capture_scan_nmap_lan.pcapng` and disagreed almost completely:

| model | score range | stddev | flows flagged |
|---|---|---|---|
| Isolation Forest (primary) | 92.89 – 93.82 | 0.27 | **0 of 996** |
| One-Class SVM (primary) | 71.87 – 99.54 | 8.67 | **703 of 996** |

Identical input flows. Identical threshold *strategy*. Opposite verdicts on
70% of them.

This was found because the UI displayed an unlabelled "Score" column while
selecting the model by **whichever row was inserted last** — so the table
showed One-Class SVM's numbers while the written analysis described
Isolation Forest's. Nothing was technically wrong with either set of
numbers; the failure was that an analyst had no way to tell whose judgement
they were acting on.

**In a detection tool that is a security defect, not a cosmetic one.**
Hence: an explicit `is_active` flag in the database, a `scored_by` block on
`GET /api/flows`, and the algorithm name rendered in the score column
header.

**One-Class SVM is evaluated and retained, but not selected.** It is
recorded in `model_versions` with full metrics and remains queryable via
`GET /api/models` and `GET /api/flows/{id}/score`. It was not chosen
because it is erratic across feature sets — 0.706 recall on 13 features,
**0.000** on the 8 behavioural features, and ROC-AUC **0.508** (i.e.
indistinguishable from random) on the TCP-only subset. Its RBF decision
boundary is highly sensitive to feature geometry and degenerates on
binary-only inputs.

---

## Evidence the behavioural signal is path-independent

Scoring all 2850 stored flows with the shipped model:

| dataset | flows | flagged | rate |
|---|---|---|---|
| LAN scan (labelled positive) | 1039 | 1000 | 96.2% |
| **loopback scan (confounded control)** | 1002 | **1000** | **99.8%** |
| normal baseline | 809 | 36 | 4.4% |

The loopback capture was **excluded from training and from every metric
used to pick this feature set**, so its 99.8% detection rate is genuinely
out-of-sample for that decision. The model has never seen loopback traffic,
yet detects the loopback scan as reliably as the LAN one.

That is direct evidence the behavioural signature (RST without a completed
handshake) transfers across capture paths, which was the hypothesis behind
dropping timing features. For contrast, the 13-feature primary model —
which *does* use timing — flagged only **1.1%** of those same loopback
flows. Removing timing features did not merely improve LAN detection; it
made the model portable across network paths.

**Scope of this evidence:** it validates path-independence for *one attack
type*. It says nothing about generalising to attack classes the model has
never seen (see limitation 7).

---

## Known limitations

### 1. The model barely outperforms a two-condition rule

| detector | recall | FPR |
|---|---|---|
| `close_type='rst' AND handshake_completed=false` | 0.9940 | 0.0343 |
| Isolation Forest (behavioural, shipped) | 0.9980 | 0.0309 |

**+0.4 percentage points of recall over a rule expressible in one line of
SQL.** The ML model is not adding meaningful detection power on this data.
Its potential advantage is generalising to patterns nobody hand-coded —
that advantage is *plausible here but unproven*, because the only attack
class in the dataset is a port scan.

Do not describe this model as outperforming rule-based detection. On this
evidence it does not.

### 2. Precision collapses at a realistic base rate

The evaluation set is ~55% scan flows. Real networks are not. Re-projecting
the measured recall and FPR onto a **1% scan base rate**:

**precision = 0.286** — roughly **7 of every 10 alerts would be false**.

The headline 0.995 precision is an artefact of a balanced test set and must
never be quoted as a deployment expectation.

### 3. The baseline does not generalise to unseen captures

Leave-one-capture-out, retraining on the other four each time:

| held-out capture | flows | FPR |
|---|---|---|
| capture2_streaming | 123 | 0.0081 |
| capture1_browsing | 418 | 0.0526 |
| capture3_downloading | 74 | 0.0541 |
| capture4_idle | 68 | 0.0588 |
| **test.pcapng** | 126 | **0.2460** |

`test.pcapng` was captured two days earlier under different conditions and
draws **~25% false alarms** — roughly 8× the held-out-random estimate of
0.031. The random 80/20 split is optimistic because flows within one
capture are temporally correlated; LOCO is the more honest number, and it
says this baseline does not cover the range of legitimate traffic.

### 4. The baseline is small and narrow

809 flows from five short captures (~30 s – 2 min) on **one** Windows host,
**one** LAN, one time window, one set of running applications. Effective
sample size is well below 809 because flows within a capture are highly
correlated. Expect legitimate-but-unseen traffic — a VPN, a game, a backup
job, a different browser — to be flagged.

### 5. The shipped feature set was chosen using the test set

`behavioural_only` was an *ablation*, run to check whether detection
survived without timing features. It outperformed the committed 13-feature
primary (0.998 vs 0.004 recall), and was then selected on that basis.

**That is selection on the evaluation data.** Its reported metrics are
therefore optimistic in a way the primary variant's are not.

*Partially* mitigated: the loopback control capture played no part in
training or in the metrics used to make this choice, and the shipped model
detects it at 99.8% (see "Evidence the behavioural signal is
path-independent" above). That is real out-of-sample support for the
feature-set decision — but only for the same attack type on a different
network path. Fully validating the choice still needs a *different* attack
class the model has never been tuned against.

### 6. Labels are heuristic, not ground truth

Scan flows are labelled by port fan-out — a `(src_ip, dst_ip)` pair
touching more than 50 distinct destination ports. This correctly separated
1002 scan flows from 37 background flows in the live capture, but it is a
stated rule, not an oracle. A slow or distributed scan would evade it.

### 7. Only one attack class has ever been tested

Every number here comes from a single TCP connect scan against one router.
Nothing in this project has yet been evaluated against beaconing, DNS
tunnelling, exfiltration, brute force, or a slow/distributed scan. Detection
performance on those is **unknown**, not "expected to be similar".

### 8. The 5% threshold is a committed choice, not an optimum

The operating point is the 5th percentile of training scores, chosen before
seeing results and never tuned against scan labels. For the primary
13-feature variant this turned out badly — recall 0.004 at 5%, jumping to
0.998 at 10%, because the scan flows clustered in a ~0.9-point band just
below the cut. The shipped behavioural variant does not have this problem
(0.998 recall already at 5%), but the sensitivity is real and the threshold
should be revisited with operational false-alarm tolerance in mind.

---

## Changing the shipped model

```python
from app.services.supabase_client import set_active_model_version
set_active_model_version("<model_version_id>")
```

Scores are stored per `(flow_id, model_version_id)`, so switching the
active model changes which scores are displayed without destroying any
other model's. Retraining always inserts new versions and never updates
existing ones — no model is ever silently replaced.
