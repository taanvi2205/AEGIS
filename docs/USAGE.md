# Running AEGIS

No installation, no dependencies, no network access. Python 3.11+ and the
standard library. Run everything from the repository root.

```bash
python3 -m aegis policy     # the shipped manifests, sanitizers and invariants
python3 -m aegis demo       # five-beat live demo, one attack per enforcement layer
python3 -m aegis eval       # paired corpus under all four defense configurations
python3 -m aegis sweep      # where provenance stops attributing + plot
python3 -m aegis redteam    # adaptive red-team loop + degradation plot
python3 -m aegis report     # all of the above, written to runs/report.md
python3 -m unittest discover -s tests   # 42 tests
```

## What each command shows

**`demo`** is the presentation. Five beats, each isolating one layer:

1. `atk-a1` — an overt injection. The in-band classifier quarantines it. The
   baseline works, on this attack.
2. `atk-a2` — the same attack rewritten as ordinary policy prose. The classifier
   passes it and the attack succeeds under `input_only`; under `full` the
   provenance layer blocks it, because the recipient address traces back to the
   fetched page.
3. `atk-c1` — a confidential file read followed by an email to a recipient the
   user themselves named. Every per-call check passes. INV-1 blocks the sequence.
4. `ben-c1` — the same two calls with an aggregate payload the declassifier can
   clear. Allowed. This is the pair that shows the system works rather than
   deadlocks.
5. The payload the red-team loop actually evolved, run under `input_only` and
   `out_of_band`.

Each line reads: request → tag assignment → layer checks → decision → reason.

**`eval`** prints attack success rate, task completion and false-positive rate
together, per configuration. Reading ASR alone is meaningless — a defense that
blocks everything scores 0%.

**`sweep`** measures how much obfuscation it takes to defeat provenance
*attribution*, per matcher tier, and shows separately that the *block* rate holds
because unattributable control-plane arguments are denied by default.

**`redteam`** evolves injection payloads against the guard and plots attack
success per round per configuration. `--target full` runs the attacker against the
whole stack; read the note it prints about fitness degeneracy before quoting the
result.

## Defense configurations

| name | layers | what it is for |
|---|---|---|
| `none` | — | is the attack feasible at all? |
| `input_only` | in-band classifier | the current-generation baseline |
| `out_of_band` | manifest + provenance + trajectory | this project's mechanism, classifier excluded so its contribution is unconfounded |
| `full` | everything | the deployed configuration |

## Layout

```
aegis/
  core.py            labels, tool calls, decisions, sanitization records
  text.py            normalisation, de-obfuscation, similarity primitives
  audit.py           the event log; the terminal view and the JSONL are one source
  checkpoint/
    checkpoint.py    the mandatory interceptor: manifest → provenance → trajectory
    classifier.py    Layer 1 (probabilistic, in-band, ingestion-time only)
    provenance.py    Layer 2 (deterministic): taint store and the matcher ladder
    trajectory.py    Layer 3 (deterministic): five sequence-level invariants
    sanitizers.py    shape checks and the one declassifier
  tools/             least-privilege manifests + mocked tools (nothing leaves the box)
  agent/             the minimal agent loop and its backends
  redteam/           mutation operators and the adaptive loop
  eval/              runner, metrics, obfuscation sweep, SVG plots
corpus/scenarios.json   26 scenarios: 13 attack, each with a benign twin
docs/decisions.md       every non-obvious choice, with alternatives
runs/                   generated: report.md, JSON results, audit log, SVGs
```

## Swapping in a real guard model

The shipped Layer-1 backend is a lexical stand-in, not a trained classifier. To
run with a real one:

```bash
python3 -m venv .venv && .venv/bin/pip install transformers torch
AEGIS_GUARD_MODEL=protectai/deberta-v3-base-prompt-injection-v2 \
  .venv/bin/python -m aegis eval --guard hf
```

Nothing else changes: the enforcement layers never consult the classifier, so
swapping it moves the `input_only` numbers and leaves `out_of_band` untouched.

## Using a live model as the planner

```bash
AEGIS_AGENT_BACKEND=ollama AEGIS_OLLAMA_MODEL=phi3:mini python3 -m aegis eval
```

This path is implemented but has not been exercised — see `docs/decisions.md`
D-03. Results from it are not reproducible run to run, which is why the scripted
backend is the default for anything reported.

## Safety properties

- No real network calls, no real emails, no real payments, no file access outside
  `sandbox/`. The mocked email and payment tools write JSON records to
  `sandbox/outbox/` and never deliver anything.
- All attack payloads are synthetic and are directed only at this repo's own
  agent and guard.
- No secrets, credentials or API keys anywhere; the two environment variables
  above are model names, not credentials.
- Every enforcement error path denies. See `tests/test_fail_closed.py`.
