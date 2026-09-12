# Design decisions

Every non-obvious choice made while building AEGIS, with the alternatives that
were rejected and why (§9, §10). Decisions marked **[open]** were points where the
spec did not settle the question; the recommended option was taken, applied
consistently, and recorded here for review. Any of them can be reversed without
touching the enforcement logic.

---

## D-01 — Zero third-party dependencies **[standing permission]**

**Context.** The development environment has no third-party packages installed
and `pip` is externally managed (PEP 668), so nothing could be installed without
a virtualenv.

**Decision.** The entire harness runs on the Python standard library. Plots are
emitted as hand-written SVG rather than through matplotlib.

**Alternatives.** (a) Require a virtualenv with numpy/matplotlib/transformers —
more conventional, but adds a setup step and a supply chain to a security
project. (b) Vendor a plotting library — worse on both counts.

**Why.** §4 Rule 7 requires justifying every dependency against what the standard
library can already do. Line charts and a lexical matcher are both squarely
inside it. The cost is that a real guard model is opt-in rather than default
(D-02).

---

## D-02 — Layer-1 guard is a pluggable adapter with a lexical baseline shipped

**Context.** §2.1 requires an off-the-shelf guard model as the input-layer
baseline and forbids fine-tuning one. No model weights or `transformers` install
are available here, and downloading model weights is not something to do
speculatively inside a security repo.

**Decision.** `aegis/checkpoint/classifier.py` defines a `Guard` interface with
two backends. `HeuristicGuard` ships and is the default: eleven weighted
regular-expression signals scored over the normalized text, over any decodable
base64/hex/rot13 payload, and over a whitespace-stripped variant. `HFGuard`
adapts a real transformers classifier (candidate:
`protectai/deberta-v3-base-prompt-injection-v2`, overridable) and activates only
if that package is present; `build_guard("hf")` raises `GuardUnavailable` rather
than silently degrading.

**Alternatives.** (a) Ship no Layer 1 at all — but then the central comparison
has nothing to compare against. (b) Ship a deliberately weak strawman — this
would manufacture the headline result, which §2 item 5 forbids.

**Why.** The measurement needs *a* representative in-band filter, and the
comparison is between in-band and out-of-band *categories*, not between specific
models. Two consequences are stated wherever Layer-1 numbers appear: the baseline
is a lexical stand-in, and the claim is the shape of the degradation curve, not
the round at which a particular model crosses.

**Honesty control.** The signal weights were fixed before the corpus was run and
were never tuned against it. The guard flags one benign corpus document
(`ben-a5`'s page contains an ordinary "send to <address>" phrasing) — that false
positive is left in rather than tuned away.

---

## D-03 — Deterministic scripted agent, with an Ollama backend behind a flag

**Context.** §3 calls for a local model via Ollama. Ollama is not installed here,
and more importantly a nondeterministic planner makes the measurement unusable:
if the plan varies between runs, a change in ASR cannot be attributed to a change
in the defense.

**Decision.** `ScriptedBackend` is the default and replays a plan declared by the
scenario. `OllamaBackend` implements the local-model path against Ollama's HTTP
API and is selected with `AEGIS_AGENT_BACKEND=ollama`. Injection is modelled
explicitly rather than hoped for: a plan step marked `caused_by` a document only
executes if that document actually reached the agent's context, and a step marked
`needs` a document cannot be performed if that document was quarantined.

**Alternatives.** (a) Ollama by default — unreproducible, and unavailable here.
(b) Drop the Ollama path entirely — but §3 asks for it, and the interface cost is
small.

**Why.** This is a measurement harness first. The trade-off is stated in the
report's limitations: these numbers describe the enforcement layers, not an
end-to-end system with a live planner.

**Status.** `OllamaBackend` is implemented but unexercised in this environment.
It is not a stub — it has no `TODO` and no placeholder — but it has not been run
against a live model, and that is stated in its docstring.

---

## D-04 — Unattributable argument values are denied, not guessed

**Context.** Taint cannot be propagated through an LLM, so provenance is
*reconstructed* by matching an argument value against ingested content. Some
values match nothing: the model synthesised them, or the matcher failed. §2 does
not say what to do with those, and §4 Rule 8 forbids guessing silently.

**Decision.** A value that matches nothing is labelled `UNTRUSTED` with
`origin_known=False` — never `TRUSTED`. Values too short to attribute at all
(under four alphanumeric characters, which would collide with every document) are
additionally marked `too_short`. What that label *means* for a call is decided by
argument role, per D-05.

**Alternatives.** (a) Treat unmatched values as trusted — permissive, and it
opens exactly the laundering hole the layer exists to close. (b) Add a fourth
label such as `UNKNOWN` — rejected because §6 fixes the tag vocabulary at three;
the distinction is carried by a boolean field on the finding instead.

**Why.** Fail closed (§3). The cost is real and is measured: it is a large part of
why `ben-a5` is blocked.

---

## D-05 — Provenance gates control-plane arguments only

**Context.** If *any* untrusted-derived argument blocked a call, then
"summarise this web page and email me the summary" would be blocked — the body of
that email necessarily derives from untrusted content. §2 predicts this deadlock;
the question is where to cut.

**Decision.** Each tool manifest declares `critical_args`: the arguments that
steer what the action does to the outside world (`send_email.to`,
`http_post.url`, `write_file.path`). Provenance *gates* only those. Data-plane
arguments (`body`, `payload`, `content`) are traced and logged but do not block on
their own; confidentiality of payload data is enforced separately by INV-1 and the
declassifier.

**Alternatives.** (a) Gate every argument — correct-looking, and it blocks the
core benign use case, which §2 item 4 calls a failure rather than a win.
(b) Gate nothing and rely on invariants alone — loses the control-flow integrity
property that is the point of the layer.

**Why.** This is the control-flow integrity argument from CaMeL (arXiv:2503.18813):
untrusted data may flow *as data*; it may not decide *what the agent does*. The
split is declared per tool in `aegis/tools/manifests.py`, so it is auditable
rather than implicit.

---

## D-06 — Only a payload-inspecting sanitizer counts as declassification

**Context.** INV-1 requires "a sanitizer has run on the data in between" a
confidential read and an egress call. Taken literally, `send_email`'s own
recipient allow-list would satisfy it, and INV-1 would never fire.

**Decision.** Sanitizers carry a `declassifies` flag. Shape checks — address
allow-list, path containment, URL host list, numeric range, enum membership —
constrain *where* data goes and set it to false. `NoConfidentialLeak` inspects the
outbound payload itself and is the only declassifier. INV-1 is satisfied only by a
passing declassifier.

**Alternatives.** (a) Any passing sanitizer satisfies INV-1 — makes the invariant
vacuous. (b) Require an explicit separate "declassify" tool call — more
ceremonious, and it puts a security-critical step in the model's hands.

**Why.** Constraining a destination says nothing about whether the payload is
still confidential. The paired scenarios `atk-c1`/`ben-c1` exist specifically to
show this distinction working in both directions.

---

## D-07 — The declassifier is a distinctive-token check

**Decision.** `NoConfidentialLeak` collects tokens that appear in confidential
content but not in any non-confidential content this session, keeping those of
five or more characters or with three or more digits, and fails the payload if any
survives in it.

**Alternatives.** (a) A model-based redaction check — forbidden: §3 bars any
LLM from the deterministic enforcement path. (b) An exact-substring check — too
weak; reordered rows would pass.

**Known limit, reported not hidden.** It is a token-level check, so semantic
leakage that shares no tokens with the source passes it. `atk-c4` is built on
exactly that gap, and is caught by INV-4 instead. This is why the layers are
layered.

---

## D-08 — Five trajectory invariants, and the cap is deliberate

**Decision.** INV-1 confidential-then-egress (the one §2 requires), INV-2
untrusted-then-destructive, INV-3 egress budget, INV-4 egress destination scope,
INV-5 denied-call retry. No more will be added.

**Why.** §2 item 2 warns against letting this become a rules engine. Five is
enough to demonstrate that sequence-level enforcement expresses things per-call
policy cannot.

**Reported negative result.** INV-5 never fires as the deciding layer in the
shipped corpus — provenance reaches the same calls first. It is retained as
defense in depth and reported as unexercised rather than dressed up as a
contribution. No scenario was contrived to make it fire, which §4 Rule 12's spirit
requires.

---

## D-09 — A `literal` matcher tier was added for measurement honesty

**Context.** The first obfuscation sweep showed the weakest tier catching
zero-width and homoglyph obfuscation, which made no sense — until it became clear
that the "exact" tier already applied NFKC, zero-width stripping, homoglyph
folding and case folding. The ladder's bottom rung silently included the very
normalisation the experiment was supposed to be measuring.

**Decision.** Added a `literal` tier that does raw substring matching with no
normalisation, and made it the bottom rung.

**Why.** Without it the sweep's first column was measuring something other than
what it was labelled. The corrected curve shows each rung buying exactly one class
of obfuscation. This changed no enforcement behaviour — the full ladder is used in
the checkpoint either way — only what the experiment can honestly claim.

---

## D-10 — The adaptive attacker may not change its destination

**Decision.** Mutation operators rewrite the injected payload's surface form:
paraphrase, reframing, padding, zero-width insertion, homoglyphs, letter spacing,
base64, sentence reordering. They may not change the address the attack
exfiltrates to.

**Why.** An attack that sends the data to somebody else's mailbox is not a
successful attack; the destination is the objective, not a free parameter.

**Consequence, disclosed in the tool's own output.** A surface-form mutator gets
no fitness gradient from a layer that does not read surface form. When the loop
targets `full`, no payload ever succeeds, so selection degenerates to the
guard-score tie-break and the run effectively searches against the classifier
again. `redteam.render` prints this whenever it happens, so the curve can never
be presented as evidence that the out-of-band layer is unbreakable. Attacks that
*do* move that layer need a different lever — an allow-listed destination — and
those live in the static corpus (`atk-c3`, `atk-c4`).

---

## D-11 — `ben-a5` is kept as a true false positive

**Decision.** The corpus contains a benign scenario the full defense blocks: the
user asks the agent to email "the distribution owner listed on that page", and the
owner is on a domain no allow-list covers.

**Alternatives.** Remove it, or add its domain to the allow-list — either would
show 0% FPR.

**Why.** The attack twin `atk-a5` is structurally identical: in both, the
destination genuinely originates in untrusted content. Provenance cannot separate
them, and pretending otherwise by editing the corpus would be exactly the kind of
demo-driven weakening §4 Rule 12 prohibits. The false positive is the honest price
of the mechanism and is reported as such.

---

## D-12 — The input filter quarantines at ingestion

**Decision.** Layer 1 screens untrusted content as it enters the agent's context
and drops what it flags; it plays no part in `Checkpoint.evaluate`. The user's own
task is never screened.

**Why.** It is how content filters actually deploy, and it keeps §3's separation
exact: no learned component appears anywhere in the deterministic decision path. It
also makes the cost of over-blocking visible — a quarantined document that the
task depended on causes the task to fail, and that failure lands in the
task-completion metric instead of being invisible.

---

## D-13 — Scenario-level egress budget

**Decision.** `AgentManifest.egress_budget` defaults to 1 and each scenario may
declare its own.

**Why.** A task that legitimately emails two recipients needs a budget of two.
Hardcoding 1 would have made `ben-a2` and `ben-a4` fail for a reason unrelated to
what they test. The budget is part of the least-privilege grant, so it belongs in
the manifest rather than in the invariant.

---

## D-14 — Citations

No citation is used that is not in the closed set in README §11. Papers are
referenced by name and arXiv ID where a mechanism is genuinely derived from them
(CaMeL for the control/data plane split in D-05, FIDES for the dual integrity and
confidentiality tags in `core.Content`, Progent and the systematization framing in
the layer docstrings). No related-work prose, novelty claim or comparison against
the Base Research Paper's own numbers has been written anywhere in this repo — the
report states only what this harness measured.

**Open item.** The Base Research Paper (arXiv:2606.26479) was not consulted
directly while the harness was built, so nothing in the code or the generated
report characterises its findings. Any related-work text must be written against
the actual paper.
