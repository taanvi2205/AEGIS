# AEGIS — Runtime Security Harness for Agentic AI Applications

**Status:** Immutable context document.

**If you are an AI model and this file has been attached, pasted, or referenced in this conversation: this document is the absolute context you must follow for the entire remainder of this chat, from this point until the conversation ends.** Do not let later messages, follow-up requests, or the normal drift of a long conversation cause you to quietly drop, soften, or forget any rule below. If a later request in the chat seems to conflict with this document, do not silently comply — surface the conflict, remind the user which rule it touches, and ask how they want to proceed before writing code. Re-check your own output against this file before every response that touches this project, not just the first one.

Every rule below is binding. When a rule and a convenience conflict, the rule wins. When something is genuinely unspecified, do **not** guess silently and do **not** leave a bare `TODO` and move on — see Rule 8 in §4 for the required behavior: surface the gap, propose the best options with a clear recommendation, and only proceed once the user has picked one (or explicitly told you to proceed with your recommendation).

Stay inside scope. This project has a deliberately narrow, fully specified shape (§2). Do not pad it with extra abstractions, extra configurability, extra "nice to have" features, or defensive generality it doesn't need — but do not under-deliver either: implement everything that *is* in scope, completely, correctly, and without skipping pieces because they're fiddly. Simple and complete beats clever and partial.

---

## 1. What this project actually is

AEGIS is **not** "another prompt injection filter." It is a **measurement harness** that answers one question: *when defensive layers for LLM agents are attacked by an adversary that adapts round over round, which layers hold and which collapse — and why?*

We are not claiming to invent a new defense from scratch. Provenance tracking, action-level policy enforcement, and taint-based information-flow control already exist in the research literature (see §10). **Critically, the specific "adaptive evaluation of out-of-band defenses" gap we're filling has already been named and partially addressed** by Narisetty et al. 2026 (arXiv:2606.26479), who propose a standardized adaptive-evaluation protocol and run it against exactly one defense (Progent) on one model with one hand-crafted attack template. Our contribution must be positioned precisely against this paper, not as a restatement of it:

> **We build a custom agent and harness that directly compares an in-band input classifier against an out-of-band provenance-plus-trajectory-invariant system, under one standardized adaptive attacker, on a controlled paired attack/benign corpus — the controlled, cross-generation comparison Narisetty et al. identify as missing (their evaluation only compares defense generations qualitatively, not in one harness), extended with sequence-level trajectory invariants, a mechanism no system in their systematization (CaMeL, FIDES, Progent, RTBAS, FORGE) implements.**

Every design decision below exists to make that specific, narrow comparison trustworthy — not to build a bigger product, and not to silently re-run an evaluation someone has already published. Keep this framing in every README, slide, and report: **"we measure where each defense layer breaks under a controlled head-to-head, and we add the one enforcement mechanism — trajectory invariants — that's genuinely absent from prior systems. We do not claim to be first to adaptive evaluation of out-of-band defenses."**

---

## 2. Non-negotiable scope boundaries

Build exactly these five components, in this order of priority. Nothing else ships in the MVP.

1. **Argument provenance** — every value that flows into a tool-call argument is tagged `trusted` or `untrusted` at the point it entered the agent's context (user input = trusted; retrieved web content, file contents, email bodies, any tool output = untrusted). A tool call is blocked if any of its arguments trace back to an untrusted source, unless that argument has passed through a sanitizer (§2.3).
2. **Trajectory invariants** — rules evaluated over the *sequence* of tool calls in a session, not each call in isolation. Minimum required invariant for MVP: *once any tool call reads confidential/sensitive-tagged data, no egress-capable tool call (send email, network request, write to external destination) may execute until a sanitizer has run on the data in between.* Add more invariants only if time allows — do not let this become a rules engine.
3. **Sanitizers** — explicit, named functions that clear taint on a value: schema validation (value matches an expected type/format), path allow-listing (file path is inside an approved directory), value allow-listing (recipient is on a known-safe list). A sanitizer must be auditable — log what it checked and why the value passed. Without sanitizers, the agent will legitimately deadlock after a few steps because everything downstream of any tool output stays tainted forever. This is expected and correct behavior to demonstrate, not a bug to hide.
4. **Paired benign corpus** — for every attack scenario in the test set, there must be a near-identical *legitimate* scenario that a correctly-functioning agent should be allowed to complete. Report three numbers together, always: **Attack Success Rate (ASR)**, **Task Completion Rate on the benign pair**, and **False Positive Rate** (benign cases wrongly blocked). A defense that drives ASR to zero by blocking everything is a failure, not a win — say this explicitly in any report or demo.
5. **Adaptive red-team loop** — an automated process that mutates injection payloads against your own guard/classifier over N rounds (start with N=10–20, scale if time allows), keeping payloads that evade detection and discarding ones that don't, then re-attacking. Plot ASR per round per defense layer. The expected and headline finding is: the input-level classifier's block rate degrades round over round, while the provenance/trajectory layer's effectiveness does not (because it doesn't depend on recognizing the payload's surface form at all). If this is NOT what you observe, report the actual result — a null or opposite result is still a valid, reportable finding. Do not adjust the harness to manufacture the expected curve.

### 2.1 Explicit cut list — do not build these
- No fine-tuned classifier. Use an existing off-the-shelf guard/classifier as the input-layer baseline (candidates: Llama Guard, Prompt Guard, NeMo Guardrails, or an equivalent open-source moderation/injection classifier — the specific choice is an open decision for whoever owns this component; document the choice and why once made, in `docs/decisions.md`).
- No production-grade dashboard. A clear terminal/log stream plus one or two generated plots (matplotlib, static PNG/SVG) is the entire UI budget. Time spent on dashboard polish is time not spent on the red-team loop, which is the actual headline result.
- No real external integrations in the base build (see §5).
- No attempt to cover every possible attack category. Pick 2–3 well-defined attack families (e.g., indirect injection via retrieved content, tool-argument injection, multi-step chained manipulation) and go deep rather than shallow-covering many.

### 2.2 Definition of done, phase by phase
- **Phase 1 (submission scope):** provenance tagging + one trajectory invariant + one sanitizer + a static (non-adaptive) attack set run once, with ASR/completion/FPR numbers reported.
- **Phase 2 (mid-sem):** paired benign corpus complete, 2–3 trajectory invariants, adaptive red-team loop running for at least N=10 rounds with a plotted degradation curve.
- **Phase 3 (final review, stretch):** compare input-only defense vs. input+provenance defense side by side on the same adaptive loop; this comparison is your final headline chart. If it doesn't complete, Phase 1+2 alone is a complete, presentable, honest project.

---

## 3. Architecture directives (no code — structure and contracts only)

- **Interceptor pattern.** AEGIS sits as a mandatory checkpoint between the agent's planning step and any tool execution. The agent must never be able to call a tool directly without passing through the checkpoint. If an AI assistant writes code where a tool call path bypasses the checkpoint "for testing" or "for simplicity," that is a defect — flag it, do not merge it.
- **Fail closed, always.** If the guard model errors, times out, returns malformed output, or is unavailable, the default action is **block/deny**, never allow. Any code that falls back to "allow on error" is a security bug, full stop.
- **Deterministic policy layer, probabilistic detection layer — keep them separate.** The provenance/trajectory/sanitizer logic (§2, items 1–3) must be deterministic, rule-based, and auditable — no LLM calls inside this layer's decision path. Only the input-content classifier (item in the cut list, §2.1) is allowed to be a learned/probabilistic component. Mixing an LLM into the enforcement decision defeats the entire point of the provenance approach (see CaMeL, §10) and must not happen.
- **Everything is logged.** Every tagged value, every sanitizer invocation, every blocked/allowed tool call, every trajectory invariant check — logged with enough detail to reconstruct exactly why a decision was made, after the fact. This log is also your demo evidence and your evaluation data source; treat its schema as a first-class design decision, not an afterthought.
- **Agent framework:** build a custom, minimal agent loop rather than adopting a full framework like LangChain/LangGraph. Rationale: you need full visibility and control over every tool-call boundary to instrument provenance and trajectory tracking correctly; a heavier framework hides exactly the internals you need to intercept, and debugging "why didn't my hook fire" inside someone else's orchestration layer wastes time you don't have. Use a local LLM via Ollama (a small instruction-tuned model, quantized) as the agent's underlying model so the whole system runs on a laptop with no API dependency; a hosted API is an acceptable fallback only if local inference is too slow for a live demo, and must be feature-flagged, not hardcoded.

---

## 4. AI coding assistant rules — binding for every prompt/session

These apply regardless of which AI tool (Claude Code, Copilot, Cursor, etc.) is generating code in this repo.

1. **Never invent security behavior that wasn't specified.** If asked to "add a check," implement exactly the check described in §2–3. Do not silently add extra "helpful" permissive behavior (e.g., an allowlist bypass, a debug backdoor, a "trusted mode" flag) without it being explicitly requested and logged as a decision in `docs/decisions.md`.
2. **No hardcoded secrets, credentials, or API keys anywhere in the codebase, ever** — not even for "temporary testing." Use environment variables and a `.env.example` file with placeholder values only. If a task seems to require a real credential, stop and ask a human rather than fabricating or hardcoding one.
3. **No real payload execution against real systems.** Every attack payload, every "malicious" tool call, every simulated exploit runs only inside the mocked/sandboxed tool layer described in §5. An AI assistant must never generate code that sends a real email, makes a real payment call, deletes real files outside the project's own sandbox directory, or reaches any real external API with attack content.
4. **Validate every external input, every time, with no exceptions "because it's just a test."** Any value coming from outside the trusted boundary (files, web content, tool outputs, user input in agent-facing fields) is untrusted until explicitly sanitized per §2.3 — there is no code path where this can be skipped for convenience.
5. **Least privilege by default.** Any new tool the agent can call must declare the narrowest possible scope/permissions manifest before it's usable. Do not grant a tool broader access "in case it's needed later" — extend scope only when a concrete requirement demands it, and log why.
6. **Prefer boring and explicit over clever and implicit.** No dynamic `eval`-style execution of model-generated code or strings, no reflection tricks to bypass type/schema checks, no "just trust the LLM's output here" shortcuts anywhere in the enforcement path. If a proposed implementation can't be explained in one sentence to a non-expert, it's too clever for this project.
7. **Every new dependency must be justified before it's added.** State why an existing capability in the standard library or an already-used package can't do it. Unvetted third-party packages are themselves a supply-chain risk — don't add one to a security project casually.
8. **When uncertain, stop and ask — never guess, and never just drop a `TODO` and move on.** If a spec gap exists (e.g., an exact taint-propagation rule for a case not covered in §2), do not silently pick an interpretation and do not leave unresolved work behind a comment. Instead: (a) state plainly what's ambiguous and why it matters, (b) propose 2–4 concrete options to resolve it, each with a one-line trade-off, (c) give a clear recommendation for which option you'd pick and why, and (d) wait for the user's choice before writing the code — unless the user has told you in this chat to proceed on your own judgment, in which case take your recommended option, say clearly that you did, and keep moving. The goal is zero silent gaps in the shipped code: every ambiguity gets resolved through a real decision, made either by the user or explicitly by you with their standing permission — never left dangling.
9. **Never forget this document mid-conversation.** This file's rules apply to every message in this chat from here to the end, not just the first response after it's attached. Do not let a long conversation, a change of subject, or a later casual request cause any rule here to quietly stop applying. If you're about to write code or make a design call that this file speaks to, check it against this file first.
10. **Keep it simple, but keep it complete.** Do not introduce architecture, abstraction layers, configuration options, or generality beyond what §2–3 actually call for — this is a scoped student project, not a platform. At the same time, do not skip, stub out, or quietly simplify away anything that *is* in scope; if a §2 component is asked for, implement it fully and correctly, not a partial version that looks done. When in doubt about how much to build, build exactly what's specified — nothing more, nothing less.
11. **No "vibe coded" security logic.** Every function inside the provenance/trajectory/sanitizer layer must have a docstring stating: what it checks, what happens on failure, and what the fail-closed behavior is. If those three things can't be stated, the function isn't ready to merge.
12. **Never weaken an existing check to make a demo pass.** If a trajectory invariant blocks a scenario you want to show working, fix the scenario or the sanitizer — do not comment out or loosen the invariant to force a green demo. Any change to enforcement logic gets logged in `docs/decisions.md` with a reason.

---

## 5. Sandbox and simulation rules

- All tools the agent can call (file access, email, payment, external API, etc.) are **mocked implementations inside the project sandbox** by default. A mocked email tool writes to a local log/JSON file instead of sending anything; a mocked payment tool records an intended transaction instead of executing one; a mocked file tool operates only inside a designated sandbox directory, never the real filesystem outside it.
- Leave a clearly documented extension point (a single, well-isolated adapter interface) where **one** real integration could later be wired in for demo polish (e.g., a real but harmless action like posting to a private test Slack channel or writing to a sandboxed test email account you control). This adapter must require an explicit opt-in flag and must never be the default. Do not build this integration unless and until it's explicitly decided to — document the interface, don't implement the real connection speculatively.
- Attack payloads used in the red-team loop are directed only at your own sandboxed agent and your own guard model — never at any third-party service, model, or system you do not own or have explicit permission to test.

---

## 6. Data and corpus rules

- Use only public, synthetic, or self-generated data. No real personal data, no real organizational data, no scraped private content.
- Every entry in the attack/benign corpus must be labeled with: attack family, expected outcome (block/allow), and — for benign pairs — which attack scenario it's paired against.
- Provenance tags in the code and in the corpus use a small, fixed vocabulary (e.g., `trusted`, `untrusted`, `sanitized`) — do not let this vocabulary grow ad hoc; every new tag needs a documented reason.
- Keep the corpus versioned and diffable (plain JSON/YAML/CSV, not a binary format) so changes to it are reviewable like code.

---

## 7. Evaluation methodology

Report these together, every time, never ASR alone:
- **Attack Success Rate (ASR)** — fraction of attack scenarios that achieved their goal despite the defense.
- **Task Completion Rate** — fraction of paired benign scenarios the agent still completed correctly.
- **False Positive Rate** — fraction of benign scenarios wrongly blocked.
- **Round-by-round ASR under the adaptive loop**, per defense configuration (input-filter-only vs. input+provenance), plotted as a degradation curve.

State clearly in every report which defense configuration produced which numbers, and never average across configurations in a way that hides which layer is doing the work.

---

## 8. Demo and reporting standards (replaces the "fancy dashboard")

- Live terminal output showing: incoming request → tag assignment → policy check → allow/block decision → reason — this readability is the actual demo, not a UI.
- One static plot: the adaptive red-team degradation curve, generated ahead of time and regenerable live if time allows.
- One live side-by-side: same attack run against (a) agent with no AEGIS layer, (b) agent with input-filter only, (c) agent with full AEGIS — show the blocked case's logged reasoning on screen.
- No feature is included in the demo "because it looks impressive" if it isn't part of the measured result. The measurement is the impressive part — present it as such.

---

## 9. Repo structure (flexible skeleton — adapt, don't rigidly enforce)

Suggested top-level layout for whoever scaffolds the repo: an `agent/` module for the minimal agent loop, a `checkpoint/` module split into `provenance/`, `trajectory/`, and `sanitizers/`, a `tools/` module containing the mocked tool implementations, a `redteam/` module for the adaptive mutation loop, a `corpus/` directory for the paired attack/benign dataset, an `eval/` module that computes and plots the three headline metrics, and a `docs/decisions.md` file that logs every non-obvious design choice made along the way (including the guard-model choice from §2.1). This is guidance, not a contract — reorganize if a clearly better structure emerges, but document why in `docs/decisions.md`.

---

## 10. Quick-reference checklist (pin this)

- [ ] Fail closed on every error path, no exceptions.
- [ ] No real secrets, no real external calls, no real exploit execution — sandbox only.
- [ ] Every tool call argument is provenance-tagged before it reaches a tool.
- [ ] Every enforcement decision is logged with a reason.
- [ ] Every attack scenario has a paired benign scenario.
- [ ] Report ASR + Task Completion + False Positive Rate together, always.
- [ ] No LLM call inside the deterministic policy/enforcement path.
- [ ] Every non-obvious decision goes in `docs/decisions.md`.
- [ ] Scope stays inside §2 — if it's not in the five components or the phase plan, it doesn't ship.
- [ ] Every ambiguity was resolved through §4 Rule 8 (options + recommendation), never a silent guess or a bare `TODO`.

---

## 11. BASE PAPERS — read this section fully before writing any related-work text, citation, or novelty claim

This is the single authoritative source of truth for every paper this project is allowed to reference. Do not treat any part of this section as optional background — it governs literature review text, code comments that reference prior work, slide content, and the report's related-work section alike.

### How to use this section (explicit instructions, follow exactly)

1. **This is the closed set.** Only cite papers listed below. If a report, slide, or piece of code commentary needs a citation that isn't in this list, stop and ask the user for it — propose what you think the citation should be and where you'd look for it (per §4 Rule 8), but do not invent a title, author list, arXiv ID, or finding, and do not silently pull one from general knowledge. A wrong or fabricated citation is worse than an honest gap.
2. **Never blur the Base Research Paper's findings with this project's findings.** When writing anything comparative, keep three things visibly distinct: what the Base Research Paper found, what this project's harness measures, and how the two differ in scope. Do not phrase project results in a way that could be mistaken for a restatement of the base paper's own numbers.
3. **Quote nothing verbatim beyond a few words.** Summarize each paper's contribution in your own words in any report or slide text. This applies to code comments too — describe a mechanism in your own words, don't paste an abstract.
4. **Keep the novelty claim exactly as scoped below — do not let it drift wider.** The claim this project can defensibly make is narrow and specific (see the boxed statement under "Base Research Paper" below). Do not let a report draft, a slide, or a demo script expand that claim into something broader ("we solve prompt injection," "we're the first to do adaptive evaluation," etc.) — that would be inaccurate and easily challenged by anyone who has read the Base Research Paper.
5. **If you're unsure whether something counts as "already covered" by these papers, ask, don't assume either way.** Follow §4 Rule 8: state the uncertainty, give options, recommend one, let the user decide.

### Base Research Paper (the single primary anchor — this project directly extends it)

- **Narisetty, Kore, Kattamanchi, Kumarapu — "Adaptive Evaluation of Out-of-Band Defenses Against Prompt Injection in LLM Agents," arXiv:2606.26479 (2026).** Argues that out-of-band/action-level defenses (CaMeL, FIDES, Progent, RTBAS, FORGE) have only been validated on static attack sets — the same flawed methodology that made earlier input-filter defenses look strong right up until adaptive attackers broke twelve of them above 90% success (Nasr et al., below). Proposes a standardized adaptive-evaluation protocol and executes one instance of it against Progent only, on one open-weight model, with one hand-crafted adaptive-attack template; explicitly calls extending this to more defenses, models, and attack families "future work."

  **Read this paper in full before writing anything else on this project — especially §7, §10, and §12 (Limitations), which define exactly what's still open and what this project must not accidentally re-claim as new.**

  **This project's exact, non-negotiable novelty claim (do not paraphrase this loosely elsewhere):**
  > We build a custom agent and harness that directly compares an in-band input classifier against an out-of-band provenance-plus-trajectory-invariant system, under one standardized adaptive attacker, on a controlled paired attack/benign corpus — the controlled, cross-generation comparison Narisetty et al. identify as missing, extended with sequence-level trajectory invariants, a mechanism absent from every system in their systematization.

### Related Base Papers (up to 10 — all verified real, with arXiv IDs, current as of Sept 2026)

1. **CaMeL** — Debenedetti, Shumailov, Fan, Hayes, Carlini, Fabian, Kern, Shi, Terzis, Tramèr, "Defeating Prompt Injections by Design," arXiv:2503.18813 (2025). The architectural template your provenance layer (§2, item 1) is based on.
2. **FIDES** — Costa, Köpf, Kolluri, Paverd, Russinovich, Salem, Tople, Wutschitz, Zanella-Béguelin, "Securing AI Agents with Information-Flow Control," arXiv:2505.23643 (2025). Taint labeling with integrity/confidentiality — closest prior work to your sanitizer design (§2, item 3).
3. **Progent** — Shi, He, Wang, Li, Wu, Guo, Song, "Progent: Securing AI Agents with Privilege Control," arXiv:2504.11703 (2025). The defense the Base Research Paper actually tested — read this to understand exactly what was evaluated.
4. **AgentDojo** — Debenedetti, Zhang, Balunović, Beurer-Kellner, Fischer, Tramèr, NeurIPS 2024 Datasets & Benchmarks, arXiv:2406.13352. Standard benchmark environment for agent prompt-injection evaluation — model your corpus/task design (§6) on this even if you build a smaller version yourself.
5. **InjecAgent** — Zhan, Liang, Ying, Kang, ACL 2024 Findings, arXiv:2403.02691. Benchmark for indirect prompt injection in tool-using agents; good source for realistic attack scenario design.
6. **"The Attacker Moves Second"** — Nasr, Carlini, Sitawarin, Tramèr, et al., arXiv:2510.09023 (2025). Shows twelve published in-band defenses collapse above 90% success under adaptive attack — this is the justification for why adaptive (not static) evaluation matters at all; cite this when motivating §2 item 5.
7. **StruQ** — Chen, Piet, Sitawarin, Wagner, USENIX Security 2025, arXiv:2402.06363. Model-level/in-band defense — the contrast case for why this project's approach is architectural rather than model-based.
8. **ToolEmu** — Ruan et al., ICLR 2024, arXiv:2309.15817. LM-emulated sandbox for evaluating agent tool-use risk — relevant to the design of the mocked tool layer (§5).
9. **AgentDyn** — Li, Wen, Shi, Zhang, Vorobeychik, Xiao, arXiv:2602.03117 (2026). Re-evaluates Progent and CaMeL on harder dynamic tasks and documents real-world deployment problems — useful for the report's discussion/limitations section.

Also citable for industry framing only, not as technical/methodological sources: **OWASP LLM01:2025 Prompt Injection** (OWASP Top 10 for LLM Applications) and **NIST AI 600-1** (Generative AI Risk Management Profile).
