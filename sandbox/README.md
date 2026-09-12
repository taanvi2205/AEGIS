# Sandbox

The only directory any AEGIS tool may touch. The `sandbox_path` sanitizer
resolves symlinks and `..` and rejects anything that lands outside this root.

- `workspace/` — the mocked file tools' working directory. Scenario files are
  supplied in-memory by `corpus/scenarios.json`, so this stays empty unless a run
  writes to it.
- `outbox/` — where the mocked email, HTTP and payment tools record *intended*
  outbound actions as JSON. Nothing is ever delivered; each record carries
  `"delivered": false`. Git-ignored.
