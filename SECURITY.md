# Security policy

## Reporting a vulnerability

Email <security@YOUR-ORG.example> rather than opening a public issue. Include
reproduction steps and, if possible, a minimal manifest that triggers the
behaviour. Expect an acknowledgement within three working days.

## Threat model of the tool itself

ThreatForge parses untrusted input, so it is worth being explicit about what it
does and does not do with it.

- **YAML is parsed with `yaml.SafeLoader`.** No arbitrary object construction.
  Unknown tags are coerced to scalars rather than resolved.
- **No manifest content is executed.** Dockerfile `RUN` lines are read as text.
- **`helm template` and `kubectl kustomize` are subprocesses** that run against
  the scanned repository. Both can execute chart logic, so treat scanning an
  untrusted repository the same way you would treat running its build. Disable
  with `helm: {render: false}` and `kustomize: {render: false}`.
- **`--live` reads from your current kubectl context.** Secret *values* are
  redacted at collection; only key names are retained.
- **No network egress.** The tool makes no outbound calls. The HTML report loads
  Chart.js and Mermaid from a CDN when opened in a browser and degrades
  gracefully offline.
- **Reports may contain sensitive material.** Findings quote configuration —
  including credential *names*, hostnames, and file paths. Treat
  `threatforge-out/` as sensitive and keep it out of version control
  (`.gitignore` covers it).
