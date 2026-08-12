# Interoperability and provenance

This document records where the interchange support in ThreatForge came from,
because the honest answer is worth writing down rather than leaving to
inference.

## What is implemented

ThreatForge can read and write a YAML threat-model interchange document
(`.thf`), and can read a native overlay format (`threatforge-overlay.yml`).

| Direction | Format | Module | Purpose |
|---|---|---|---|
| Read | overlay / `.thf` | `threatforge/ingest/manual.py` | Merge a hand-drawn model into the scanned graph |
| Read | `.tm7` | `threatforge/ingest/tmt.py` | Import existing Microsoft Threat Modeling Tool models |
| Read | `.drawio` | `threatforge/ingest/drawio.py` | Import diagrams drawn in draw.io / diagrams.net |
| Write | `.thf` | `threatforge/render/thf.py` | Export a generated model for editing in a graphical tool |
| Write | `.tm7` | `threatforge/render/tmt.py` | Export a generated model for opening in Microsoft TMT |
| Write | `.drawio` | `threatforge/render/drawio.py` | Export an editable, risk-coloured draw.io diagram |

`.drawio` is mxGraph XML. draw.io itself is Apache-2.0, but no draw.io code is
used here either — the reader and writer are independent implementations against
the mxGraph data format.

`.tm7` is **Microsoft's** format — a .NET DataContract XML dialect emitted by the
Microsoft Threat Modeling Tool. Both the reader and the writer were built against
that schema and a sample document. Neither is derived from any other
implementation.

### What "integrating TMT" can and cannot mean

The Microsoft Threat Modeling Tool is proprietary Windows software distributed
under its own licence. It ships no CLI, no API, and no SDK, and it cannot be
redistributed. So the *application* cannot be embedded, invoked, or bundled —
not for licensing reasons alone, but because there is no automation surface to
call.

What can be integrated is its **data**, and that is now bidirectional: read
`.tm7`, analyse, write `.tm7`. Users keep TMT as their editor if they want it;
ThreatForge supplies the analysis.

**Export verification:** schema-conformant and round-trips through our own
importer with no loss of elements, flows or boundaries. Not yet opened in TMT
itself, which requires Windows. Until someone does, treat TMT compatibility as
expected rather than proven.

Both handle the same vocabulary: `elements` (process, data store, external
entity), `data_flows`, `trust_boundaries`, and `threats`.

## Why this is clean

**No third-party source code is included in this project.** Not copied, not
translated, not ported, not machine-converted.

The implementations here were written against the *observed structure of data
files* — the shape of the YAML, its key names, and the values those keys take.
That is interoperability, and it is the ordinary way file format support gets
written.

Three separate reasons this is legitimate:

1. **A file format is not a work of authorship.** Copyright protects a
   particular expression, not a data layout. Reading and writing a format is
   not reproduction of anyone's code.
2. **Nothing was derived.** Any editor implementing this format does so in its
   own language and architecture. Our reader is Python operating on our own
   `Asset` / `Flow` / `Boundary` model, written from scratch, and it does not
   resemble another implementation because it was not looking at one.
3. **Interoperability is the point.** The purpose is to let models move
   *between* tools, which benefits users of every tool involved, including the
   ones we interoperate with.

## What was deliberately not done

While evaluating interoperability we reviewed a graphical threat-modelling
application released under Apache-2.0. We did **not**:

- copy, adapt or translate any of its source code;
- reuse its icon registry, which carries its own separate ISC, MIT, CC0-1.0 and
  Apache-2.0 attribution obligations;
- reuse its documentation, test fixtures, or branding.

Had any of that been incorporated, Apache-2.0 §4 would require us to retain the
copyright notice, ship the licence text, preserve the NOTICE file, and state
that changes were made. Those obligations are cheap and we would have met them.
We simply have nothing to attribute, because nothing was taken.

**If you contribute code to this project that is derived from another project,
say so in the pull request.** It is almost always fine — permissive licences
are permissive — but it has to be declared so the attribution can be recorded
correctly. Silent inclusion is the only version that causes a problem, and it
tends to surface later through code-similarity scanning, at the worst possible
moment.

## Scanning untrusted sources

The app can scan a git repository or an uploaded archive. Both are code you did
not write, so they are marked untrusted and treated accordingly:

* **Helm and Kustomize rendering are disabled.** `helm template` and
  `kustomize build` execute logic from the scanned repository. For your own code
  that is the point; for a stranger's it is remote code execution.
* **Git URLs are validated before they reach a subprocess** — no shell strings,
  `--` before user input, and a host allowlist, because "clone any URL" is a
  request-forgery primitive against internal git servers.
* **Archive members are resolved before extraction** and refused if they land
  outside the target directory, with size, member-count and compression-ratio
  limits on top.

The trade is visible in the UI rather than hidden: an untrusted scan says so,
and says what was disabled.

## Round-trip behaviour

Export then re-import preserves every asset id, every data store, and every
trust boundary. Two deliberate exceptions:

- **Control edges are not data flows.** `runs` (workload → container) and
  `protects` (NetworkPolicy → workload) describe structure and policy, not data
  movement, so they are omitted from `data_flows`. They are recreated on the
  next scan of the original manifests.
- **Containers are folded into their workload** unless they carry a finding.
  A forty-service cluster would otherwise export as an unreadable diagram with
  several hundred nodes.

Neither loses information you cannot regenerate, because the manifests remain
the source of truth. The interchange document is a *view*, not a replacement.

## The intended workflow

```
  manifests ──scan──> model ──export──> .thf ──edit by hand──┐
      ▲                                                      │
      └──────────── next scan merges both ◀──────────────────┘
                    (overlay + manifests)
```

1. Scan the repository. The scanner finds what is declared.
2. Export `threat-model.thf` and open it in a diagram editor, or write a
   `threatforge-overlay.yml` by hand.
3. Add what static analysis cannot see: third-party SaaS, on-premises systems,
   human actors, anything reached over a VPN.
4. Commit the overlay next to your manifests. Every subsequent scan merges it,
   so those components participate in reachability, blast radius and attack
   paths exactly like a scanned asset.

## The DFD editor

`threatforge serve` renders the model on an interactive canvas. Diagram and
editor share one renderer, so what you read is exactly what you edit.

* **Scroll to zoom, drag the background to pan, drag a node to move it.**
* **Nodes are coloured by their worst active finding**, not by type — the
  diagram is a heat map, and a node with no colour has no open findings.
* **A red edge is unencrypted.** Dashed means encryption could not be
  determined from the manifests, which is a different claim from "plaintext"
  and is drawn differently on purpose.
* **A green dot marks a hand-added element.** Only those can be edited or
  deleted; a scanned asset is owned by its manifest, and the editor says so
  rather than letting you delete something that reappears on the next scan.
* **Select a node or a flow** to edit its name, type, trust zone, data classes,
  description, protocol and encryption state in the properties panel.
* `Delete` removes the selection, `Ctrl+Z` undoes, `Escape` cancels connect
  mode. **Auto-layout** arranges components in columns by hops from the
  internet — the order an attacker walks them.

**Save & re-scan** writes the hand-authored elements to the overlay and re-runs
the whole pipeline. Only hand-authored content is written; scanned elements are
never echoed back, or each scan would re-import the last one's output.

The point of the editor is that what you draw is analysed, not merely drawn. A
partner system talking plaintext across a trust boundary is invisible to static
analysis and obvious to a human; draw it and `TF-FLOW-006` fires on the next
scan, with the protocol you entered as its evidence.

Use `attach_to` to annotate an asset the scanner already found, rather than
creating a duplicate beside it:

```yaml
components:
  - attach_to: k8s:StatefulSet:shop/postgres
    tags: [crown-jewel, gdpr-in-scope]
    data: [pii]
```

If the id does not resolve, the scan reports it as a parse warning rather than
silently ignoring it — a typo in an overlay would otherwise quietly remove a
node from the analysis.
