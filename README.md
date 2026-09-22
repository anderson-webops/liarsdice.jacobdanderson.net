# Liar’s Dice Strategy Results

A concise strategy and counterstrategy recap in the same visual style as the Incan Gold results page. It presents probability-based heads-up strategies, multiplayer results by ruleset, supported targeted counters, and the limits of the simulation evidence.

[Hosted site](https://liars-dice-strategy-results.jacoba1100254352.chatgpt.site) · [Public source](https://github.com/anderson-webops/liarsdice.jacobdanderson.net)

The source repository is public. The Sites publication is owner-private. The repository name does not establish that `liarsdice.jacobdanderson.net` is serving this content. Custom-domain routing is managed separately.

## Run and validate

This is a static page with no JavaScript, package dependencies, application server, database, worker, writable state, or build-time framework. The authored, tracked `dist/` directory is the deployable site and can also be served directly by Nginx. This is the minimum resident-memory topology: Nginx or the static host serves files without a site-specific Node process.

```sh
python3 -m http.server 4175 --bind 127.0.0.1 --directory dist
python3 -I -B scripts/check_site.py
python3 -B -m unittest -v scripts.test_site scripts.test_release_artifact
```

Validation fails closed under optimized Python. It checks the complete deployable file inventory and digests against the owner-reviewed anchor in `security/approved-publication.json`, rejects symlinks and unexpected files, enforces a passive browser-content policy across HTML/CSS/SVG, checks visible result labels and values against the evidence, and validates the evidence against the independently reviewed digest and source hashes. Regression tests exercise active-content, hidden-marker, visible-label, unlisted-file, symlink, optimized-interpreter, and co-mutable-provenance bypasses. It does not prove a custom domain is live.

## Release artifact

Create release assets only from a clean committed checkout. The builder emits a deterministic static archive, complete file/source manifest, and checksums; the verifier rejects path traversal, links, duplicate or missing members, digest drift, dirty source identity, and an unexpected commit or version. Verification unpacks the exact archive into an isolated temporary tree and reruns the publication policy.

```sh
release_dir="$(mktemp -d)"
python3 -I -B scripts/release_artifact.py build --output-dir "$release_dir"
python3 -I -B scripts/release_artifact.py verify \
  --release-dir "$release_dir" \
  --expected-commit "$(git rev-parse HEAD)" \
  --expected-version "$(tr -d '\r\n' < VERSION)"
```

The three release assets are the source-bound `.tar.gz`, `release-manifest.json`, and `SHA256SUMS`. The archive contains only `dist/`; the control manifest and trust anchor are never placed under the published static root.

## Evidence and interpretation

The completed September 9, 2026 research contains 7,180,416 games. Only the 3,377,152 games reserved for final confirmation support the published statistical claims. The frozen experiment covers seven simulator rule profiles, two through six players, and five starting dice. All research games used strict action checks without corrections.

`dist/evidence/confirmation-summary.json` is an unchanged copy of the simulator’s `research_results/2026-09-07/confirmation-summary.json`. `dist/evidence/provenance.json` records its hash, source-document hashes and execution-source hashes. The separately owned `security/approved-publication.json` is the publication trust anchor; it must be rotated only after independently reviewing the authoritative research inputs. The full snapshot includes paired differences, all 35 mixed-field settings, opponent-specific results, and selected policy parameters.

The page’s heads-up average equally weights its profile’s frozen challenger population, including analytic 50% self-play. The separate mixed-field averages give four panels equal weight. Supported counters exceed the symmetric `1 / players` reference against copies of one frozen target. All reported intervals use the simultaneous 95% family of 5,180 estimates. Observed leaders are not automatically statistically distinguished winners.

## Publication guidelines

- Keep the recap focused and match labels, values, rules and limitations to the saved evidence. Preserve the original snapshot; use a separately verified snapshot for future research updates.
- Preserve the distinction between heads-up field averages, mixed tables and targeted counters. Do not claim universal optimality or measured performance against human players.
- Changes to `dist/`, the evidence trust anchor, validator, tests, or release workflow require the repository code owner. Treat a changed bundled digest as an internal consistency update until the independently reviewed trust anchor is deliberately rotated.
- Keep all source on `main`, validate before committing, and push the exact validated revision to both the public repository and the Sites source remote before saving a deployment version.
- Publish only the `dist/` assets. Keep local working files and credentials out of Git and published artifacts. The Sites manifest contains identifiers and static-directory configuration only.
- Treat source publication, Sites deployment, and verification of the custom domain as separate states. Do not alter DNS or external routing without explicit authorization for the exact change.
- Static hosting must retain `Content-Security-Policy: default-src 'none'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; script-src 'none'`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`. The document carries equivalent CSP/referrer meta defenses, but response headers remain the deployment authority.
- Monitor the existing static root or published release identity. Do not add artificial health APIs or a resident application process.
