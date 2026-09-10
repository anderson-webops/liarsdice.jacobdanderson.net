# Liar’s Dice Strategy Results

A concise strategy and counterstrategy recap in the same visual style as the Incan Gold results page. It presents probability-based heads-up strategies, multiplayer results by ruleset, supported targeted counters, and the limits of the simulation evidence.

[Hosted site](https://liars-dice-strategy-results.jacoba1100254352.chatgpt.site) · [Public source](https://github.com/anderson-webops/liarsdice.jacobdanderson.net)

The source repository is public. The Sites publication is owner-private. The repository name does not establish that `liarsdice.jacobdanderson.net` is serving this content. Custom-domain routing is managed separately.

## Run and validate

This is a static page with no JavaScript, package dependencies, or build step. The authored, tracked `dist/` directory is the deployable site and can also be served directly by Nginx.

```sh
python3 -m http.server 4175 --bind 127.0.0.1 --directory dist
python3 scripts/check_site.py
```

Validation checks local assets and anchors, structural HTML, every displayed result and parameter against the bundled evidence, and its SHA-256. It does not substitute for browser testing or prove a custom domain is live.

## Evidence and interpretation

The completed September 9, 2026 research contains 7,180,416 games. Only the 3,377,152 games reserved for final confirmation support the published statistical claims. The frozen experiment covers seven simulator rule profiles, two through six players, and five starting dice. All research games used strict action checks without corrections.

`dist/evidence/confirmation-summary.json` is an unchanged copy of the simulator’s `research_results/2026-09-07/confirmation-summary.json`. `dist/evidence/provenance.json` records its hash, source-document hashes and execution-source hashes. The full snapshot includes paired differences, all 35 mixed-field settings, opponent-specific results, and selected policy parameters.

The page’s heads-up average equally weights its profile’s frozen challenger population, including analytic 50% self-play. The separate mixed-field averages give four panels equal weight. Supported counters exceed the symmetric `1 / players` reference against copies of one frozen target. All reported intervals use the simultaneous 95% family of 5,180 estimates. Observed leaders are not automatically statistically distinguished winners.

## Publication guidelines

- Keep the recap focused and match labels, values, rules and limitations to the saved evidence. Preserve the original snapshot; use a separately verified snapshot for future research updates.
- Preserve the distinction between heads-up field averages, mixed tables and targeted counters. Do not claim universal optimality or measured performance against human players.
- Keep all source on `main`, validate before committing, and push the exact validated revision to both the public repository and the Sites source remote before saving a deployment version.
- Publish only the `dist/` assets. Keep local working files and credentials out of Git and published artifacts. The Sites manifest contains identifiers and static-directory configuration only.
- Treat source publication, Sites deployment, and verification of the custom domain as separate states. Do not alter DNS or external routing without explicit authorization for the exact change.
