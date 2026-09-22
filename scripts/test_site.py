"""Regression tests for static publication trust boundaries."""

from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from scripts.check_site import ROOT, ValidationError, validate


class PublicationValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        shutil.copytree(ROOT / 'dist', self.root / 'dist')
        shutil.copytree(ROOT / 'security', self.root / 'security')

    def tearDown(self):
        self.temporary.cleanup()

    @property
    def trust_path(self):
        return self.root / 'security' / 'approved-publication.json'

    def trust(self):
        return json.loads(self.trust_path.read_text())

    def write_trust(self, trust):
        self.trust_path.write_text(json.dumps(trust, indent=2, ensure_ascii=False) + '\n')

    def rehash(self, relative):
        trust = self.trust()
        raw = (self.root / 'dist' / relative).read_bytes()
        trust['publication_files'][relative]['sha256'] = sha256(raw).hexdigest()
        trust['publication_files'][relative]['size'] = len(raw)
        self.write_trust(trust)

    def mutate_index(self, old, new):
        path = self.root / 'dist' / 'index.html'
        html = path.read_text()
        self.assertIn(old, html)
        path.write_text(html.replace(old, new, 1))
        self.rehash('index.html')

    def assert_rejected(self, pattern):
        with self.assertRaisesRegex(ValidationError, pattern):
            validate(self.root)

    def test_current_publication_passes(self):
        validate(self.root)

    def test_optimized_python_fails_closed(self):
        result = subprocess.run(
            [sys.executable, '-O', str(ROOT / 'scripts' / 'check_site.py')],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Optimized Python is forbidden', result.stderr)

    def test_unlisted_file_is_rejected_even_if_manifest_is_extended(self):
        extra = self.root / 'dist' / 'alternate.html'
        extra.write_text('<!doctype html><title>Unreviewed</title>')
        trust = self.trust()
        raw = extra.read_bytes()
        trust['publication_files']['alternate.html'] = {
            'media_type': 'text/html',
            'sha256': sha256(raw).hexdigest(),
            'size': len(raw),
        }
        self.write_trust(trust)
        self.assert_rejected('unsupported publication path')

    def test_publication_symlink_is_rejected(self):
        favicon = self.root / 'dist' / 'favicon.svg'
        outside = self.root / 'outside.svg'
        favicon.replace(outside)
        favicon.symlink_to(outside)
        self.assert_rejected('symlink')

    def test_inline_event_handler_is_rejected_after_digest_rotation(self):
        self.mutate_index('<main>', '<main onclick="alert(1)">')
        self.assert_rejected('Unsupported attribute|Event handler')

    def test_remote_stylesheet_is_rejected_after_digest_rotation(self):
        self.mutate_index('href="styles.css"', 'href="https://example.invalid/tracker.css"')
        self.assert_rejected('Unapproved external navigation')

    def test_meta_refresh_is_rejected_after_digest_rotation(self):
        self.mutate_index('</head>', '<meta http-equiv="refresh" content="0;url=https://example.invalid">\n</head>')
        self.assert_rejected('Meta declarations differ')

    def test_css_import_is_rejected_after_digest_rotation(self):
        path = self.root / 'dist' / 'styles.css'
        path.write_text('@import "https://example.invalid/tracker.css";\n' + path.read_text())
        self.rehash('styles.css')
        self.assert_rejected('Forbidden CSS construct')

    def test_css_escape_at_rule_is_rejected_after_digest_rotation(self):
        path = self.root / 'dist' / 'styles.css'
        path.write_text('@\\69mport "https://example.invalid/tracker.css";\n' + path.read_text())
        self.rehash('styles.css')
        self.assert_rejected('CSS escapes')

    def test_css_cannot_hide_evidence_after_digest_rotation(self):
        path = self.root / 'dist' / 'styles.css'
        path.write_text(path.read_text() + '\n.rate{display:none}\n')
        self.rehash('styles.css')
        self.assert_rejected('display:none|Forbidden CSS construct')

    def test_active_svg_is_rejected_after_digest_rotation(self):
        path = self.root / 'dist' / 'favicon.svg'
        svg = path.read_text().replace('</svg>', '<script>alert(1)</script></svg>')
        path.write_text(svg)
        self.rehash('favicon.svg')
        self.assert_rejected('Unexpected SVG element count|Unsupported SVG element')

    def test_hidden_evidence_row_is_rejected_after_digest_rotation(self):
        self.mutate_index('<tr data-result="duel"', '<tr hidden data-result="duel"')
        self.assert_rejected('Unsupported attribute|hidden')

    def test_duplicate_value_marker_is_rejected_after_digest_rotation(self):
        self.mutate_index('>74.5%</td>', '>74.5%<span data-value="mean">74.5%</span></td>')
        self.assert_rejected('Duplicate visible value')

    def test_trailing_rate_claim_is_rejected_after_digest_rotation(self):
        self.mutate_index('>74.5%</td>', '>74.5% misleading</td>')
        self.assert_rejected('Wrong visible rate')

    def test_visible_rule_label_is_rejected_after_digest_rotation(self):
        self.mutate_index('>Single-loser-agree</th>', '>Classic</th>')
        self.assert_rejected('Visible row label differs')

    def test_co_mutable_bundle_cannot_replace_independent_evidence_anchor(self):
        summary_path = self.root / 'dist' / 'evidence' / 'confirmation-summary.json'
        summary = json.loads(summary_path.read_text())
        summary['policy_details']['truthful']['description'] += ' Altered.'
        summary_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False) + '\n')
        summary_digest = sha256(summary_path.read_bytes()).hexdigest()

        provenance_path = self.root / 'dist' / 'evidence' / 'provenance.json'
        provenance = json.loads(provenance_path.read_text())
        provenance['confirmation_summary_sha256'] = summary_digest
        provenance_path.write_text(json.dumps(provenance, indent=2, ensure_ascii=False) + '\n')
        self.rehash('evidence/confirmation-summary.json')
        self.rehash('evidence/provenance.json')
        self.assert_rejected('independently approved digest')


if __name__ == '__main__':
    unittest.main()
