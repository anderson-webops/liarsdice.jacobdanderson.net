"""Regression tests for immutable static release artifacts."""

from __future__ import annotations

from hashlib import sha256
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

from scripts.check_site import ROOT, ValidationError
from scripts.release_artifact import build_release, verify_release


COMMIT = 'a' * 40


class ReleaseArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / 'source'
        self.release = Path(self.temporary.name) / 'release'
        self.root.mkdir()
        shutil.copytree(ROOT / 'dist', self.root / 'dist')
        shutil.copytree(ROOT / 'security', self.root / 'security')
        (self.root / 'VERSION').write_text('1.0.0\n')
        self.manifest = build_release(
            self.root,
            self.release,
            source_commit=COMMIT,
            source_clean=True,
            require_clean=False,
        )

    def tearDown(self):
        self.temporary.cleanup()

    @property
    def archive_path(self):
        return self.release / self.manifest['archive']['name']

    @property
    def manifest_path(self):
        return self.release / 'release-manifest.json'

    def write_manifest_and_checksums(self, manifest):
        self.manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n')
        self.manifest = manifest
        (self.release / 'SHA256SUMS').write_text(
            f'{sha256(self.archive_path.read_bytes()).hexdigest()}  {self.archive_path.name}\n'
            f'{sha256(self.manifest_path.read_bytes()).hexdigest()}  release-manifest.json\n'
        )

    def test_exact_release_passes(self):
        result = verify_release(self.root, self.release, expected_commit=COMMIT, expected_version='1.0.0')
        self.assertEqual(result['source_commit'], COMMIT)

    def test_isolated_cli_loads_sibling_validator(self):
        result = subprocess.run(
            [sys.executable, '-I', '-B', str(ROOT / 'scripts' / 'release_artifact.py'), '--help'],
            cwd=self.temporary.name,
            check=False,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Build and verify the immutable static publication artifact', result.stdout)

    def test_wrong_expected_commit_is_rejected(self):
        with self.assertRaisesRegex(ValidationError, 'expected commit'):
            verify_release(self.root, self.release, expected_commit='b' * 40)

    def test_tampered_archive_is_rejected(self):
        with self.archive_path.open('ab') as handle:
            handle.write(b'tampered')
        with self.assertRaisesRegex(ValidationError, 'size differs'):
            verify_release(self.root, self.release, expected_commit=COMMIT)

    def test_symlink_member_is_rejected_even_with_updated_archive_digest(self):
        malicious = self.archive_path.with_suffix('.malicious')
        with tarfile.open(malicious, 'w:gz') as archive:
            member = tarfile.TarInfo('dist/index.html')
            member.type = tarfile.SYMTYPE
            member.linkname = '/etc/passwd'
            archive.addfile(member)
        malicious.replace(self.archive_path)
        manifest = json.loads(self.manifest_path.read_text())
        manifest['archive']['sha256'] = sha256(self.archive_path.read_bytes()).hexdigest()
        manifest['archive']['size'] = self.archive_path.stat().st_size
        self.write_manifest_and_checksums(manifest)
        with self.assertRaisesRegex(ValidationError, 'member inventory|Unsupported archive member'):
            verify_release(self.root, self.release, expected_commit=COMMIT)

    def test_duplicate_member_is_rejected_even_with_updated_archive_digest(self):
        records = {record['path']: record for record in self.manifest['files']}
        malicious = self.archive_path.with_suffix('.malicious')
        with tarfile.open(malicious, 'w:gz') as archive:
            for name, record in records.items():
                raw = (self.root / name).read_bytes()
                member = tarfile.TarInfo(name)
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
            raw = (self.root / 'dist/index.html').read_bytes()
            duplicate = tarfile.TarInfo('dist/index.html')
            duplicate.size = len(raw)
            archive.addfile(duplicate, io.BytesIO(raw))
        malicious.replace(self.archive_path)
        manifest = json.loads(self.manifest_path.read_text())
        manifest['archive']['sha256'] = sha256(self.archive_path.read_bytes()).hexdigest()
        manifest['archive']['size'] = self.archive_path.stat().st_size
        self.write_manifest_and_checksums(manifest)
        with self.assertRaisesRegex(ValidationError, 'member inventory'):
            verify_release(self.root, self.release, expected_commit=COMMIT)


if __name__ == '__main__':
    unittest.main()
