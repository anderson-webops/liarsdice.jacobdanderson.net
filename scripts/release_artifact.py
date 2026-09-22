"""Build and verify the immutable static publication artifact."""

from __future__ import annotations

import argparse
import gzip
from hashlib import sha256
import importlib.util
import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tempfile

if __package__:
    from scripts.check_site import MAX_TOTAL_BYTES, ROOT, ValidationError, load_json, read_regular, require, validate
else:
    validator_path = Path(__file__).resolve().with_name('check_site.py')
    validator_spec = importlib.util.spec_from_file_location('liarsdice_check_site', validator_path)
    if validator_spec is None or validator_spec.loader is None:
        raise ImportError(f'Cannot load publication validator: {validator_path}')
    validator = importlib.util.module_from_spec(validator_spec)
    validator_spec.loader.exec_module(validator)
    MAX_TOTAL_BYTES = validator.MAX_TOTAL_BYTES
    ROOT = validator.ROOT
    ValidationError = validator.ValidationError
    load_json = validator.load_json
    read_regular = validator.read_regular
    require = validator.require
    validate = validator.validate


SCHEMA_VERSION = 1
MANIFEST_NAME = 'release-manifest.json'
CHECKSUM_NAME = 'SHA256SUMS'


def file_digest(path: Path) -> str:
    digest = sha256()
    with path.open('rb') as handle:
        while chunk := handle.read(128 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def git_output(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ['git', '-C', str(root), *arguments],
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.strip()


def source_identity(root: Path, require_clean: bool) -> tuple[str, bool]:
    commit = git_output(root, 'rev-parse', 'HEAD')
    require(re.fullmatch(r'[0-9a-f]{40}', commit) is not None, 'Invalid source commit')
    clean = not git_output(root, 'status', '--porcelain', '--untracked-files=all')
    require(clean or not require_clean, 'Release artifacts require a clean checkout')
    return commit, clean


def normalized_tar_info(name: str, size: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o644
    info.mtime = 0
    info.uid = 0
    info.gid = 0
    info.uname = ''
    info.gname = ''
    return info


def build_release(
    root: Path,
    output_dir: Path,
    *,
    source_commit: str | None = None,
    source_clean: bool | None = None,
    require_clean: bool = True,
) -> dict:
    root = root.resolve()
    validate(root)
    version = (root / 'VERSION').read_text().strip()
    require(re.fullmatch(r'\d+\.\d+\.\d+', version) is not None, 'VERSION must be semantic')
    if source_commit is None or source_clean is None:
        source_commit, source_clean = source_identity(root, require_clean)
    require(re.fullmatch(r'[0-9a-f]{40}', source_commit) is not None, 'Invalid source commit')
    require(source_clean or not require_clean, 'Release artifacts require a clean checkout')

    trust_path = root / 'security' / 'approved-publication.json'
    trust_raw = trust_path.read_bytes()
    trust = json.loads(trust_raw)
    records = []
    for name, approved in sorted(trust['publication_files'].items()):
        path = root / 'dist' / name
        raw = path.read_bytes()
        require(len(raw) == approved['size'] and sha256(raw).hexdigest() == approved['sha256'], f'Publication changed before packaging: {name}')
        records.append({
            'media_type': approved['media_type'],
            'path': f'dist/{name}',
            'sha256': approved['sha256'],
            'size': approved['size'],
        })

    output_dir.mkdir(parents=True, exist_ok=True)
    archive_name = f'liarsdice-site-v{version}-{source_commit[:12]}.tar.gz'
    archive_path = output_dir / archive_name
    with archive_path.open('wb') as destination:
        with gzip.GzipFile(filename='', mode='wb', fileobj=destination, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
                for record in records:
                    raw = (root / record['path']).read_bytes()
                    archive.addfile(normalized_tar_info(record['path'], len(raw)), io.BytesIO(raw))

    manifest = {
        'document_type': 'liarsdice.static-release',
        'schema_version': SCHEMA_VERSION,
        'version': version,
        'source_commit': source_commit,
        'source_clean': bool(source_clean),
        'approved_publication_sha256': sha256(trust_raw).hexdigest(),
        'archive': {
            'name': archive_name,
            'sha256': file_digest(archive_path),
            'size': archive_path.stat().st_size,
        },
        'files': records,
    }
    manifest_path = output_dir / MANIFEST_NAME
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + '\n')
    checksum_path = output_dir / CHECKSUM_NAME
    checksum_path.write_text(
        f'{file_digest(archive_path)}  {archive_name}\n'
        f'{file_digest(manifest_path)}  {MANIFEST_NAME}\n'
    )
    return manifest


def safe_archive_members(archive_path: Path, expected: dict[str, dict]) -> dict[str, bytes]:
    require(archive_path.stat().st_size <= MAX_TOTAL_BYTES, 'Compressed archive exceeds size limit')
    extracted = {}
    total = 0
    with tarfile.open(archive_path, mode='r:gz') as archive:
        members = archive.getmembers()
        require(len(members) == len(expected), 'Archive member inventory differs from manifest')
        for member in members:
            path = PurePosixPath(member.name)
            require(not path.is_absolute() and '..' not in path.parts, f'Unsafe archive path: {member.name}')
            require(len(path.parts) <= 4 and len(member.name.encode()) <= 512, f'Archive path limit exceeded: {member.name}')
            require(member.isfile() and not member.issym() and not member.islnk(), f'Unsupported archive member: {member.name}')
            require(member.name in expected, f'Unexpected archive member: {member.name}')
            require(member.size == expected[member.name]['size'], f'Archive member size mismatch: {member.name}')
            total += member.size
            require(total <= MAX_TOTAL_BYTES, 'Expanded archive exceeds size limit')
            handle = archive.extractfile(member)
            require(handle is not None, f'Cannot read archive member: {member.name}')
            raw = handle.read(member.size + 1)
            require(len(raw) == member.size, f'Archive member changed while reading: {member.name}')
            require(sha256(raw).hexdigest() == expected[member.name]['sha256'], f'Archive member digest mismatch: {member.name}')
            require(member.name not in extracted, f'Duplicate archive member: {member.name}')
            extracted[member.name] = raw
    require(set(extracted) == set(expected), 'Archive is missing a required member')
    return extracted


def verify_release(
    root: Path,
    release_dir: Path,
    *,
    expected_commit: str | None = None,
    expected_version: str | None = None,
) -> dict:
    root = root.resolve()
    release_dir = release_dir.resolve()
    manifest_raw, manifest = load_json(release_dir / MANIFEST_NAME, 128 * 1024)
    require(set(manifest) == {'document_type', 'schema_version', 'version', 'source_commit', 'source_clean', 'approved_publication_sha256', 'archive', 'files'}, 'Unexpected release-manifest fields')
    require(manifest.get('document_type') == 'liarsdice.static-release', 'Unexpected release document type')
    require(manifest.get('schema_version') == SCHEMA_VERSION, 'Unsupported release schema')
    require(manifest.get('source_clean') is True, 'Release source was not clean')
    require(re.fullmatch(r'[0-9a-f]{40}', manifest.get('source_commit', '')) is not None, 'Invalid release source commit')
    require(re.fullmatch(r'\d+\.\d+\.\d+', manifest.get('version', '')) is not None, 'Invalid release version')
    if expected_commit is not None:
        require(manifest['source_commit'] == expected_commit, 'Release source commit differs from expected commit')
    if expected_version is not None:
        require(manifest['version'] == expected_version, 'Release version differs from expected version')

    trust_path = root / 'security' / 'approved-publication.json'
    trust_raw, trust = load_json(trust_path, 128 * 1024)
    require(manifest['approved_publication_sha256'] == sha256(trust_raw).hexdigest(), 'Release trust anchor differs from source')
    expected_files = {
        f'dist/{name}': {
            'media_type': record['media_type'],
            'path': f'dist/{name}',
            'sha256': record['sha256'],
            'size': record['size'],
        }
        for name, record in trust['publication_files'].items()
    }
    manifest_records = manifest.get('files', [])
    require(isinstance(manifest_records, list), 'Release files must be a list')
    manifest_files = {record['path']: record for record in manifest_records}
    require(len(manifest_files) == len(manifest_records), 'Duplicate release file record')
    require(manifest_files == expected_files, 'Release file manifest differs from approved publication')

    archive = manifest.get('archive', {})
    expected_name = f'liarsdice-site-v{manifest["version"]}-{manifest["source_commit"][:12]}.tar.gz'
    require(archive.get('name') == expected_name, 'Release archive name is not source-bound')
    archive_path = release_dir / expected_name
    require(archive_path.is_file() and not archive_path.is_symlink(), 'Release archive is missing or unsafe')
    require(archive_path.stat().st_size == archive.get('size'), 'Release archive size differs from manifest')
    require(file_digest(archive_path) == archive.get('sha256'), 'Release archive digest differs from manifest')

    expected_checksums = (
        f'{archive["sha256"]}  {expected_name}\n'
        f'{sha256(manifest_raw).hexdigest()}  {MANIFEST_NAME}\n'
    )
    checksum_raw = read_regular(release_dir / CHECKSUM_NAME, 4 * 1024)
    require(checksum_raw.decode('ascii') == expected_checksums, 'SHA256SUMS differs from release manifest')
    extracted = safe_archive_members(archive_path, expected_files)

    with tempfile.TemporaryDirectory() as directory:
        artifact_root = Path(directory)
        for name, raw in extracted.items():
            target = artifact_root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
        (artifact_root / 'security').mkdir()
        (artifact_root / 'security' / 'approved-publication.json').write_bytes(trust_raw)
        validate(artifact_root)
    return manifest


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description=__doc__)
    subcommands = command.add_subparsers(dest='command', required=True)
    build = subcommands.add_parser('build')
    build.add_argument('--output-dir', type=Path, required=True)
    verify = subcommands.add_parser('verify')
    verify.add_argument('--release-dir', type=Path, required=True)
    verify.add_argument('--expected-commit')
    verify.add_argument('--expected-version')
    return command


def main() -> int:
    arguments = parser().parse_args()
    try:
        if arguments.command == 'build':
            manifest = build_release(ROOT, arguments.output_dir)
            print(f'PASS: built {manifest["archive"]["name"]} from {manifest["source_commit"]}.')
        else:
            manifest = verify_release(
                ROOT,
                arguments.release_dir,
                expected_commit=arguments.expected_commit,
                expected_version=arguments.expected_version,
            )
            print(f'PASS: verified {manifest["archive"]["name"]} and isolated static tree.')
    except (KeyError, OSError, subprocess.CalledProcessError, tarfile.TarError, ValidationError, ValueError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
