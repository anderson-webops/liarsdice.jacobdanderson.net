"""Fail-closed validation for the complete static publication."""

from __future__ import annotations

from collections import Counter
from hashlib import sha256
from html.parser import HTMLParser
import json
import re
import stat
import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit
from xml.etree import ElementTree


ROOT = Path(__file__).resolve().parents[1]
MAX_FILES = 16
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_HTML_BYTES = 256 * 1024
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_ELEMENTS = 2_000
MAX_DEPTH = 32
EXPECTED_PUBLIC_PATHS = {
    'index.html',
    'styles.css',
    'favicon.svg',
    'evidence/confirmation-summary.json',
    'evidence/provenance.json',
}
VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}
ALLOWED_TAGS = {
    'a', 'article', 'aside', 'body', 'br', 'caption', 'code', 'details', 'div',
    'footer', 'h1', 'h2', 'h3', 'head', 'header', 'html', 'li', 'link', 'main',
    'meta', 'p', 'section', 'span', 'strong', 'summary', 'table', 'tbody', 'td',
    'th', 'thead', 'title', 'tr', 'ul',
}
ALLOWED_ATTRIBUTES = {
    'a': {'class', 'download', 'href'},
    'article': {'class'},
    'aside': {'aria-labelledby', 'class'},
    'details': {'class'},
    'div': {'aria-label', 'class', 'role', 'tabindex'},
    'footer': {'class'},
    'h2': {'id'},
    'header': {'class'},
    'html': {'lang'},
    'link': {'href', 'rel', 'type'},
    'meta': {'charset', 'content', 'http-equiv', 'name'},
    'p': {'class'},
    'section': {'aria-labelledby', 'class', 'id'},
    'span': {'class', 'data-value'},
    'td': {'class', 'data-value'},
    'th': {'class', 'scope'},
    'tr': {'class', 'data-players', 'data-profile', 'data-result', 'data-strategy', 'data-target'},
    'ul': {'class'},
}
PROFILE_LABELS = {
    'calza': 'Calza',
    'classic': 'Classic',
    'no-wild': 'No-wild',
    'perudo': 'Perudo',
    'perudo-calza': 'Perudo-Calza',
    'single-loser-agree': 'Single-loser-agree',
    'spot-on': 'Spot-on',
}
FAMILY_LABELS = {
    'AdaptiveSurvivalStrategy': 'Adapt to table size and dice left',
    'CalzaDisciplinedStrategy': 'Disciplined probability play',
    'MCTSStrategy': 'Search over likely next responses',
    'ProbabilityStrategy': 'Probability-led bidding',
    'PublicBeliefSearchStrategy': 'Search informed by public bids',
    'ResponseEVStrategy': 'Learn opponents’ responses',
}
EXPECTED_CSP = (
    "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'none'; "
    "connect-src 'none'; media-src 'none'; object-src 'none'; frame-src 'none'; "
    "worker-src 'none'; manifest-src 'none'; base-uri 'none'; form-action 'none'; "
    "script-src 'none'"
)
EXPECTED_METAS = [
    {'charset': 'utf-8'},
    {'name': 'viewport', 'content': 'width=device-width, initial-scale=1'},
    {'name': 'description', 'content': 'What 7.18 million simulated Liar’s Dice games found: probability-based strategies, ruleset-specific leaders, and supported counters.'},
    {'name': 'theme-color', 'content': '#0b3027'},
    {'name': 'referrer', 'content': 'no-referrer'},
    {'http-equiv': 'Content-Security-Policy', 'content': EXPECTED_CSP},
]
APPROVED_EXTERNAL_NAVIGATION = {
    'https://github.com/anderson-webops/liarsdice.jacobdanderson.net',
}
SENSITIVE_MARKERS = (
    b'-----BEGIN PRIVATE KEY', b'-----BEGIN OPENSSH PRIVATE KEY', b'/Users/',
    b'github_pat_', b'ghp_', b'AKIA',
)


class ValidationError(RuntimeError):
    """A publication invariant was violated."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def normalized(value: str) -> str:
    return ' '.join(value.split())


def pct(value: float) -> str:
    return f'{100 * value:.1f}%'


def digest_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def read_regular(path: Path, limit: int) -> bytes:
    try:
        info = path.lstat()
    except FileNotFoundError as error:
        raise ValidationError(f'Missing required file: {path}') from error
    require(stat.S_ISREG(info.st_mode), f'Not a regular file: {path}')
    require(not path.is_symlink(), f'Symlink is not allowed: {path}')
    require(info.st_size <= limit, f'File exceeds {limit} bytes: {path}')
    value = path.read_bytes()
    require(len(value) == info.st_size, f'File changed while being read: {path}')
    return value


def load_json(path: Path, limit: int = MAX_JSON_BYTES):
    raw = read_regular(path, limit)
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError(f'Invalid JSON: {path}') from error
    nodes = 0

    def visit(item, depth=0):
        nonlocal nodes
        nodes += 1
        require(nodes <= 250_000, f'JSON node limit exceeded: {path}')
        require(depth <= MAX_DEPTH, f'JSON nesting limit exceeded: {path}')
        if isinstance(item, dict):
            for key, child in item.items():
                require(isinstance(key, str) and len(key) <= 512, f'Unsafe JSON key: {path}')
                visit(child, depth + 1)
        elif isinstance(item, list):
            for child in item:
                visit(child, depth + 1)
        elif isinstance(item, str):
            require(len(item) <= 64_000, f'JSON string limit exceeded: {path}')

    visit(value)
    return raw, value


class Element:
    def __init__(self, tag='', attrs=(), parent=None):
        names = [name for name, _ in attrs]
        require(len(names) == len(set(names)), f'Duplicate attribute on <{tag}>')
        self.tag = tag
        self.attrs = dict(attrs)
        self.children = []
        self.parent = parent

    def descendants(self):
        for child in self.children:
            if isinstance(child, Element):
                yield child
                yield from child.descendants()

    def elements(self):
        return [child for child in self.children if isinstance(child, Element)]

    def text(self):
        pieces = []
        for child in self.children:
            if isinstance(child, Element):
                pieces.append(' ' if child.tag == 'br' else child.text())
            else:
                pieces.append(child)
        return normalized(''.join(pieces))

    def direct_text(self):
        return normalized(''.join(child for child in self.children if isinstance(child, str)))


class Document(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Element()
        self.stack = [self.root]
        self.declarations = []
        self.element_count = 0

    def handle_decl(self, declaration):
        self.declarations.append(declaration.lower())

    def unknown_decl(self, declaration):
        raise ValidationError(f'Unsupported declaration: {declaration}')

    def handle_comment(self, _data):
        raise ValidationError('HTML comments are not allowed in the publication')

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        require(tag in ALLOWED_TAGS, f'Unsupported HTML element: <{tag}>')
        self.element_count += 1
        require(self.element_count <= MAX_ELEMENTS, 'HTML element limit exceeded')
        require(len(self.stack) <= MAX_DEPTH, 'HTML nesting limit exceeded')
        element = Element(tag, attrs, self.stack[-1])
        self.stack[-1].children.append(element)
        if tag not in VOID:
            self.stack.append(element)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag.lower() not in VOID:
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        require(len(self.stack) > 1, f'Unexpected closing tag: </{tag}>')
        require(self.stack[-1].tag == tag.lower(), f'Unbalanced HTML at </{tag}>')
        self.stack.pop()

    def handle_data(self, text):
        self.stack[-1].children.append(text)

    def finish(self):
        self.close()
        require(self.declarations == ['doctype html'], 'Exactly one HTML5 doctype is required')
        require(len(self.stack) == 1, 'Unclosed HTML element')


def class_tokens(element: Element) -> set[str]:
    value = element.attrs.get('class', '')
    tokens = value.split()
    require(all(re.fullmatch(r'[a-z0-9-]+', token) for token in tokens), f'Invalid class on <{element.tag}>')
    require(len(tokens) == len(set(tokens)), f'Duplicate class on <{element.tag}>')
    return set(tokens)


def enumerate_publication(public: Path, approved: dict) -> dict[str, bytes]:
    require(public.is_dir() and not public.is_symlink(), 'dist must be a real directory')
    files = {}
    directories = set()
    for path in public.rglob('*'):
        relative = path.relative_to(public).as_posix()
        info = path.lstat()
        require(not path.is_symlink(), f'Publication symlink is not allowed: {relative}')
        if stat.S_ISDIR(info.st_mode):
            directories.add(relative)
            continue
        require(stat.S_ISREG(info.st_mode), f'Unsupported publication entry: {relative}')
        require(len(Path(relative).parts) <= 4, f'Publication path too deep: {relative}')
        require(not any(part.startswith('.') for part in Path(relative).parts), f'Hidden publication path: {relative}')
        require(len(files) < MAX_FILES, 'Publication file-count limit exceeded')
        files[relative] = read_regular(path, MAX_JSON_BYTES)
    approved_files = approved.get('publication_files')
    require(isinstance(approved_files, dict), 'Trust anchor lacks publication_files')
    require(set(approved_files) == EXPECTED_PUBLIC_PATHS, 'Trust anchor approves an unsupported publication path')
    require(set(files) == set(approved_files), 'Publication inventory differs from approved manifest')
    expected_directories = {
        '/'.join(Path(name).parts[:index])
        for name in approved_files
        for index in range(1, len(Path(name).parts))
    }
    require(directories == expected_directories, 'Publication directory inventory differs from approved manifest')
    require(sum(len(value) for value in files.values()) <= MAX_TOTAL_BYTES, 'Publication byte limit exceeded')
    media_types = {
        '.css': 'text/css', '.html': 'text/html', '.json': 'application/json', '.svg': 'image/svg+xml',
    }
    for name, raw in files.items():
        record = approved_files[name]
        require(set(record) == {'media_type', 'sha256', 'size'}, f'Invalid manifest record: {name}')
        require(record['size'] == len(raw), f'Publication size mismatch: {name}')
        require(record['sha256'] == digest_bytes(raw), f'Publication digest mismatch: {name}')
        require(record['media_type'] == media_types.get(Path(name).suffix), f'Publication media type mismatch: {name}')
        for marker in SENSITIVE_MARKERS:
            require(marker not in raw, f'Sensitive marker found in publication file: {name}')
    return files


def validate_html(raw: bytes, public: Path, approved: dict, data: dict) -> Document:
    require(len(raw) <= MAX_HTML_BYTES, 'index.html is too large')
    try:
        html = raw.decode('utf-8')
    except UnicodeDecodeError as error:
        raise ValidationError('index.html must be UTF-8') from error
    require('\u2014' not in html, 'Use punctuation consistent with site conventions')
    document = Document()
    document.feed(html)
    document.finish()
    elements = list(document.root.descendants())
    require(elements and elements[0].tag == 'html', 'Document root must be html')
    require(elements[0].attrs == {'lang': 'en'}, 'Document language must be English')
    ids = []
    manifest_paths = set(approved['publication_files'])

    for element in elements:
        allowed = ALLOWED_ATTRIBUTES.get(element.tag, set())
        require(set(element.attrs) <= allowed, f'Unsupported attribute on <{element.tag}>')
        for name, value in element.attrs.items():
            require(not name.startswith('on'), f'Event handler is not allowed: {name}')
            require(name not in {'style', 'srcdoc', 'hidden', 'nonce'}, f'Active or hidden attribute is not allowed: {name}')
            if value is not None:
                require(not any(ord(char) < 32 and char not in '\t\n\r' for char in value), f'Control character in {name}')
        class_tokens(element)
        if 'id' in element.attrs:
            require(re.fullmatch(r'[a-z][a-z0-9-]*', element.attrs['id']) is not None, 'Invalid document ID')
            ids.append(element.attrs['id'])
        if element.tag == 'th':
            require(element.attrs.get('scope') in {'col', 'row'}, 'Unscoped table heading')
        if 'tabindex' in element.attrs:
            require(element.attrs['tabindex'] == '0', 'Only neutral keyboard tabindex is allowed')
        if 'role' in element.attrs:
            require(element.attrs['role'] == 'region', 'Unexpected explicit role')
        for reference in element.attrs.get('aria-labelledby', '').split():
            require(re.fullmatch(r'[a-z][a-z0-9-]*', reference) is not None, 'Invalid aria-labelledby')

        href = element.attrs.get('href')
        if href is not None:
            require(element.tag in {'a', 'link'}, 'href is allowed only on anchors and links')
            parsed = urlsplit(href)
            require(not parsed.query, f'URL queries are not approved: {href}')
            if parsed.scheme or parsed.netloc:
                require(element.tag == 'a' and href in APPROVED_EXTERNAL_NAVIGATION, f'Unapproved external navigation: {href}')
            else:
                require('\\' not in href and '\x00' not in href, f'Unsafe local URL: {href}')
                decoded = unquote(parsed.path)
                require(not decoded.startswith('/'), f'Root-relative URL is not approved: {href}')
                if decoded:
                    target = (public / decoded).resolve()
                    require(target.is_relative_to(public.resolve()), f'Asset outside publication root: {href}')
                    relative = target.relative_to(public.resolve()).as_posix()
                    require(relative in manifest_paths and target.is_file(), f'Unapproved local asset: {href}')
                require(not parsed.fragment or not decoded, f'Cross-document fragments are not approved: {href}')

    require(len(ids) == len(set(ids)), 'Duplicate document IDs')
    for element in elements:
        for reference in element.attrs.get('aria-labelledby', '').split():
            require(reference in ids, f'Missing accessible label: {reference}')
        href = element.attrs.get('href', '')
        parsed = urlsplit(href)
        if parsed.fragment and not parsed.path:
            require(parsed.fragment in ids, f'Missing anchor: {parsed.fragment}')

    metas = [element for element in elements if element.tag == 'meta']
    require([meta.attrs for meta in metas] == EXPECTED_METAS, 'Meta declarations differ from the approved passive policy')
    links = [element for element in elements if element.tag == 'link']
    require(len(links) == 2, 'Exactly two passive local link resources are required')
    require(any(link.attrs == {'rel': 'stylesheet', 'href': 'styles.css'} for link in links), 'Local stylesheet link is required')
    require(any(link.attrs == {'rel': 'icon', 'type': 'image/svg+xml', 'href': 'favicon.svg'} for link in links), 'Local SVG icon link is required')
    require(sum(element.tag == 'h1' for element in elements) == 1, 'Exactly one h1 is required')

    for claim in approved.get('required_visible_claims', []):
        matches = []
        for element in elements:
            if element.tag != claim['tag']:
                continue
            if claim.get('id') and element.attrs.get('id') != claim['id']:
                continue
            if claim.get('class') and claim['class'] not in class_tokens(element):
                continue
            if element.text() == claim['text']:
                matches.append(element)
        require(len(matches) == 1, f'Approved visible claim missing or duplicated: {claim["text"]}')

    validate_rows(elements, data)
    return document


def validate_rows(elements: list[Element], data: dict) -> None:
    seen = Counter()
    keys = set()
    result_rows = [element for element in elements if 'data-result' in element.attrs]
    tbody_rows = [element for element in elements if element.tag == 'tr' and element.parent and element.parent.tag == 'tbody']
    require(result_rows == tbody_rows, 'Every body row must be one evidence-backed result row')

    for row in result_rows:
        require(row.tag == 'tr' and row.parent and row.parent.tag == 'tbody', 'Result marker must be on a tbody row')
        kind = row.attrs['data-result']
        profile = row.attrs.get('data-profile')
        players = row.attrs.get('data-players')
        require(profile in PROFILE_LABELS and profile in data['profiles'], f'Unknown profile: {profile}')
        expected_attributes = {
            'duel': {'data-result', 'data-profile', 'data-strategy'},
            'parameters': {'data-result', 'data-profile', 'data-strategy'},
            'mixed': {'data-result', 'data-profile', 'data-players', 'data-strategy'},
            'counter': {'data-result', 'data-profile', 'data-players', 'data-strategy', 'data-target'},
        }
        require(kind in expected_attributes, f'Unknown result kind: {kind}')
        require(set(row.attrs) - {'class'} == expected_attributes[kind], f'Unexpected result-row attributes: {kind}')
        key = (kind, profile, players)
        require(key not in keys, f'Duplicate result: {key}')
        keys.add(key)
        seen[kind] += 1

        result = data['profiles'][profile]
        if kind in {'duel', 'parameters'}:
            expected = result['duels'][0]
        elif kind == 'mixed':
            require(players in {'3', '4', '5', '6'}, f'Invalid mixed player count: {players}')
            expected = result['tables'][players]['rankings'][0]
        else:
            require(players in {'2', '3', '4', '5', '6'}, f'Invalid counter player count: {players}')
            expected = result['tables'][players]['targeted_rankings'][0]
            require(expected['advantage_supported'], f'Unsupported counter displayed: {key}')
            require(row.attrs['data-target'] == expected['opponent_style'], f'Wrong counter target: {key}')
        require(row.attrs['data-strategy'] == expected['strategy'], f'Wrong strategy: {key}')

        cells = row.elements()
        expected_cell_count = 5 if kind == 'counter' else 4
        require(len(cells) == expected_cell_count, f'Wrong cell count: {key}')
        require(cells[0].tag == 'th' and cells[0].attrs.get('scope') == 'row', f'Invalid row heading: {key}')
        require(all(cell.tag == 'td' for cell in cells[1:]), f'Unexpected cell element: {key}')
        expected_label = PROFILE_LABELS[profile] if kind in {'duel', 'parameters'} else players
        require(cells[0].text() == expected_label, f'Visible row label differs from evidence: {key}')

        values = {}
        for descendant in row.descendants():
            if 'data-value' not in descendant.attrs:
                continue
            name = descendant.attrs['data-value']
            require(name not in values, f'Duplicate visible value {name}: {key}')
            values[name] = descendant

        if kind == 'parameters':
            require(set(values) == {'opening', 'raise', 'call'}, f'Wrong parameter fields: {key}')
            params = data['policy_details'][expected['strategy']]['configured_profile']
            require(params['bluff_chance'] == 0, f'Displayed leader is not zero-bluff: {key}')
            for field, source in (('opening', 'opening_target_probability'), ('raise', 'raise_target_probability'), ('call', 'call_threshold')):
                require(values[field].tag == 'td' and values[field].direct_text() == pct(params[source]), f'Wrong visible {field}: {key}')
        else:
            expected_fields = {'mean', 'interval'} | ({'games', 'reference'} if kind == 'counter' else set())
            require(set(values) == expected_fields, f'Wrong visible value fields: {key}')
            require(values['mean'].tag == 'td' and values['mean'].direct_text() == pct(expected['mean']), f'Wrong visible rate: {key}')
            lower, upper = expected['simultaneous']
            require(values['interval'].tag == 'td' and values['interval'].direct_text() == f'{100 * lower:.1f}–{100 * upper:.1f}%', f'Wrong visible interval: {key}')
            if kind == 'counter':
                require(values['games'].tag == 'span' and values['games'].direct_text() == f'{expected["blocks"] * int(players):,} games', f'Wrong visible game count: {key}')
                require(values['reference'].tag == 'td' and values['reference'].direct_text() == pct(expected['identical_style_baseline']), f'Wrong visible reference: {key}')

        if kind != 'parameters':
            strategy_cell = cells[1]
            policy = data['policy_details'][expected['strategy']]
            require(strategy_cell.direct_text() == FAMILY_LABELS[policy['implementation_family']], f'Wrong visible strategy label: {key}')
            strategy_markers = [element for element in strategy_cell.descendants() if 'strategy-id' in class_tokens(element)]
            expected_count = 2 if kind == 'counter' else 1
            require(len(strategy_markers) == expected_count, f'Wrong strategy marker count: {key}')
            require(strategy_markers[0].text() == expected['strategy'], f'Wrong visible strategy ID: {key}')
            if kind == 'counter':
                require('opponent' in class_tokens(strategy_markers[1]), f'Counter opponent marker missing: {key}')
                require(strategy_markers[1].text() == f'Against: {expected["opponent_style"]}', f'Wrong visible opponent: {key}')

    require(seen == {'duel': 7, 'parameters': 7, 'mixed': 28, 'counter': 7}, f'Wrong result inventory: {seen}')
    expected_counter_keys = {
        ('counter', profile, players)
        for profile, result in data['profiles'].items()
        for players, table in result['tables'].items()
        if table['targeted_rankings'][0]['advantage_supported']
    }
    require({key for key in keys if key[0] == 'counter'} == expected_counter_keys, 'Supported counter inventory differs from evidence')
    require(len([element for element in elements if element.tag == 'details']) == 8, 'Unexpected details-section count')


def validate_css(raw: bytes) -> None:
    try:
        css = raw.decode('utf-8')
    except UnicodeDecodeError as error:
        raise ValidationError('styles.css must be UTF-8') from error
    lowered = css.lower()
    forbidden = ('@import', 'url(', 'expression(', 'javascript:', '-moz-binding', '@font-face', '[data-', 'visibility:hidden', 'opacity:0')
    for token in forbidden:
        require(token not in lowered, f'Forbidden CSS construct: {token}')
    require('\\' not in css, 'CSS escapes are not allowed')
    require(set(re.findall(r'@[a-z-]+', lowered)) <= {'@media'}, 'Unsupported CSS at-rule')
    require('/*' not in css and '*/' not in css, 'CSS comments are not allowed')
    require(not re.search(r'(^|[;{])\s*behavior\s*:', lowered), 'Legacy CSS behavior property is not allowed')
    require(not re.search(r'(^|[;{])\s*content\s*:', lowered), 'Generated CSS content is not allowed')
    require(not re.search(r'position\s*:\s*(fixed|sticky)', lowered), 'Fixed or sticky CSS positioning is not allowed')
    require(len(re.findall(r'display\s*:\s*none', lowered)) == 1 and '.skip{display:none}' in lowered, 'Only the print skip-link may use display:none')
    require(len(re.findall(r'position\s*:\s*absolute', lowered)) == 1 and '.skip{position:absolute' in lowered, 'Only the keyboard skip-link may use absolute positioning')
    require(len(re.findall(r'z-index\s*:', lowered)) == 1, 'Unexpected CSS stacking context')


def validate_svg(raw: bytes) -> None:
    lowered = raw.lower()
    require(b'<!doctype' not in lowered and b'<!entity' not in lowered, 'SVG declarations and entities are not allowed')
    try:
        root = ElementTree.fromstring(raw)
    except ElementTree.ParseError as error:
        raise ValidationError('Invalid favicon SVG') from error
    allowed_attributes = {
        'svg': {'viewBox'},
        'rect': {'width', 'height', 'rx', 'fill'},
        'text': {'x', 'y', 'text-anchor', 'font-family', 'font-size', 'font-weight', 'fill'},
    }
    elements = list(root.iter())
    require(len(elements) == 3, 'Unexpected SVG element count')
    for element in elements:
        require(element.tag.startswith('{http://www.w3.org/2000/svg}'), 'Unexpected SVG namespace')
        tag = element.tag.rsplit('}', 1)[-1]
        require(tag in allowed_attributes, f'Unsupported SVG element: {tag}')
        require(set(element.attrib) <= allowed_attributes[tag], f'Unsupported SVG attribute on {tag}')
        require(not any(name.lower().startswith('on') or 'href' in name.lower() for name in element.attrib), 'Active SVG attribute is not allowed')
    require(root.tag.rsplit('}', 1)[-1] == 'svg', 'SVG root element is required')
    text_nodes = [element for element in elements if element.tag.rsplit('}', 1)[-1] == 'text']
    require(len(text_nodes) == 1 and normalized(text_nodes[0].text or '') == 'LD', 'Unexpected SVG text')


def validate(root: Path = ROOT) -> None:
    require(sys.flags.optimize == 0 and __debug__, 'Optimized Python is forbidden for publication validation')
    root = root.resolve()
    public = root / 'dist'
    trust_path = root / 'security' / 'approved-publication.json'
    _, approved = load_json(trust_path, 128 * 1024)
    require(approved.get('schema_version') == 1, 'Unsupported trust-anchor schema')
    require(approved.get('approval_owner') == 'Jacoba1100254352', 'Unexpected trust-anchor owner')
    files = enumerate_publication(public, approved)

    summary_raw, data = load_json(public / 'evidence' / 'confirmation-summary.json')
    _, provenance = load_json(public / 'evidence' / 'provenance.json', 128 * 1024)
    require(digest_bytes(summary_raw) == approved['confirmation_summary_sha256'], 'Research snapshot differs from independently approved digest')
    require(provenance['confirmation_summary_sha256'] == approved['confirmation_summary_sha256'], 'Bundled provenance digest differs from approved digest')
    require(provenance['source_document_sha256'] == approved['source_document_sha256'], 'Source-document hashes differ from approved anchor')
    require(provenance['execution_source_sha256'] == approved['execution_source_sha256'], 'Execution-source hashes differ from approved anchor')
    require(data['execution_provenance']['sources'] == approved['execution_source_sha256'], 'Embedded execution-source hashes differ from approved anchor')
    require(data['games'] == 3_377_152, 'Unexpected confirmation-game count')
    require(sum(item['games'] for item in data['phase_totals'].values()) == 7_180_416, 'Unexpected research-game count')
    require(data['coerced_actions'] == 0 and data['family_size'] == 5_180, 'Unexpected research integrity constants')

    validate_html(files['index.html'], public, approved, data)
    validate_css(files['styles.css'])
    validate_svg(files['favicon.svg'])


def main() -> int:
    try:
        validate()
    except (KeyError, TypeError, ValueError, ValidationError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        return 1
    print('PASS: complete publication inventory, passive-content policy, and independent evidence anchor.')
    print('PASS: 42 visible result rows and 7 visible parameter rows match the pinned evidence.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
