"""Validate the static recap against its independent, pinned research snapshot."""
from collections import Counter
from hashlib import sha256
from html.parser import HTMLParser
import json
from pathlib import Path
from urllib.parse import unquote, urlsplit

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / 'dist'
VOID = {'area', 'base', 'br', 'col', 'embed', 'hr', 'img', 'input', 'link', 'meta', 'param', 'source', 'track', 'wbr'}


class Element:
    def __init__(self, tag='', attrs=()):
        self.tag = tag
        self.attrs = dict(attrs)
        self.children = []

    def text(self):
        return ''.join(c.text() if isinstance(c, Element) else c for c in self.children).strip()

    def descendants(self):
        for child in self.children:
            if isinstance(child, Element):
                yield child
                yield from child.descendants()


class Document(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = Element()
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        el = Element(tag, attrs)
        self.stack[-1].children.append(el)
        if tag not in VOID:
            self.stack.append(el)

    def handle_endtag(self, tag):
        assert len(self.stack) > 1 and self.stack[-1].tag == tag, f'Unbalanced HTML at </{tag}>'
        self.stack.pop()

    def handle_data(self, text):
        self.stack[-1].children.append(text)


def pct(value):
    return f'{100 * value:.1f}%'


def main():
    raw = (PUBLIC / 'evidence/confirmation-summary.json').read_bytes()
    data = json.loads(raw)
    provenance = json.loads((PUBLIC / 'evidence/provenance.json').read_text())
    assert sha256(raw).hexdigest() == provenance['confirmation_summary_sha256'], 'Research snapshot changed'
    assert data['games'] == 3_377_152
    assert sum(x['games'] for x in data['phase_totals'].values()) == 7_180_416
    assert data['coerced_actions'] == 0 and data['family_size'] == 5180
    assert data['execution_provenance']['sources'] == provenance['execution_source_sha256']

    html = (PUBLIC / 'index.html').read_text()
    assert '\u2014' not in html, 'Use punctuation consistent with site conventions'
    assert '/Users/' not in html and 'PARAMETER_ROWS' not in html
    doc = Document()
    doc.feed(html)
    doc.close()
    assert len(doc.stack) == 1, 'Unclosed HTML elements'
    elements = list(doc.root.descendants())
    ids = [x.attrs['id'] for x in elements if 'id' in x.attrs]
    assert len(ids) == len(set(ids)), 'Duplicate document IDs'
    assert sum(x.tag == 'h1' for x in elements) == 1
    assert not any(x.tag == 'script' for x in elements), 'Static site must not require JavaScript'
    assert next(x for x in elements if x.tag == 'html').attrs.get('lang') == 'en'
    for el in elements:
        if el.tag == 'th':
            assert el.attrs.get('scope') in {'col', 'row'}, 'Unscoped table heading'
        for key in ['href', 'src']:
            if key not in el.attrs:
                continue
            url = urlsplit(el.attrs[key])
            if url.scheme or url.netloc:
                continue
            if url.path:
                target = (PUBLIC / unquote(url.path)).resolve()
                assert target.is_relative_to(PUBLIC), 'Asset outside public directory'
                assert target.is_file(), f'Missing local asset: {url.path}'
            if url.fragment and not url.path:
                assert url.fragment in ids, f'Missing anchor: {url.fragment}'
        for ref in el.attrs.get('aria-labelledby', '').split():
            assert ref in ids, f'Missing accessible label: {ref}'

    seen = Counter()
    keys = set()
    for row in (x for x in elements if 'data-result' in x.attrs):
        kind = row.attrs['data-result']
        profile = row.attrs['data-profile']
        players = row.attrs.get('data-players')
        key = (kind, profile, players)
        assert key not in keys, f'Duplicate result {key}'
        keys.add(key)
        seen[kind] += 1
        result = data['profiles'][profile]
        if kind in {'duel', 'parameters'}:
            expected = result['duels'][0]
        elif kind == 'mixed':
            expected = result['tables'][players]['rankings'][0]
        elif kind == 'counter':
            expected = result['tables'][players]['targeted_rankings'][0]
            assert expected['advantage_supported']
            assert row.attrs['data-target'] == expected['opponent_style']
        else:
            raise AssertionError(f'Unknown result kind {kind}')
        assert row.attrs['data-strategy'] == expected['strategy'], f'Wrong strategy in {key}'
        cells = {x.attrs['data-value']: x.text() for x in row.descendants() if 'data-value' in x.attrs}
        if kind == 'parameters':
            params = data['policy_details'][expected['strategy']]['configured_profile']
            assert params['bluff_chance'] == 0
            for attr, source in [('opening', 'opening_target_probability'), ('raise', 'raise_target_probability'), ('call', 'call_threshold')]:
                assert cells[attr] == pct(params[source]), f'Wrong {attr} in {key}'
        else:
            assert cells['mean'].split('%')[0] + '%' == pct(expected['mean']), f'Wrong rate in {key}'
            lo, hi = expected['simultaneous']
            assert cells['interval'] == f'{100 * lo:.1f}–{100 * hi:.1f}%', f'Wrong interval in {key}'
        if kind == 'counter':
            assert cells['games'] == f'{expected["blocks"] * int(players):,} games'
            assert cells['reference'] == pct(expected['identical_style_baseline'])
    assert seen == {'duel': 7, 'parameters': 7, 'mixed': 28, 'counter': 7}, seen
    expected_counter_keys = {('counter', p, n) for p, result in data['profiles'].items() for n, table in result['tables'].items() if table['targeted_rankings'][0]['advantage_supported']}
    assert {key for key in keys if key[0] == 'counter'} == expected_counter_keys
    assert len([x for x in elements if x.tag == 'details']) == 8
    print('PASS: 42 result rows and 7 parameter rows match the pinned evidence.')
    print('PASS: HTML structure, accessibility references, local assets, and provenance checks.')


if __name__ == '__main__':
    main()
