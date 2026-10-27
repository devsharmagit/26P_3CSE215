"""
Load and validate a rule file (see rules.yaml for the format).

    rs = load_rules('rules.yaml')
    rs.rules            -> list[Rule]
    rs.settings         -> Settings
    print(describe(rs)) -> human-readable listing (python main.py rules)

Rules are data: changing a threshold, its policy (fixed/adaptive) or switching a rule off is an edit to
the YAML file, not to the code. The measures themselves are implemented in engine.py.
"""
import copy
import ipaddress
from dataclasses import dataclass, field

import yaml

SOURCE_MEASURES = {'syn_rate', 'icmp_rate', 'distinct_ports', 'port_entropy', 'half_open_ratio', 'rejected_probes'}
VICTIM_MEASURES = {'victim_pps', 'victim_conn_rate'}
MEASURES = SOURCE_MEASURES | VICTIM_MEASURES
# measures that a rule-level window_seconds applies to (ratio / entropy measures have no window length to scale)
WINDOWED_MEASURES = {'syn_rate', 'icmp_rate', 'distinct_ports', 'victim_pps', 'victim_conn_rate', 'rejected_probes'}
KINDS = {'count', 'behaviour'}
POLICIES = {'fixed', 'adaptive'}
OPS = {'>', '>='}


class RuleFileError(ValueError):
    pass


@dataclass
class Settings:
    window_seconds: float = 1.0
    home_net: list = field(default_factory=lambda: ['192.168.0.0/16'])
    connection_timeout_seconds: float = 30.0
    multiplier: float = 3.0
    alpha: float = 0.2
    freeze_seconds: float = 60.0


@dataclass
class Rule:
    id: str
    name: str
    measure: str
    scope: str
    kind: str
    policy: str
    value: float
    op: str = '>'
    multiplier: float = 3.0
    alpha: float = 0.2
    freeze_seconds: float = 60.0
    min_support: int = 0
    params: dict = field(default_factory=dict)
    weight: float = 1.0
    description: str = ''
    enabled: bool = True
    window_seconds: float = None   # sliding window of the measure; None = the engine window (rejected_probes: params)

    def threshold_text(self):
        if self.policy == 'fixed':
            return f'{self.op} {self.value:g} (fixed)'
        return f'{self.op} max({self.value:g}, {self.multiplier:g} x baseline) (adaptive, alpha={self.alpha:g}, freeze={self.freeze_seconds:g}s)'


@dataclass
class RuleSet:
    rules: list
    settings: Settings
    source: str = '<memory>'

    def variant(self, policy=None, kinds=None, ids=None, exclude=()):
        """Copy with every rule forced to `policy`, and only the rules whose kind is in `kinds` /
        id is in `ids` (None = keep all), minus `exclude`. Used by the experiments."""
        rs = copy.deepcopy(self)
        keep = []
        for r in rs.rules:
            if kinds is not None and r.kind not in kinds:
                continue
            if ids is not None and r.id not in ids:
                continue
            if r.id in exclude:
                continue
            if policy is not None:
                r.policy = policy
            keep.append(r)
        rs.rules = keep
        return rs


def _home_prefixes(nets):
    out = []
    for n in nets:
        try:
            out.append(ipaddress.ip_network(n, strict=False))
        except ValueError as e:
            raise RuleFileError(f'settings.home_net: {e}') from None
    return out


def parse_rules(doc, source='<memory>'):
    if not isinstance(doc, dict) or 'rules' not in doc:
        raise RuleFileError(f'{source}: expected a mapping with a "rules" list')
    st = doc.get('settings') or {}
    ad = st.get('adaptive_defaults') or {}
    settings = Settings(
        window_seconds=float(st.get('window_seconds', 1.0)),
        home_net=list(st.get('home_net', ['192.168.0.0/16'])),
        connection_timeout_seconds=float(st.get('connection_timeout_seconds', 30.0)),
        multiplier=float(ad.get('multiplier', 3.0)),
        alpha=float(ad.get('alpha', 0.2)),
        freeze_seconds=float(ad.get('freeze_seconds', 60.0)),
    )
    if settings.window_seconds <= 0:
        raise RuleFileError('settings.window_seconds must be > 0')
    _home_prefixes(settings.home_net)
    rules, seen = [], set()
    for i, r in enumerate(doc['rules'] or []):
        where = f'{source}: rules[{i}]'
        if not isinstance(r, dict):
            raise RuleFileError(f'{where}: expected a mapping')
        missing = [k for k in ('id', 'measure', 'threshold') if k not in r]
        if missing:
            raise RuleFileError(f'{where}: missing {", ".join(missing)}')
        rid = str(r['id'])
        if rid in seen:
            raise RuleFileError(f'{where}: duplicate id "{rid}"')
        seen.add(rid)
        measure = r['measure']
        if measure not in MEASURES:
            raise RuleFileError(f'{where} ({rid}): unknown measure "{measure}" (known: {", ".join(sorted(MEASURES))})')
        scope = r.get('scope', 'victim' if measure in VICTIM_MEASURES else 'source')
        if (scope == 'victim') != (measure in VICTIM_MEASURES):
            raise RuleFileError(f'{where} ({rid}): measure "{measure}" cannot have scope "{scope}"')
        kind = r.get('kind', 'count')
        if kind not in KINDS:
            raise RuleFileError(f'{where} ({rid}): kind must be one of {sorted(KINDS)}')
        th = r['threshold']
        if not isinstance(th, dict) or 'value' not in th:
            raise RuleFileError(f'{where} ({rid}): threshold needs at least a value')
        policy = th.get('policy', 'fixed')
        if policy not in POLICIES:
            raise RuleFileError(f'{where} ({rid}): threshold.policy must be one of {sorted(POLICIES)}')
        op = th.get('op', '>')
        if op not in OPS:
            raise RuleFileError(f'{where} ({rid}): threshold.op must be ">" or ">="')
        window = r.get('window_seconds')
        if window is not None:
            window = float(window)
            if measure not in WINDOWED_MEASURES:
                raise RuleFileError(f'{where} ({rid}): measure "{measure}" has no window_seconds')
            if window <= 0 or (measure != 'rejected_probes' and window < settings.window_seconds):
                raise RuleFileError(f'{where} ({rid}): window_seconds must be > 0 and, for a count measure, '
                                    f'at least settings.window_seconds')
        rules.append(Rule(
            id=rid, name=str(r.get('name', rid)), measure=measure, scope=scope, kind=kind, policy=policy,
            value=float(th['value']), op=op,
            multiplier=float(th.get('multiplier', settings.multiplier)),
            alpha=float(th.get('alpha', settings.alpha)),
            freeze_seconds=float(th.get('freeze_seconds', settings.freeze_seconds)),
            min_support=int(r.get('min_support', 0)), params=dict(r.get('params') or {}),
            weight=float(r.get('weight', 1)), description=str(r.get('description', '')),
            enabled=bool(r.get('enabled', True)), window_seconds=window))
    return RuleSet([r for r in rules if r.enabled], settings, source)


def load_rules(path):
    with open(path) as f:
        try:
            doc = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise RuleFileError(f'{path}: {e}') from None
    return parse_rules(doc, path)


def describe(rs):
    lines = [f'Rule file: {rs.source}',
             f'  window {rs.settings.window_seconds:g}s, home_net {", ".join(rs.settings.home_net)}', '']
    for r in rs.rules:
        extra = []
        if r.window_seconds is not None:
            extra.append(f'window {r.window_seconds:g}s (sliding)')
        if r.min_support:
            extra.append(f'min_support {r.min_support}')
        extra += [f'{k} {v}' for k, v in r.params.items()]
        lines.append(f'  [{r.id}] {r.name}  ({r.kind}, per {r.scope}, weight {r.weight:g})')
        lines.append(f'      alert when {r.measure} {r.threshold_text()}' + (f'; {", ".join(extra)}' if extra else ''))
        if r.description:
            lines.append(f'      {r.description}')
    return '\n'.join(lines)
