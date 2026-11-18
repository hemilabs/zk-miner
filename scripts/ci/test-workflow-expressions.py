#!/usr/bin/env python3
"""Evaluates build-macos.yml's `${{ }}` expressions the way GitHub Actions does, per event (B9-CI).

    test-workflow-expressions.py [--repo DIR]

A workflow's expressions only run on GitHub, and a wrong one fails silently: a job shows as
skipped, an env var gets another value. This file holds a small evaluator of GitHub's expression
language (the subset the workflows use: literals, contexts, `.`/`[]`, `!`, comparisons, `&&`, `||`,
format/contains/startsWith/endsWith/join/toJSON/fromJSON and the status functions), written from
https://docs.github.com/en/actions/reference/workflows-and-actions/expressions:
  - `==`/`!=` compare loosely: values of different types are both coerced to numbers (null -> 0,
    true -> 1, false -> 0, a string -> its JSON number, '' -> 0, anything else -> NaN; NaN equals
    nothing); strings compare ignoring case;
  - `&&`/`||` return one of their operands; false, 0, -0, '', null and NaN are falsy;
  - format() writes null as '', booleans as 'true'/'false'.
Then the table test: build-macos.yml's job conditions and step env per event (push, pull_request
from the repository and from a fork, workflow_dispatch with each input, workflow_call with nothing
and with release.yml's own `with:`), where the `inputs` context is empty on push/pull_request and
holds the declared defaults overlaid with the given values otherwise. Every expression of the file
must evaluate in every event. Also the evaluator's own cases from the docs, and the B9-CI round-1
finding (`inputs.metal_probe != false` skips the probe on push).

The workflows are read with PyYAML when importable, else with Ruby's YAML (both read `on:` as true).
The simulation (B9-CI note) imports this file to evaluate the steps' env and the jobs' `if:`.
Exit 0 when every case passes.
"""
import json
import math
import os
import re
import subprocess
import sys

NAN = float('nan')


class ExprError(Exception):
    pass


# --------------------------------------------------------------------------- lexer / parser

TOKEN = re.compile(r"""\s*(?:
    (?P<num>-?(?:0x[0-9a-fA-F]+|\d+(?:\.\d+)?(?:[eE][+-]?\d+)?))|
    (?P<str>'(?:[^']|'')*')|
    (?P<op>==|!=|<=|>=|&&|\|\||[<>!()\[\].,*])|
    (?P<id>[A-Za-z_][A-Za-z0-9_-]*)
)""", re.X)


def lex(s):
    out, i = [], 0
    while i < len(s):
        if s[i:].strip() == '':
            break
        m = TOKEN.match(s, i)
        if not m:
            raise ExprError(f'cannot read {s[i:]!r} in {s!r}')
        i = m.end()
        if m.group('num') is not None:
            t = m.group('num')
            out.append(('lit', float(int(t, 16)) if t.lower().startswith(('0x', '-0x')) else float(t)))
        elif m.group('str') is not None:
            out.append(('lit', m.group('str')[1:-1].replace("''", "'")))
        elif m.group('op') is not None:
            out.append(('op', m.group('op')))
        else:
            w = m.group('id')
            if w == 'true':
                out.append(('lit', True))
            elif w == 'false':
                out.append(('lit', False))
            elif w == 'null':
                out.append(('lit', None))
            elif w == 'NaN':
                out.append(('lit', NAN))
            elif w == 'Infinity':
                out.append(('lit', math.inf))
            else:
                out.append(('id', w))
    return out


class Parser:
    # precedence, low to high: || , && , == != , < <= > >= , ! , postfix . []
    def __init__(self, toks, src):
        self.t, self.i, self.src = toks, 0, src

    def peek(self):
        return self.t[self.i] if self.i < len(self.t) else (None, None)

    def take(self, kind=None, val=None):
        k, v = self.peek()
        if k is None or (kind and k != kind) or (val is not None and v != val):
            raise ExprError(f'expected {val or kind} at token {self.i} of {self.src!r}')
        self.i += 1
        return v

    def parse(self):
        e = self.or_()
        if self.i != len(self.t):
            raise ExprError(f'trailing tokens in {self.src!r}')
        return e

    def bin(self, sub, ops):
        e = sub()
        while self.peek()[0] == 'op' and self.peek()[1] in ops:
            op = self.take()
            e = ('bin', op, e, sub())
        return e

    def or_(self):
        return self.bin(self.and_, ('||',))

    def and_(self):
        return self.bin(self.eq, ('&&',))

    def eq(self):
        return self.bin(self.cmp, ('==', '!='))

    def cmp(self):
        return self.bin(self.unary, ('<', '<=', '>', '>='))

    def unary(self):
        if self.peek() == ('op', '!'):
            self.take()
            return ('not', self.unary())
        return self.postfix()

    def postfix(self):
        e = self.primary()
        while True:
            k, v = self.peek()
            if (k, v) == ('op', '.'):
                self.take()
                k2, v2 = self.peek()
                if (k2, v2) == ('op', '*'):
                    self.take()
                    e = ('star', e)
                else:
                    e = ('get', e, ('lit', self.take('id')))
            elif (k, v) == ('op', '['):
                self.take()
                if self.peek() == ('op', '*'):
                    self.take()
                    e = ('star', e)
                else:
                    e = ('get', e, self.or_())
                self.take('op', ']')
            else:
                return e

    def primary(self):
        k, v = self.peek()
        if k == 'lit':
            self.take()
            return ('lit', v)
        if (k, v) == ('op', '('):
            self.take()
            e = self.or_()
            self.take('op', ')')
            return e
        if k == 'id':
            self.take()
            if self.peek() == ('op', '('):
                self.take()
                args = []
                if self.peek() != ('op', ')'):
                    args.append(self.or_())
                    while self.peek() == ('op', ','):
                        self.take()
                        args.append(self.or_())
                self.take('op', ')')
                return ('call', v.lower(), args)
            return ('ctx', v)
        raise ExprError(f'unexpected {v!r} in {self.src!r}')


# --------------------------------------------------------------------------- semantics

def is_num(v):
    return isinstance(v, float) or (isinstance(v, int) and not isinstance(v, bool))


def to_num(v):
    if v is None:
        return 0.0
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if is_num(v):
        return float(v)
    if isinstance(v, str):
        s = v.strip()
        if s == '':
            return 0.0
        try:
            if re.fullmatch(r'-?0x[0-9a-fA-F]+', s):
                return float(int(s, 16))
            if re.fullmatch(r'-?(0|[1-9]\d*)(\.\d+)?([eE][+-]?\d+)?', s):
                return float(s)
        except ValueError:
            pass
        return NAN
    return NAN


def kind(v):
    if v is None:
        return 'null'
    if isinstance(v, bool):
        return 'bool'
    if is_num(v):
        return 'num'
    if isinstance(v, str):
        return 'str'
    return 'obj'


def truthy(v):
    if v is None or v is False or v == '':
        return False
    if is_num(v):
        return not (v == 0 or math.isnan(v))
    return True


def loose_eq(a, b):
    ka, kb = kind(a), kind(b)
    if ka == kb:
        if ka == 'str':
            return a.casefold() == b.casefold()
        if ka == 'num':
            return float(a) == float(b)
        if ka == 'obj':
            return a is b
        return a == b
    x, y = to_num(a), to_num(b)
    return not (math.isnan(x) or math.isnan(y)) and x == y


def compare(op, a, b):
    if kind(a) == 'str' and kind(b) == 'str':
        x, y = a.casefold(), b.casefold()
    else:
        x, y = to_num(a), to_num(b)
        if math.isnan(x) or math.isnan(y):
            return False
    return {'<': x < y, '<=': x <= y, '>': x > y, '>=': x >= y}[op]


def to_str(v):
    if v is None:
        return ''
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if is_num(v):
        f = float(v)
        if math.isnan(f):
            return 'NaN'
        return str(int(f)) if f.is_integer() else repr(f)
    if isinstance(v, str):
        return v
    return to_json(v)


def to_json(v):
    def norm(x):
        if is_num(x) and float(x).is_integer():
            return int(x)
        if isinstance(x, dict):
            return {k: norm(y) for k, y in x.items()}
        if isinstance(x, list):
            return [norm(y) for y in x]
        return x
    return json.dumps(norm(v), indent=2)


def get(obj, key):
    if isinstance(obj, dict):
        k = to_str(key)
        for kk, vv in obj.items():
            if str(kk).casefold() == k.casefold():
                return vv
        return None
    if isinstance(obj, list) and is_num(key):
        i = int(key)
        return obj[i] if 0 <= i < len(obj) else None
    return None


def fmt(template, args):
    out, i = [], 0
    while i < len(template):
        c = template[i]
        if c == '{' and template[i:i + 2] == '{{':
            out.append('{'); i += 2
        elif c == '}' and template[i:i + 2] == '}}':
            out.append('}'); i += 2
        elif c == '{':
            j = template.index('}', i)
            out.append(to_str(args[int(template[i + 1:j])])); i = j + 1
        else:
            out.append(c); i += 1
    return ''.join(out)


def call(name, args, status):
    if name == 'format':
        return fmt(to_str(args[0]), args[1:])
    if name == 'contains':
        hay, needle = args
        if isinstance(hay, list):
            return any(loose_eq(x, needle) for x in hay)
        return to_str(needle).casefold() in to_str(hay).casefold()
    if name == 'startswith':
        return to_str(args[0]).casefold().startswith(to_str(args[1]).casefold())
    if name == 'endswith':
        return to_str(args[0]).casefold().endswith(to_str(args[1]).casefold())
    if name == 'join':
        sep = to_str(args[1]) if len(args) > 1 else ','
        return sep.join(to_str(x) for x in args[0]) if isinstance(args[0], list) else to_str(args[0])
    if name == 'tojson':
        return to_json(args[0])
    if name == 'fromjson':
        v = json.loads(to_str(args[0]))
        return float(v) if is_num(v) else v
    if name == 'success':
        return status == 'success'
    if name == 'failure':
        return status == 'failure'
    if name == 'cancelled':
        return status == 'cancelled'
    if name == 'always':
        return True
    if name == 'hashfiles':
        return '0' * 64
    raise ExprError(f'unknown function {name}()')


def ev(node, ctx, status='success'):
    t = node[0]
    if t == 'lit':
        return node[1]
    if t == 'ctx':
        name = node[1]
        for k, v in ctx.items():
            if k.casefold() == name.casefold():
                return v
        raise ExprError(f'unknown context {name!r}')
    if t == 'get':
        return get(ev(node[1], ctx, status), ev(node[2], ctx, status))
    if t == 'star':
        o = ev(node[1], ctx, status)
        return list(o.values()) if isinstance(o, dict) else (o if isinstance(o, list) else [])
    if t == 'not':
        return not truthy(ev(node[1], ctx, status))
    if t == 'call':
        return call(node[1], [ev(a, ctx, status) for a in node[2]], status)
    op, a = node[1], ev(node[2], ctx, status)
    if op == '&&':
        return ev(node[3], ctx, status) if truthy(a) else a
    if op == '||':
        return a if truthy(a) else ev(node[3], ctx, status)
    b = ev(node[3], ctx, status)
    if op == '==':
        return loose_eq(a, b)
    if op == '!=':
        return not loose_eq(a, b)
    return compare(op, a, b)


def evaluate(expr, ctx, status='success'):
    """One expression (without the ${{ }})."""
    return ev(Parser(lex(expr), expr).parse(), ctx, status)


EMBED = re.compile(r'\$\{\{(.*?)\}\}', re.S)


def render(value, ctx):
    """A YAML scalar: a single `${{ x }}` gives x's value; text with expressions gives a string."""
    if not isinstance(value, str) or '${{' not in value:
        return value
    m = EMBED.fullmatch(value.strip())
    if m:
        return evaluate(m.group(1), ctx)
    return EMBED.sub(lambda mm: to_str(evaluate(mm.group(1), ctx)), value)


def condition(value, ctx):
    """A job's or step's `if:` (with or without ${{ }}); a missing one means success()."""
    if value is None:
        return True
    if isinstance(value, bool):
        return value
    s = str(value).strip()
    m = EMBED.fullmatch(s)
    expr = m.group(1) if m else s
    if not re.search(r'\b(success|failure|cancelled|always)\s*\(', expr):
        expr = f'success() && ({expr})'
    return truthy(evaluate(expr, ctx))


def env_value(v):
    """What a rendered env value is in the process environment (None: unset is not possible)."""
    return to_str(v)


# --------------------------------------------------------------------------- workflows and events

def load_yaml(path):
    try:
        import yaml  # noqa: PLC0415
        with open(path) as f:
            return yaml.safe_load(f)
    except ImportError:
        out = subprocess.run(['ruby', '-ryaml', '-rjson', '-e',
                              'puts JSON.generate(YAML.load_file(ARGV[0]).transform_keys(&:to_s))', path],
                             check=True, capture_output=True, text=True).stdout
        return json.loads(out)


def triggers(wf):
    for k in ('on', True, 'true'):
        if k in wf:
            return wf[k]
    raise ExprError('workflow has no on:')


def declared_inputs(wf, event):
    t = triggers(wf).get(event) or {}
    return {k: (v or {}).get('default') for k, v in (t.get('inputs') or {}).items()}


def context(wf, event, given=None, fork=False, ref_type='branch', repo='hemilabs/zk-miner'):
    """GitHub's contexts for `event`: inputs are empty on push and pull_request, the declared
    defaults overlaid with `given` on workflow_dispatch and workflow_call."""
    if event in ('workflow_dispatch', 'workflow_call'):
        inputs = {k: v for k, v in declared_inputs(wf, event).items() if v is not None}
        inputs.update(given or {})
        inputs = {k: (float(v) if is_num(v) else v) for k, v in inputs.items()}
    else:
        assert not given
        inputs = {}
    gh = {'event_name': event if event != 'workflow_call' else 'push', 'ref': 'refs/heads/main',
          'ref_type': ref_type, 'repository': repo, 'workflow': 'macOS Build', 'sha': 'f' * 40,
          'event': {}}
    if event == 'pull_request':
        gh['event'] = {'pull_request': {'head': {'repo': {'full_name': 'someone/zk-miner' if fork else repo}}}}
        gh['ref'] = 'refs/pull/1/merge'
    if event == 'workflow_call':
        gh['workflow'] = 'Release'
    return {'inputs': inputs, 'github': gh, 'vars': {}, 'secrets': {'GITHUB_TOKEN': '***'},
            'runner': {'temp': '/runner/temp', 'os': 'macOS'}, 'env': {}, 'needs': {}, 'matrix': {},
            'steps': {}, 'job': {}, 'strategy': {}}


def all_expressions(node, where=''):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from all_expressions(v, f'{where}.{k}')
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from all_expressions(v, f'{where}[{i}]')
    elif isinstance(node, str) and '${{' in node:
        yield where, node


# --------------------------------------------------------------------------- tests

def main(argv):
    repo = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '..'))
    if len(argv) >= 2 and argv[0] == '--repo':
        repo = argv[1]
    passed = failed = 0

    def check(name, got, want):
        nonlocal passed, failed
        if got == want or (isinstance(want, float) and isinstance(got, float) and math.isnan(want) and math.isnan(got)):
            passed += 1
        else:
            failed += 1
            print(f'FAIL {name}: got {got!r}, want {want!r}')

    # 1. The evaluator against the documented semantics.
    empty = {'inputs': {}, 'github': {'event_name': 'push'}}
    for e, want in [
        ('null == 0', True), ('false == 0', True), ('true == 1', True), ("'' == 0", True),
        ("'' == null", True), ("'1' == 1", True), ("'abc' == 'ABC'", True), ("'abc' == 0", False),
        ('NaN == NaN', False), ('null != false', False), ('null == false', True),
        ("format('{0}', null)", ''), ("format('{0}', false)", 'false'), ("format('{0}', true)", 'true'),
        ("format('{0} {{x}} {1}', 'a', 14)", 'a {x} 14'), ("null || 'pinned'", 'pinned'),
        ("'xcode' || 'pinned'", 'xcode'), ("false && '0' || '1'", '1'), ("true && '0' || '1'", '0'),
        ('!null', True), ("!''", True), ('!0', True), ("!'false'", False), ('inputs.missing', None),
        ('inputs.missing.deeper', None), ("contains('Hello', 'ell')", True),
        ("startsWith('refs/tags/v1', 'refs/TAGS/')", True), ("fromJSON('[1,2]')[1]", 2),
        ("github.EVENT_NAME == 'PUSH'", True), ('1 < 2 && 2 <= 2', True), ("'b' > 'A'", True),
    ]:
        check(f'expr {e}', evaluate(e, empty), want)

    # 2. The round-1 finding, reproduced: the old expressions on push.
    check('round-1 finding: old metal-probe if on push', condition('${{ inputs.metal_probe != false }}', empty), False)
    check('round-1 finding: old PROBE_PROOF on push', render("${{ inputs.probe_proof == false && '0' || '1' }}", empty), '0')

    # 3. build-macos.yml per event.
    wf = load_yaml(os.path.join(repo, '.github/workflows/build-macos.yml'))
    rel = load_yaml(os.path.join(repo, '.github/workflows/release.yml'))
    release_with = (rel['jobs']['macos'].get('with') or {})
    check('release.yml calls build-macos.yml', rel['jobs']['macos'].get('uses'), './.github/workflows/build-macos.yml')
    jobs = wf['jobs']
    probe = jobs['metal-probe']
    probe_step = next(s for s in probe['steps'] if 'PROBE_PROOF' in (s.get('env') or {}))
    # (label, event, given inputs, fork) -> build/cpu-tests run, probe runs, PROBE_PROOF, METAL_TOOLCHAIN
    cases = [
        ('push', 'push', None, False, True, True, '1', 'pinned'),
        ('pull_request (same repo)', 'pull_request', None, False, True, True, '1', 'pinned'),
        ('pull_request (fork)', 'pull_request', None, True, False, False, '1', 'pinned'),
        ('workflow_dispatch defaults', 'workflow_dispatch', {}, False, True, True, '1', 'pinned'),
        ('workflow_dispatch metal_probe=false', 'workflow_dispatch', {'metal_probe': False}, False, True, False, '1', 'pinned'),
        ('workflow_dispatch probe_proof=false', 'workflow_dispatch', {'probe_proof': False}, False, True, True, '0', 'pinned'),
        ('workflow_dispatch metal_toolchain=xcode', 'workflow_dispatch', {'metal_toolchain': 'xcode'}, False, True, True, '1', 'xcode'),
        ('workflow_call with nothing', 'workflow_call', {}, False, True, True, '1', 'pinned'),
        ('workflow_call probe_proof=false', 'workflow_call', {'probe_proof': False}, False, True, True, '0', 'pinned'),
        ("workflow_call from release.yml's with:", 'workflow_call', dict(release_with), False, True, False, '1', 'pinned'),
    ]
    for label, event, given, fork, runs, probes, proof, tc in cases:
        ctx = context(wf, event, given, fork)
        for j in ('build', 'cpu-tests'):
            check(f'{label}: {j} runs', condition(jobs[j].get('if'), ctx), runs)
            check(f'{label}: {j} METAL_TOOLCHAIN', env_value(render(jobs[j]['env']['METAL_TOOLCHAIN'], ctx)), tc)
        check(f'{label}: metal-probe runs', runs and condition(probe.get('if'), ctx), probes)
        check(f'{label}: PROBE_PROOF', env_value(render(probe_step['env']['PROBE_PROOF'], ctx)), proof)
        # Every expression of the workflow evaluates in this event.
        for where, text in all_expressions(wf):
            try:
                render(text, ctx)
                passed += 1
            except Exception as ex:  # noqa: BLE001
                failed += 1
                print(f'FAIL {label}: {where}: {text!r}: {ex}')
        # The concurrency groups of the three jobs differ, and include the calling workflow.
        groups = [render(jobs[j]['concurrency']['group'], ctx) for j in ('build', 'cpu-tests', 'metal-probe')]
        check(f'{label}: distinct concurrency groups', len(set(groups)), 3)
        check(f'{label}: concurrency group names the workflow', all(ctx['github']['workflow'] in g for g in groups), True)
    # The release's call must not be able to build with another compiler: workflow_call declares no
    # metal_toolchain input.
    check('workflow_call has no metal_toolchain input', 'metal_toolchain' in declared_inputs(wf, 'workflow_call'), False)
    print(f'test-workflow-expressions: {passed} passed, {failed} failed')
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
