#!/usr/bin/env python3
"""Local stage-4 fixtures. Never starts an agent or reads a native agent home."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

SYSTEM_PATH = '/opt/homebrew/bin:/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin'
SPACE = 'project:stage4'
IDENTITIES = {'owner': 'agent:stage4-owner', 'A': 'agent:stage4-a', 'B': 'agent:stage4-b'}


class Failure(Exception):
    def __init__(self, code, detail):
        self.code, self.detail = code, detail
        super().__init__(detail)


def require(condition, code, detail):
    if not condition:
        raise Failure(code, detail)


def dump(path, value):
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')


def digest(path):
    return 'sha256:' + hashlib.sha256(path.read_bytes()).hexdigest()


def inside(root, path):
    path = Path(path).resolve()
    require(path.is_relative_to(root), 'path_escape', 'A fixture path escapes scratch')
    return path


def clean_env(root, name):
    base = root / name
    env = {key: str(base / sub) for key, sub in {
        'HOME': 'home', 'XDG_CONFIG_HOME': 'config', 'XDG_DATA_HOME': 'data',
        'XDG_STATE_HOME': 'state', 'XDG_CACHE_HOME': 'cache', 'TMPDIR': 'tmp',
        'GOCACHE': 'go-cache', 'GOPATH': 'go-path'}.items()}
    for value in env.values():
        Path(value).mkdir(parents=True, exist_ok=True, mode=0o700)
    env.update(PATH=SYSTEM_PATH, LANG='C', LC_ALL='C', TZ='UTC', GOENV='off',
               GOTOOLCHAIN='local', GOPROXY='off', GOSUMDB='off', CGO_ENABLED='0',
               GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL='/dev/null',
               GIT_CONFIG_SYSTEM='/dev/null', GIT_ALLOW_PROTOCOL='file',
               GIT_TERMINAL_PROMPT='0', GIT_SSH_COMMAND='false', SSH_AUTH_SOCK='/dev/null')
    return env


def call(command, env, cwd, label, evidence, stdin=None):
    """Logs public outputs, never an environment dump or private key contents."""
    result = subprocess.run([str(c) for c in command], env=env, cwd=cwd,
                            input=stdin, capture_output=True, text=True, timeout=600)
    dump(evidence / (label + '.json'), {'command': [str(c) for c in command],
         'exit': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr})
    require(result.returncode == 0, 'command_failed',
            f'{label} exited {result.returncode}; see evidence/{label}.json')
    return result.stdout.strip()


def memory(summary, name, args, label, stdin=None):
    root = Path(summary['scratch'])
    env = json.loads((root / f'{name}.env.json').read_text())
    result = json.loads(call([summary['installed']['shim'], '--json', *args], env,
                            summary['project'], label, root / 'evidence', stdin))
    require(result.get('type') == 'result' and result.get('error') is None
            and result.get('data_classification') == 'data', 'invalid_cli_result', label)
    return result['data']


def bare_env(env):
    return {k: v for k, v in env.items() if k not in ('GIT_DIR', 'GIT_WORK_TREE')}


def public_tree(source, dest):
    """Copy only the declared package input; never walk scratch or key trees."""
    require(not source.is_symlink(), 'invalid_source', 'Source root must not be a symlink')
    manifest = json.loads((source / 'agent-skill.json').read_text())
    require(manifest.get('build_roots') == ['go'] and manifest.get('runtime_roots') == []
            and manifest.get('commands') == {'memory': {'type': 'build', 'driver': 'go-v1',
                                                       'source_dir': 'go/cmd/memory'}},
            'invalid_source', 'Expected the local Go memory skill package')
    dest.mkdir()
    for name in ('SKILL.md', 'agent-skill.json', 'go'):
        item = source / name
        paths = [item, *item.rglob('*')] if item.is_dir() else [item]
        require(all(not p.is_symlink() for p in paths), 'invalid_source',
                'Package input contains a symlink')
        if item.is_dir():
            shutil.copytree(item, dest / name)
        else:
            shutil.copy2(item, dest / name)


def installation(root, project):
    """Validate Curator's context, marker, receipt, artifact and direct launcher."""
    skill = inside(root, project / '.agents/skills/memory')
    adapter = inside(root, project / '.codex/skills/memory')
    shim = project / '.agents/bin/memory'
    inside(root, shim)
    marker_path = skill / '.csk-install.json'
    marker = json.loads(marker_path.read_text())
    require((skill / 'SKILL.md').read_bytes() == (adapter / 'SKILL.md').read_bytes(),
            'skill_adapter_mismatch', 'Codex adapter differs from installed context')
    build = marker['builds']['memory']
    receipts = list((root / 'curator/home/.curator/cache/build').rglob('curator-receipt.ccj.json'))
    matches = [p for p in receipts if digest(p) == build['receipt_sha256']]
    require(len(matches) == 1, 'receipt_mismatch', 'No unique marker-bound build receipt')
    receipt = inside(root, matches[0])
    artifact = inside(root, receipt.parent / build['artifact_path'])
    require(digest(artifact) == build['artifact_sha256'], 'artifact_mismatch', 'Wrong build artifact')
    if shim.is_symlink():
        require(shim.resolve() == artifact, 'shim_target_mismatch', 'Shim has another target')
    else:
        # Curator manager §3 POSIX launcher: exact exec target, no shell evaluation.
        targets = [shlex.split(line)[1] for line in shim.read_text().splitlines()
                   if line.startswith('exec ')]
        require(targets == [str(artifact)], 'shim_target_mismatch', 'Unexpected Curator launcher')
    return {'shim': str(shim), 'shim_sha256': digest(shim), 'artifact': str(artifact),
            'artifact_sha256': digest(artifact), 'receipt': str(receipt),
            'receipt_sha256': digest(receipt), 'marker_sha256': digest(marker_path),
            'skill': str(skill), 'skill_sha256': digest(skill / 'SKILL.md'),
            'codex_adapter': str(project / '.codex/skills/memory')}


def prepare(args):
    root = Path(args.scratch).absolute()
    source = Path(args.source).resolve()
    require(not root.exists(), 'scratch_exists', 'Use a fresh, absent scratch directory')
    require(not source.is_relative_to(root) and root != source, 'invalid_scratch',
            'Scratch cannot contain the source checkout')
    root.mkdir(parents=True, mode=0o700)
    root = root.resolve()
    evidence = root / 'evidence'
    evidence.mkdir(mode=0o700)
    env = clean_env(root, 'curator')
    curator = Path(args.curator or shutil.which('curator') or '').resolve()
    go = Path(args.go or shutil.which('go', path=SYSTEM_PATH) or '').resolve()
    require(curator.is_file() and go.is_file(), 'missing_tool', 'Curator and Go executables required')
    # Tool selection is explicit/discovered, but no inherited variables enter a child.
    goroot = call([go, 'env', 'GOROOT'], env, root, 'go-root', evidence)
    env.update(GOROOT=goroot, PATH=str(go.parent) + ':' + SYSTEM_PATH)
    dump(evidence / 'curator-environment.json', env)
    call([go, 'version'], env, root, 'go-version', evidence)
    call([curator, '--version'], env, root, 'curator-version', evidence)
    public_tree(source, root / 'source')
    project = root / 'project'
    project.mkdir()
    dump(project / 'Skillfile.json', {'schema_version': 2, 'project': {'alias': 'stage4'},
         'agents': ['codex_cli'], 'sources': {'memory-source': {'path': str(root / 'source')}},
         'skills': [{'name': 'memory', 'from': 'memory-source', 'directory': '.'}]})
    call([curator, 'skill', 'check', root / 'source', '--json'], env, root, 'skill-check', evidence)
    call([curator, 'bootstrap', '--skills-root', root / 'sources', '--default-agents',
          'codex_cli', '--non-interactive'], env, root, 'bootstrap', evidence)
    call([curator, 'project', 'resolve', project], env, root, 'resolve', evidence)
    call([curator, 'install', project, '--verbose'], env, root, 'install', evidence)
    installed = installation(root, project)
    summary = {'schema_version': 1, 'scratch': str(root), 'project': str(project),
               'source_checkout': str(source), 'installed': installed,
               'space': SPACE, 'remote': str(root / 'remote.gitstore'), 'agents': {}}
    signers = root / 'allowed_signers'
    lines = []
    for name, identity in IDENTITIES.items():
        agent_env = clean_env(root, name)
        base = root / name
        key = base / 'commit_signer'
        call(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-C', f'stage4-{name}',
              '-f', key], agent_env, root, f'{name}-signer', evidence)
        email = f'stage4-{name.lower()}@example.invalid'
        lines.append(email + ' ' + (base / 'commit_signer.pub').read_text().strip())
        signers.write_text('\n'.join(lines) + '\n')
        settings = [('user.signingkey', str(key)), ('gpg.format', 'ssh'),
                    ('gpg.ssh.program', shutil.which('ssh-keygen', path=SYSTEM_PATH)),
                    ('gpg.ssh.allowedSignersFile', str(signers)), ('core.hooksPath', '/dev/null'),
                    ('commit.gpgsign', 'true')]
        agent_env.update(PATH=str(project / '.agents/bin') + ':' + SYSTEM_PATH,
                         MEMORY_HOME=str(base / 'memory'),
                         GIT_AUTHOR_NAME=f'Stage4 {name}', GIT_AUTHOR_EMAIL=email,
                         GIT_COMMITTER_NAME=f'Stage4 {name}', GIT_COMMITTER_EMAIL=email,
                         GIT_CONFIG_COUNT=str(len(settings)))
        for i, (k, v) in enumerate(settings):
            agent_env[f'GIT_CONFIG_KEY_{i}'] = k
            agent_env[f'GIT_CONFIG_VALUE_{i}'] = v
        # Pre-create an empty worktree and separate metadata, with no .git entry.
        # spaces init/add adopt it through their existing-clone path, then perform
        # normal genesis verification, fetch, sync, admission and publication.
        clone = base / 'memory/clones' / hashlib.sha256(SPACE.encode()).hexdigest()
        clone.mkdir(parents=True, mode=0o700)
        metadata = base / 'git-store'
        call(['git', 'init', '--bare', '--initial-branch=main', metadata], agent_env,
             root, f'{name}-git-init', evidence)
        for setting, value in [('core.bare', 'false'), ('core.worktree', str(clone))]:
            call(['git', '--git-dir', metadata, 'config', setting, value], agent_env,
                 root, f'{name}-{setting}', evidence)
        call(['git', '--git-dir', metadata, 'remote', 'add', 'origin', summary['remote']],
             agent_env, root, f'{name}-origin', evidence)
        agent_env.update(GIT_DIR=str(metadata), GIT_WORK_TREE=str(clone))
        dump(root / f'{name}.env.json', agent_env)
        envfile = root / (f'agent-{name}.env' if name != 'owner' else 'owner.env')
        envfile.write_text('# Source only in an empty environment; see README.\n' + ''.join(
            f'export {k}={shlex.quote(v)}\n' for k, v in sorted(agent_env.items())))
        envfile.chmod(0o600)
        keyinfo = memory(summary, name, ['keys', 'init', '--identity', identity], f'{name}-memory-key')
        summary['agents'][name] = dict(keyinfo, env_file=str(envfile),
                                      memory_home=agent_env['MEMORY_HOME'],
                                      clone=str(clone), git_dir=str(metadata),
                                      env_sha256=digest(root / f'{name}.env.json'))
    owner_env = bare_env(json.loads((root / 'owner.env.json').read_text()))
    call(['git', 'init', '--bare', '--initial-branch=main', summary['remote']], owner_env,
         project, 'remote-init', evidence)
    init = memory(summary, 'owner', ['spaces', 'init', SPACE, '--remote', summary['remote'],
                                    '--kind', 'project'], 'space-init')
    summary.update(genesis_digest=init['policy_digest'], genesis_commit=init['cursor'])
    for name in ('A', 'B'):
        agent = summary['agents'][name]
        memory(summary, 'owner', ['keys', 'register', '--space', SPACE, '--identity', agent['identity'],
                                  '--public-key', agent['public_key']], f'{name}-register')
        for role in ('writer', 'reader'):
            memory(summary, 'owner', ['policy', 'grant', '--space', SPACE, '--identity',
                                      agent['identity'], '--role', role], f'{name}-grant-{role}')
    for name in ('A', 'B'):
        memory(summary, name, ['spaces', 'add', SPACE, '--remote', summary['remote'], '--branch',
                               'main', '--genesis', summary['genesis_digest'], '--kind', 'project'],
               f'{name}-space-add')
        memory(summary, name, ['sync', '--space', SPACE], f'{name}-initial-sync')
        spaces = memory(summary, name, ['spaces', 'list'], f'{name}-spaces')['spaces']
        require(len(spaces) == 1 and spaces[0]['id'] == SPACE, 'fixture_spaces', name)
        summary['agents'][name]['clone'] = str(inside(root, spaces[0]['clone_path']))
    summary['prepared_head'] = call(['git', '--git-dir', summary['remote'], 'rev-parse', 'main'],
                                    owner_env, project, 'prepared-head', evidence)
    dump(root / 'summary.json', summary)
    print(json.dumps(summary, indent=2, sort_keys=True))


def load(root):
    root = Path(root).resolve()
    s = json.loads((root / 'summary.json').read_text())
    require(s['scratch'] == str(root), 'scratch_moved', 'Scratch must stay at its original path')
    for name in IDENTITIES:
        require(digest(root / f'{name}.env.json') == s['agents'][name]['env_sha256'],
                'environment_changed', name)
    return s


def verify(args):
    s = load(args.scratch)
    root, project = Path(s['scratch']), Path(s['project'])
    evidence = root / 'evidence'
    require(args.topic.strip() and args.expected.strip(), 'empty_expectation',
            'Topic and expected text must be nonempty')
    require(installation(root, project) == s['installed'], 'installation_changed',
            'Installed skill/launcher/artifact/receipt changed since prepare')
    env = bare_env(json.loads((root / 'owner.env.json').read_text()))
    head = call(['git', '--git-dir', s['remote'], 'rev-parse', 'main'], env, project,
                'verify-remote-head', evidence)
    checks = {}
    for name in ('A', 'B'):
        rows = memory(s, name, ['check', '--space', SPACE], f'verify-{name}-check')['spaces']
        require(len(rows) == 1 and rows[0]['id'] == SPACE and rows[0]['cursor'] == head
                and rows[0]['diagnostic_count'] == 0 and rows[0]['diagnostics'] == [],
                'check_not_clean', name)
        checks[name] = rows[0]
    recall = memory(s, 'B', ['recall', args.topic, '--space', SPACE, '--require-current'], 'verify-B-recall')
    require(len(recall['spaces']) == 1 and recall['spaces'][0]['id'] == SPACE
            and recall['spaces'][0]['cursor'] == head and not recall['spaces'][0]['diagnostics'],
            'recall_not_clean', 'Recall must describe the verified remote head')
    items = [item for view in recall['spaces'][0]['views'] for item in view['items']]
    # A unique current documentary decision; no authoritative receipt is inferred.
    require(len(items) == 1, 'decision_not_unique', f'Expected one current topic item, got {len(items)}')
    item = items[0]
    require(item['issuer'] == IDENTITIES['A'] and item['submitter'] == IDENTITIES['A'],
            'wrong_issuer', 'Decision must be issued/submitted by A')
    require(item['currentness'] == 'current' and not item['needs_review'],
            'decision_not_current', 'Decision is not current/clean')
    values = [c['value'] for c in item['content'] if c['field'] == 'value' and isinstance(c['value'], str)]
    require(any(args.expected in value for value in values), 'decision_text_mismatch',
            'Current decision does not contain the expected text')
    refs = item['source_refs']
    require(refs and all(isinstance(r.get('id'), str) and r['id'] and
                        type(r.get('version')) is int and r['version'] > 0 for r in refs),
            'missing_source_refs', 'Decision must disclose exact source refs')
    commits = call(['git', '--git-dir', s['remote'], 'rev-list', '--reverse', 'main'],
                   env, project, 'verify-history', evidence).splitlines()
    records, seen = [], {}
    for n, commit in enumerate(commits):
        signature = call(['git', '--git-dir', s['remote'], 'log', '-1', '--format=%G?', commit],
                         env, project, f'verify-commit-{n}', evidence)
        require(signature == 'G', 'unsigned_commit', commit)
        paths = call(['git', '--git-dir', s['remote'], 'ls-tree', '-r', '--name-only', commit, '--',
                      'records/'], env, project, f'verify-record-paths-{n}', evidence).splitlines()
        for path in paths:
            if path in seen:
                continue
            raw = call(['git', '--git-dir', s['remote'], 'show', f'{commit}:{path}'],
                       env, project, f'verify-record-{len(records)}', evidence)
            record = json.loads(raw)
            envelope, signature = record['record']['envelope'], record['signature']
            row = {'path': path, 'introduced_at': commit, 'ref': {'id': envelope['id'],
                   'version': envelope['version']}, 'issuer': envelope['issuer'],
                   'submitter': envelope['submitter'], 'key': signature['key'], 'kind': envelope['kind']}
            records.append(row)
            seen[path] = record
    akey, bkey = s['agents']['A']['key_id'], s['agents']['B']['key_id']
    require(not any(r['key'] == bkey or r['issuer'] == IDENTITIES['B']
                    or r['submitter'] == IDENTITIES['B'] for r in records),
            'b_wrote_record', 'History contains a record written by B')
    matches = [r for r in records if r['ref'] == item['ref'] and r['key'] == akey
               and r['issuer'] == IDENTITIES['A'] and r['submitter'] == IDENTITIES['A']]
    require(len(matches) == 1, 'missing_a_signed_record', 'Recalled item lacks its A-key signed record')
    require(all(any(r['ref'] == ref and r['kind'] == 'source' and r['key'] == akey for r in records)
                for ref in refs), 'missing_signed_source', 'Source ref lacks its A-key signed source')
    require(installation(root, project) == s['installed'], 'installation_changed',
            'Installation changed during verification')
    result = {'verdict': 'pass', 'space': SPACE, 'head': head, 'topic': args.topic,
              'decision': item, 'checks': checks, 'history_records': records,
              'installed': s['installed'], 'execution_evidence': {
                  'verifier_invoked': s['installed']['shim'],
                  'agent_execution': 'Requires orchestrator launcher/tool transcript; state cannot attest past execution'}}
    dump(evidence / 'verdict.json', result)
    print(json.dumps(result, indent=2, sort_keys=True))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    p = commands.add_parser('prepare')
    p.add_argument('scratch')
    p.add_argument('source')
    p.add_argument('--curator', help='Trusted Curator executable (default: discovered on PATH)')
    p.add_argument('--go', help='Trusted Go executable (default: system tool path, no goenv shim)')
    p = commands.add_parser('verify')
    p.add_argument('scratch')
    p.add_argument('topic')
    p.add_argument('expected')
    args = parser.parse_args()
    os.umask(0o077)
    try:
        {'prepare': prepare, 'verify': verify}[args.command](args)
        return 0
    except (Failure, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        result = {'verdict': 'fail', 'reason': getattr(error, 'code', 'harness_error'), 'detail': str(error)}
        print(json.dumps(result, sort_keys=True))
        return 1


if __name__ == '__main__':
    sys.exit(main())
