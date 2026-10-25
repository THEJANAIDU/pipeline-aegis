"""Deterministic security agent. Never executes code from the scanned repository."""
import argparse
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import yaml

LEVELS = {'INFO': 'LOW', 'WARNING': 'MEDIUM', 'ERROR': 'HIGH'}
SEVERITIES = {'UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'}
DIGEST = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9./:_-]*@sha256:[a-f0-9]{64}$')
EXCLUDED = {'.git', '.venv', 'node_modules', '__pycache__', 'aegis-results'}


def finding(tool, rule, severity, path, line, message):
    # Never store source snippets, secret values, or scanner-generated messages.
    path = str(path).replace('\\', '/')
    key = f'{tool}|{rule}|{path}|{line}'
    return dict(tool=tool, rule=str(rule), severity=severity, path=path,
                line=int(line or 1), message=message,
                fingerprint=hashlib.sha256(key.encode()).hexdigest())


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def lint(root):
    results, errors = [], []
    def add(rule, path, message, severity='HIGH', line=1):
        results.append(finding('aegis', rule, severity, path, line, message))
    for folder, dirs, names in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED and not (Path(folder)/d).is_symlink())
        for name in sorted(names):
            p = Path(folder)/name
            if p.is_symlink():
                continue
            rel = str(p.relative_to(root))
            if name == '.semgrepignore' and p.read_text(errors='replace').strip():
                errors.append(f'Application-controlled Semgrep exclusions require security review: {rel}')
            if name != 'Dockerfile' and not name.endswith(('.yml', '.yaml', '.Dockerfile', '.tf', '.sh', '.bash')):
                continue
            if p.stat().st_size > 2_000_000:
                errors.append(f'File too large to lint: {rel}')
                continue
            text = p.read_text(errors='replace')
            if re.search(r'trivy:ignore', text, re.I):
                errors.append(f'Inline Trivy suppression requires security review: {rel}')
            if re.search(r'shellcheck\s+disable', text, re.I):
                errors.append(f'Inline ShellCheck suppression requires security review: {rel}')
            if name.endswith(('.tf','.sh','.bash')):
                continue
            if name == 'Dockerfile' or name.endswith('.Dockerfile'):
                instructions = [(i, x.strip()) for i,x in enumerate(text.splitlines(),1) if x.strip() and not x.lstrip().startswith('#')]
                users = [x.split(None,1)[1] for _,x in instructions if x.upper().startswith('USER ')]
                if not users or users[-1].split(':')[0] in ('0', 'root'):
                    add('DOCKER_NONROOT', rel, 'Set a non-root USER in the final build stage.')
                for i,x in instructions:
                    if x.upper().startswith('FROM ') and '@sha256:' not in x and not x.split()[1].isdigit() and x.split()[1].lower() != 'scratch':
                        add('DOCKER_BASE_PIN', rel, 'Pin external base images by digest; stage aliases require review.', 'MEDIUM', i)
                    if re.match(r'(?i)^(ARG|ENV)\s+.*(password|secret|token|private_key)', x):
                        add('DOCKER_BUILD_SECRET', rel, 'Use BuildKit secret mounts, not ARG/ENV credentials.', line=i)
                    if re.search(r'(?i)(curl|wget).*\|\s*(sh|bash)', x):
                        add('REMOTE_SCRIPT', rel, 'Verify downloaded tools before execution.', line=i)
                continue
            try:
                docs = list(yaml.safe_load_all(text))
            except yaml.YAMLError:
                errors.append(f'Invalid or unsupported YAML: {rel}')
                continue
            for doc in docs:
                for obj in walk(doc):
                    if obj.get('persistCredentials') is True:
                        add('ADO_PERSIST_CREDENTIALS', rel, 'Disable persisted checkout credentials.')
                    if obj.get('continueOnError') is True:
                        add('ADO_IGNORE_FAILURE', rel, 'Do not ignore failures in a security/deployment pipeline.')
                    if obj.get('condition') and re.search(r'\b(always|succeededOrFailed)\s*\(', str(obj['condition'])) and any('deployment' in child or 'environment' in child for child in walk(obj)):
                        add('ADO_DEPLOY_CONDITION', rel, 'Deployment must require successful prerequisite stages.')
                    if 'task' in obj and not re.search(r'@\d+$', str(obj['task'])):
                        add('ADO_TASK_VERSION', rel, 'Pin task major versions.', 'MEDIUM')
                    if obj.get('privileged') is True or obj.get('allowPrivilegeEscalation') is True or obj.get('hostNetwork') is True:
                        add('K8S_PRIVILEGE', rel, 'Remove privileged execution, escalation, and host networking.')
                    if obj.get('runAsUser') == 0:
                        add('K8S_ROOT', rel, 'Use a non-root workload identity.')
                    if 'image' in obj and isinstance(obj['image'], str) and obj.get('name') and '@sha256:' not in obj['image']:
                        add('K8S_IMAGE_DIGEST', rel, 'Deploy images by immutable digest.', 'HIGH')
            for i,line in enumerate(text.splitlines(),1):
                if re.search(r'(?i)(curl|wget).*\|\s*(sh|bash)', line):
                    add('REMOTE_SCRIPT', rel, 'Verify downloaded tools before execution.', line=i)
                if re.search(r'(?i)(docker\s+(run|create).*--privileged|chmod\s+777)', line):
                    add('UNSAFE_SCRIPT', rel, 'Remove privileged containers and world-writable permissions.', line=i)
                if re.search(r'(?i)(echo|printenv|env\s*$).*System.AccessToken', line):
                    add('ADO_TOKEN_LOG', rel, 'Do not print pipeline access tokens.', line=i)
    unique = {f['fingerprint']: f for f in results}
    return list(unique.values()), errors


def execute_json(command, root, timeout, allowed_codes=(0,), expect_list=False):
    """No shell. Suppress raw output because it may contain secrets."""
    env = {k:v for k,v in os.environ.items() if k in {'PATH','SYSTEMROOT','SSL_CERT_FILE','SSL_CERT_DIR','HTTPS_PROXY','HTTP_PROXY','NO_PROXY'}}
    env['HOME'] = str(root)
    env.update(SEMGREP_SEND_METRICS='off', SEMGREP_ENABLE_VERSION_CHECK='0')
    try:
        p = subprocess.run(command, cwd=root, env=env, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError('Scanner missing, could not start, or timed out') from None
    if p.returncode not in allowed_codes:
        raise ValueError(f'Scanner failed with exit code {p.returncode}')
    try:
        data = json.loads(p.stdout)
    except (ValueError, TypeError):
        raise ValueError('Scanner returned invalid JSON') from None
    if not isinstance(data, list if expect_list else dict):
        raise ValueError('Scanner returned invalid schema')
    return data


def normalized_path(value, root):
    p = Path(str(value))
    if p.is_absolute():
        try:
            return str(p.relative_to(root))
        except ValueError:
            return '<external>'
    if '..' in p.parts:
        return '<external>'
    return str(p)


def parse_trivy(data, root):
    if data.get('SchemaVersion') != 2:
        raise ValueError('Unsupported Trivy schema version')
    if 'Results' not in data:
        # Trivy emits null Results for a supported clean target.
        if 'SchemaVersion' not in data:
            raise ValueError('Trivy report missing SchemaVersion/Results')
    if not isinstance(data.get('Results') or [], list):
        raise ValueError('Invalid Trivy Results')
    out = []
    for result in data.get('Results') or []:
        path = normalized_path(result.get('Target', '.'), root)
        for key, idkey, message in [('Vulnerabilities','VulnerabilityID','Vulnerable dependency; review scanner advisory and upgrade.'),
                                     ('Misconfigurations','ID','Insecure configuration; review the scanner rule.'),
                                     ('Secrets','RuleID','Potential secret detected. Revoke and rotate; remove from history.')]:
            for item in result.get(key) or []:
                if key == 'Misconfigurations' and item.get('Status') == 'PASS':
                    continue
                sev = item.get('Severity', 'UNKNOWN').upper()
                if sev not in SEVERITIES:
                    sev = 'UNKNOWN'
                ident = str(item.get(idkey, 'unknown'))
                if key == 'Vulnerabilities':
                    ident += ':' + str(item.get('PkgName','unknown')) + ':' + str(item.get('InstalledVersion','unknown'))
                out.append(finding('trivy', ident, sev, path, item.get('StartLine',1), message))
    return out


def parse_semgrep(data, root):
    if not isinstance(data.get('results'), list):
        raise ValueError('Semgrep report missing results')
    if data.get('errors'):
        raise ValueError('Semgrep reported incomplete analysis or parse errors')
    return [finding('semgrep',x['check_id'], LEVELS.get(x['extra']['severity'],'HIGH'),
                    normalized_path(x['path'],root),x['start']['line'],
                    'Potential unsafe application code; review the Semgrep rule.') for x in data['results']]


def parse_ruff(data, root):
    if any(str(x.get('code','')).startswith('E9') or x.get('code')=='invalid-syntax' for x in data):
        raise ValueError('Ruff could not completely parse or read source')
    return [finding('ruff',x['code'],'HIGH' if x['code'].startswith('S') else 'MEDIUM',
                    normalized_path(x['filename'],root),x['location']['row'],
                    'Python lint/security issue; review the Ruff rule.') for x in data]


def parse_shellcheck(data, root):
    return [finding('shellcheck','SC'+str(x['code']),
                    'HIGH' if x['level']=='error' else 'MEDIUM',
                    normalized_path(x['file'],root),x['line'],
                    'Shell script issue; review the ShellCheck rule.') for x in data]


def source_files(root, suffix):
    for folder, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED and not (Path(folder)/d).is_symlink())
        for name in sorted(files):
            p=Path(folder)/name
            if p.suffix in suffix and not p.is_symlink():
                yield str(p)


def load_policy(path):
    p = json.loads(Path(path).read_text()) if path else {'block_severities':['HIGH','CRITICAL'],'exceptions':[]}
    if not isinstance(p,dict) or not isinstance(p.get('block_severities'),list) or not p['block_severities'] or not set(p['block_severities']) <= SEVERITIES:
        raise ValueError('Invalid block_severities')
    exceptions = p.get('exceptions',[])
    if not isinstance(exceptions,list):
        raise ValueError('Invalid exceptions')
    for x in exceptions:
        if not all(isinstance(x.get(k),str) and x[k].strip() for k in ('fingerprint','owner','reason','ticket','expires')):
            raise ValueError('Exception needs fingerprint, owner, reason, ticket, expires')
        if not re.fullmatch('[0-9a-f]{64}', x['fingerprint']):
            raise ValueError('Invalid exception fingerprint')
        expiry = dt.date.fromisoformat(x['expires'])
        if expiry < dt.date.today():
            raise ValueError('Expired exception; renew through security review or remove it')
        if expiry > dt.date.today()+dt.timedelta(days=90):
            raise ValueError('Exceptions cannot exceed 90 days')
    return p


def evaluate(findings, errors, policy):
    exceptions={x['fingerprint']:x for x in policy.get('exceptions',[])}
    for f in findings:
        f['exception'] = exceptions.get(f['fingerprint'])
        # Unknown scanner severity must never silently pass.
        f['blocking'] = not f['exception'] and (f['severity'] in policy['block_severities'] or f['severity']=='UNKNOWN')
    return 'error' if errors else ('blocked' if any(f['blocking'] for f in findings) else 'passed')


def write_reports(out, report):
    out.mkdir(parents=True,exist_ok=True)
    os.chmod(out,0o700)
    def write(name, data):
        p=out/name
        if p.is_symlink():
            raise ValueError('Refusing report symlink')
        # Private atomic replacement; never follows a pre-existing report file.
        fd,temp=tempfile.mkstemp(dir=out)
        with os.fdopen(fd,'w') as stream:
            stream.write(data)
        os.replace(temp,p)
    write('report.json',json.dumps(report,indent=2)+'\n')
    lines=['# Pipeline Aegis',f"Decision: **{report['decision']}**",'',f"Findings: {len(report['findings'])}; operational errors: {len(report['errors'])}",'',
           '|Severity|Rule|File|Line|Disposition|','|---|---|---|---|---|']
    def safe(x):
        return str(x).replace('|','\\|').replace('\n',' ').replace('<','&lt;')
    for f in report['findings']:
        lines.append('|'+ '|'.join(safe(x) for x in [f['severity'],f['rule'],f['path'],f['line'],'excepted' if f['exception'] else 'block' if f['blocking'] else 'review'])+'|')
    lines += ['', '## Operational errors']+[safe(e) for e in report['errors']]
    write('summary.md','\n'.join(lines)+'\n')
    rules={f['rule']: {'id':f['rule'],'shortDescription':{'text':f['message']}} for f in report['findings']}
    sarif={'version':'2.1.0','$schema':'https://json.schemastore.org/sarif-2.1.0.json','runs':[{'tool':{'driver':{'name':'Pipeline Aegis','rules':list(rules.values())}},'results':[
        {'ruleId':f['rule'],'level':'error' if f['blocking'] else 'warning','message':{'text':f['message']},
         'partialFingerprints':{'aegis/v1':f['fingerprint']},
         'locations':[{'physicalLocation':{'artifactLocation':{'uri':f['path']},'region':{'startLine':max(1,f['line'])}}}]} for f in report['findings']]}]}
    write('results.sarif',json.dumps(sarif,indent=2)+'\n')


def source_digest(root):
    digest=hashlib.sha256()
    for folder,dirs,names in os.walk(root,followlinks=False):
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED)
        for name in sorted(dirs+names):
            if (Path(folder)/name).is_symlink():
                raise ValueError('Symlink sources require an explicit reviewed materialization step')
        for name in sorted(names):
            p=Path(folder)/name
            if not p.is_file():
                raise ValueError('Special source files are unsupported')
            digest.update(str(p.relative_to(root)).encode()+b'\0')
            with p.open('rb') as stream:
                while chunk:=stream.read(1024*1024):
                    digest.update(chunk)
            digest.update(b'\0')
    return digest.hexdigest()


def scan(args):
    root=Path(args.repo).resolve(strict=True)
    if not root.is_dir():
        raise ValueError('Repository must be a directory')
    out=Path(args.output).resolve()
    if out == root or root in out.parents:
        raise ValueError('Reports must be outside the scanned repository')
    policy=load_policy(args.policy)
    source_before=source_digest(root)
    findings, errors=lint(root)
    coverage={'local-lint':'completed','sast':'not-run','filesystem':'not-run','image':'not-requested'}
    if args.lint_only:
        errors.append('Lint-only mode: SAST, dependency, secret, IaC and image coverage is incomplete; deployment is blocked')
    else:
        rules=Path(__file__).with_name('rules.yml')
        commands=[('sast',['semgrep','scan','--config',str(rules),'--json','--metrics','off','--disable-nosem','--no-rewrite-rule-ids','--no-git-ignore',str(root)],parse_semgrep),
                  ('filesystem',['trivy','fs','--config',os.devnull,'--ignorefile',os.devnull,'--secret-config','','--skip-dirs','.git','--scanners','vuln,secret,misconfig','--format','json','--exit-code','0',str(root)],parse_trivy)]
        python_files=list(source_files(root,{'.py'}))
        shell_files=list(source_files(root,{'.sh','.bash'}))
        if python_files:
            commands.append(('python-lint',['ruff','check','--isolated','--ignore-noqa','--no-cache','--select','E,F,B,S','--output-format','json',str(root)],parse_ruff))
        if shell_files:
            commands.append(('shell-lint',['shellcheck','--format=json','--norc',*shell_files],parse_shellcheck))
        if args.image:
            if not DIGEST.fullmatch(args.image):
                raise ValueError('Image must be a registry reference pinned to sha256 digest')
            commands.append(('image',['trivy','image','--config',os.devnull,'--ignorefile',os.devnull,'--secret-config','','--scanners','vuln,secret,misconfig','--format','json','--exit-code','0',args.image],parse_trivy))
        else:
            errors.append('No immutable image supplied: deployment image coverage is incomplete')
        # Separate working directory prevents scanners reading app-controlled scanner config.
        with tempfile.TemporaryDirectory(prefix='aegis-scanner-') as wd:
            for kind,command,parser in commands:
                try:
                    if kind in ('python-lint','shell-lint'):
                        data=execute_json(command,wd,args.timeout,allowed_codes=(0,1),expect_list=True)
                    else:
                        data=execute_json(command,wd,args.timeout)
                    findings.extend(parser(data,root))
                    coverage[kind]='completed'
                except (ValueError,KeyError,TypeError,AttributeError) as e:
                    coverage[kind]='error'
                    errors.append(f'{kind}: '+ (str(e) if isinstance(e,ValueError) else 'Invalid scanner schema'))
    if source_digest(root) != source_before:
        errors.append('Source changed during scanning; rescan an immutable checkout')
    findings=list({f['fingerprint']:f for f in findings}.values())
    report={'schema_version':1,'decision':evaluate(findings,errors,policy),
            'source_sha256':source_before,'created_at':dt.datetime.now(dt.timezone.utc).isoformat(),'image':args.image,
            'coverage':coverage,'findings':findings,'errors':errors,
            'policy_sha256':hashlib.sha256(json.dumps(policy,sort_keys=True).encode()).hexdigest()}
    write_reports(out,report)
    print(f"Pipeline Aegis: {report['decision']}; {len(findings)} findings; {len(errors)} errors. Reports: {out}")
    return {'passed':0,'blocked':1,'error':2}[report['decision']]



def verify_release(args):
    """Validate trusted same-run evidence; does not authenticate unsigned artifacts."""
    report=json.loads(Path(args.report).read_text())
    policy=load_policy(args.policy)
    expected_policy=hashlib.sha256(json.dumps(policy,sort_keys=True).encode()).hexdigest()
    if report.get('schema_version')!=1 or report.get('decision')!='passed' or report.get('errors'):
        raise ValueError('Release evidence did not pass')
    if not DIGEST.fullmatch(args.image) or report.get('image')!=args.image:
        raise ValueError('Release image differs from scanned image')
    if report.get('source_sha256')!=source_digest(Path(args.repo).resolve(strict=True)):
        raise ValueError('Release source differs from scanned source')
    if report.get('policy_sha256')!=expected_policy:
        raise ValueError('Release policy differs from scanned policy')
    now=dt.datetime.now(dt.timezone.utc)
    created=dt.datetime.fromisoformat(report['created_at'])
    age=(now-created).total_seconds()
    if not math.isfinite(args.max_age_hours) or age < -300 or age > args.max_age_hours*3600 or args.max_age_hours<=0:
        raise ValueError('Release evidence is stale or in the future')
    coverage=report.get('coverage',{})
    for key in ('local-lint','sast','filesystem','image'):
        if coverage.get(key)!='completed':
            raise ValueError('Release coverage is incomplete')
    for key,extensions in [('python-lint',{'.py'}),('shell-lint',{'.sh','.bash'})]:
        if (key in coverage or any(source_files(Path(args.repo).resolve(),extensions))) and coverage.get(key)!='completed':
            raise ValueError('Release lint coverage is incomplete')
    if evaluate(report['findings'],[],policy)!='passed':
        raise ValueError('Release findings fail the current policy')
    print('Pipeline Aegis: release evidence matches source, policy and image. Ops approval remains required.')
    return 0


def main():
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest='command',required=True)
    s=sub.add_parser('scan',help='Run local lint and required security scanners')
    s.add_argument('--repo',required=True)
    s.add_argument('--output',required=True)
    s.add_argument('--policy',help='Trusted policy JSON outside application control')
    s.add_argument('--image',help='Exact registry image@sha256:digest to deploy')
    s.add_argument('--timeout',type=int,default=600)
    s.add_argument('--lint-only',action='store_true',help='Fast local feedback; always blocks deployment')
    v=sub.add_parser('verify-release',help='Bind trusted same-run scan evidence to a release')
    v.add_argument('--report',required=True)
    v.add_argument('--repo',required=True)
    v.add_argument('--image',required=True)
    v.add_argument('--policy')
    v.add_argument('--max-age-hours',type=float,default=24)
    args=p.parse_args()
    try:
        return verify_release(args) if args.command=='verify-release' else scan(args)
    except (ValueError,OSError,TypeError,KeyError,AttributeError,yaml.YAMLError) as e:
        print(f'Pipeline Aegis configuration/report error: {type(e).__name__}. No deployment approval.',file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
