import datetime as dt
import json
from pathlib import Path
from unittest.mock import patch
import pytest
from aegis.cli import (lint, finding, evaluate, parse_semgrep, parse_trivy,
                       load_policy, main, execute_json, write_reports, DIGEST)


def test_pipeline_and_docker_lint(tmp_path):
    (tmp_path/'azure-pipelines.yml').write_text('steps:\n- checkout: self\n  persistCredentials: true\n- task: Thing\n  continueOnError: true\n')
    (tmp_path/'Dockerfile').write_text('FROM python:latest\nARG ACCESS_TOKEN\nUSER root\n')
    hits,errors=lint(tmp_path)
    assert not errors
    assert {'ADO_PERSIST_CREDENTIALS','ADO_IGNORE_FAILURE','ADO_TASK_VERSION','DOCKER_NONROOT','DOCKER_BUILD_SECRET'} <= {x['rule'] for x in hits}


def test_symlinks_and_invalid_yaml(tmp_path):
    (tmp_path/'outside.yml').symlink_to('/etc/passwd')
    (tmp_path/'bad.yml').write_text('foo: [')
    hits,errors=lint(tmp_path)
    assert not hits and len(errors)==1


def test_secret_redaction(tmp_path):
    data={'SchemaVersion':2,'Results':[{'Target':'app.py','Secrets':[{'RuleID':'generic','Severity':'HIGH','Match':'DO_NOT_LEAK','Code':{'Lines':['SECRET']}}]}]}
    result=parse_trivy(data,tmp_path)
    assert 'DO_NOT_LEAK' not in json.dumps(result)
    assert 'SECRET' not in json.dumps(result)


def test_sast_errors_fail_closed(tmp_path):
    with pytest.raises(ValueError):
        parse_semgrep({'results':[],'errors':[{'message':'secret'}]},tmp_path)
    with pytest.raises(ValueError):
        parse_semgrep({},tmp_path)


def test_coverage_and_unknown_severity():
    f=finding('x','r','UNKNOWN','x',1,'review')
    assert evaluate([f],[],{'block_severities':['HIGH']})=='blocked'
    assert evaluate([],['missing scanner'],{'block_severities':['HIGH']})=='error'


def test_exception_expiry(tmp_path):
    p=tmp_path/'policy.json'
    base={'block_severities':['HIGH'],'exceptions':[dict(fingerprint='a'*64,owner='Ops',reason='accepted',ticket='SEC-1',expires='2020-01-01')]}
    p.write_text(json.dumps(base))
    with pytest.raises(ValueError): load_policy(p)
    base['exceptions'][0]['expires']=(dt.date.today()+dt.timedelta(days=7)).isoformat()
    p.write_text(json.dumps(base))
    assert load_policy(p)['exceptions']


def test_exception_exact_match():
    a=finding('x','r','HIGH','app.py',1,'review')
    b=finding('x','r','HIGH','other.py',1,'review')
    policy={'block_severities':['HIGH'],'exceptions':[dict(fingerprint=a['fingerprint'],owner='Ops')]}
    assert evaluate([a,b],[],policy)=='blocked'
    assert a['exception'] and not b['exception']


def test_missing_tool_and_timeout(tmp_path):
    with pytest.raises(ValueError): execute_json(['/nonexistent/aegis-tool'],tmp_path,1)
    with patch('subprocess.run',side_effect=__import__('subprocess').TimeoutExpired('tool',1)):
        with pytest.raises(ValueError): execute_json(['tool'],tmp_path,1)


def test_malformed_scanner_json(tmp_path):
    for code,stdout in [(0,'oops'),(2,'{}'),(0,'[]')]:
        with patch('subprocess.run',return_value=__import__('subprocess').CompletedProcess([],code,stdout,'')):
            with pytest.raises(ValueError): execute_json(['tool'],tmp_path,1)


def test_digest_validation():
    assert DIGEST.fullmatch('registry.example/app@sha256:'+'a'*64)
    assert not DIGEST.fullmatch('registry.example/app:latest')
    assert not DIGEST.fullmatch('--help@sha256:'+'a'*64)


def test_lint_only_never_passes(tmp_path):
    repo=tmp_path/'app';repo.mkdir()
    out=tmp_path/'reports'
    with patch('sys.argv',['aegis','scan','--repo',str(repo),'--output',str(out),'--lint-only']):
        assert main()==2
    report=json.loads((out/'report.json').read_text())
    assert report['decision']=='error'
    assert (out/'results.sarif').exists()


def test_full_scan_with_adapter_contract(tmp_path):
    repo=tmp_path/'app';repo.mkdir()
    out=tmp_path/'reports'
    clean=[{'results':[],'errors':[]},{'SchemaVersion':2,'Results':[]},{'SchemaVersion':2,'Results':[]}]
    with patch('aegis.cli.execute_json',side_effect=clean),patch('sys.argv',['aegis','scan','--repo',str(repo),'--output',str(out),'--image','registry/app@sha256:'+'a'*64]):
        assert main()==0
    report=json.loads((out/'report.json').read_text())
    assert report['coverage']['image']=='completed'


def test_missing_image_blocks(tmp_path):
    repo=tmp_path/'app';repo.mkdir()
    with patch('aegis.cli.execute_json',side_effect=[{'results':[]},{'SchemaVersion':2}]),patch('sys.argv',['aegis','scan','--repo',str(repo),'--output',str(tmp_path/'out')]):
        assert main()==2


def test_reports_inside_source_rejected(tmp_path):
    with patch('sys.argv',['aegis','scan','--repo',str(tmp_path),'--output',str(tmp_path/'out'),'--lint-only']):
        assert main()==2


def test_kubernetes_privilege(tmp_path):
    (tmp_path/'pod.yml').write_text('apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  containers:\n  - name: app\n    image: nginx:latest\n    securityContext:\n      privileged: true\n      runAsUser: 0\n')
    hits,_=lint(tmp_path)
    assert {'K8S_ROOT','K8S_PRIVILEGE','K8S_IMAGE_DIGEST'} <= {x['rule'] for x in hits}


def test_scanner_environment_is_scrubbed(tmp_path, monkeypatch):
    monkeypatch.setenv('TRIVY_SEVERITY','LOW')
    monkeypatch.setenv('AZURE_CLIENT_SECRET','private')
    with patch('subprocess.run',return_value=__import__('subprocess').CompletedProcess([],0,'{}','')) as run:
        execute_json(['tool'],tmp_path,1)
    env=run.call_args.kwargs['env']
    assert 'TRIVY_SEVERITY' not in env and 'AZURE_CLIENT_SECRET' not in env


def test_application_suppression_blocks(tmp_path):
    (tmp_path/'.semgrepignore').write_text('*')
    (tmp_path/'deployment.yml').write_text('# trivy:ignore:AVD-KSV-0001\nkind: Pod')
    _,errors=lint(tmp_path)
    assert len(errors)==2


def test_advanced_lint_adapters(tmp_path):
    from aegis.cli import parse_ruff, parse_shellcheck
    assert parse_ruff([{'code':'S602','filename':'app.py','location':{'row':3}}],tmp_path)[0]['severity']=='HIGH'
    assert parse_shellcheck([{'code':2086,'level':'warning','file':'build.sh','line':1}],tmp_path)[0]['rule']=='SC2086'


def test_source_binding_and_symlink(tmp_path):
    from aegis.cli import source_digest
    p=tmp_path/'app.py';p.write_text('print(1)')
    original=source_digest(tmp_path)
    p.write_text('print(2)')
    assert source_digest(tmp_path)!=original
    (tmp_path/'link.py').symlink_to(p)
    with pytest.raises(ValueError): source_digest(tmp_path)


def test_report_redaction_and_sarif(tmp_path):
    f=finding('trivy','secret-rule','HIGH','app.py',2,'Rotate the exposed credential.')
    evaluate([f],[],{'block_severities':['HIGH']})
    report={'decision':'blocked','findings':[f],'errors':[]}
    write_reports(tmp_path/'reports',report)
    assert json.loads((tmp_path/'reports/results.sarif').read_text())['runs'][0]['results'][0]['level']=='error'
    assert ((tmp_path/'reports/report.json').stat().st_mode & 0o777)==0o600


def test_release_evidence_binding(tmp_path):
    repo=tmp_path/'app';repo.mkdir()
    out=tmp_path/'reports';image='registry/app@sha256:'+'a'*64
    with patch('aegis.cli.execute_json',side_effect=[{'results':[]},{'SchemaVersion':2},{'SchemaVersion':2}]),patch('sys.argv',['aegis','scan','--repo',str(repo),'--output',str(out),'--image',image]):
        assert main()==0
    args=['aegis','verify-release','--repo',str(repo),'--report',str(out/'report.json'),'--image',image]
    with patch('sys.argv',args): assert main()==0
    with patch('sys.argv',args[:-1]+['registry/app@sha256:'+'b'*64]): assert main()==2
    (repo/'app.py').write_text('print(1)')
    with patch('sys.argv',args): assert main()==2


def test_release_stale_or_forged_pass(tmp_path):
    repo=tmp_path/'app';repo.mkdir()
    out=tmp_path/'reports';image='registry/app@sha256:'+'a'*64
    with patch('aegis.cli.execute_json',side_effect=[{'results':[]},{'SchemaVersion':2},{'SchemaVersion':2}]),patch('sys.argv',['aegis','scan','--repo',str(repo),'--output',str(out),'--image',image]):
        assert main()==0
    report=out/'report.json';data=json.loads(report.read_text())
    data['created_at']='2020-01-01T00:00:00+00:00';report.write_text(json.dumps(data))
    args=['aegis','verify-release','--repo',str(repo),'--report',str(report),'--image',image]
    with patch('sys.argv',args): assert main()==2
    data['created_at']=dt.datetime.now(dt.timezone.utc).isoformat()
    data['coverage']['image']='error';report.write_text(json.dumps(data))
    with patch('sys.argv',args): assert main()==2


def test_deployment_condition_on_parent_stage(tmp_path):
    (tmp_path/'azure-pipelines.yml').write_text('stages:\n- stage: Production\n  condition: always()\n  jobs:\n  - deployment: Release\n    environment: production\n')
    hits,errors=lint(tmp_path)
    assert not errors and any(x['rule']=='ADO_DEPLOY_CONDITION' for x in hits)


def test_ruff_incomplete_analysis_blocks(tmp_path):
    from aegis.cli import parse_ruff
    for code in ('E902','E999','invalid-syntax'):
        with pytest.raises(ValueError): parse_ruff([{'code':code}],tmp_path)
