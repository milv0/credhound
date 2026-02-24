"""CredHound Reporter - 출력 포맷 담당 (JSON, SARIF 2.1.0, HTML)"""
import json
import html as _html_mod
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime, timezone

from scanner import Finding, CWE_MAP, REMEDIATION, SEVERITY_ORDER


def export_json(findings: List[Finding], stats: Dict, version: str,
                file_results: Dict = None, filepath: str = None, mask: bool = True) -> str:
    """JSON 형식으로 내보내기"""
    by_rule = {}
    by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    output = {
        'tool': {'name': 'credhound', 'version': version},
        'scan_time': datetime.now().isoformat(),
        'masked': mask,
        'statistics': {k: v for k, v in stats.items() if k != 'failed_files_list'},
        'summary': {
            'total_findings': len(findings),
            'by_rule': by_rule,
            'by_severity': by_severity,
        },
        'findings': [f.to_dict(mask=mask) for f in findings],
    }
    if file_results:
        output['file_pattern_findings'] = file_results
    json_str = json.dumps(output, indent=2, ensure_ascii=False, default=str)
    if filepath:
        Path(filepath).write_text(json_str, encoding='utf-8')
    return json_str


def export_sarif(findings: List[Finding], version: str,
                 filepath: str = None, mask: bool = True) -> str:
    """SARIF 2.1.0 형식으로 내보내기 (OASIS 표준)"""
    rule_map = {}
    for f in findings:
        if f.rule_id not in rule_map:
            cwe_id = CWE_MAP.get(f.rule_id)
            rule_def = {
                'id': f.rule_id,
                'name': f.rule_name,
                'shortDescription': {'text': f.rule_name},
                'defaultConfiguration': {
                    'level': 'error' if f.severity in ('CRITICAL', 'HIGH') else 'warning' if f.severity == 'MEDIUM' else 'note'
                },
                'properties': {'severity': f.severity},
            }
            if cwe_id:
                rule_def['relationships'] = [{
                    'target': {'id': cwe_id, 'guid': cwe_id,
                               'toolComponent': {'name': 'CWE'}},
                    'kinds': ['superset']
                }]
                cwe_num = cwe_id.split('-')[1]
                rule_def['helpUri'] = f'https://cwe.mitre.org/data/definitions/{cwe_num}.html'
                remediation = REMEDIATION.get(cwe_id, '')
                if remediation:
                    rule_def['help'] = {'text': remediation}
            rule_map[f.rule_id] = rule_def

    results = []
    for f in findings:
        display_text = Finding._mask_text(f.matched_text[:50]) if mask else f.matched_text[:50]
        result = {
            'ruleId': f.rule_id,
            'level': 'error' if f.severity in ('CRITICAL', 'HIGH') else 'warning' if f.severity == 'MEDIUM' else 'note',
            'message': {'text': f"[{f.severity}] {f.rule_name}: {display_text}..."},
            'fingerprints': {'credhound/v1': f.get_hash()},
            'locations': [{
                'physicalLocation': {
                    'artifactLocation': {'uri': f.file_path},
                    'region': {'startLine': f.line_number}
                }
            }],
            'properties': {'confidence': f.confidence, 'severity': f.severity}
        }
        if f.entropy is not None:
            result['properties']['entropy'] = f.entropy
        results.append(result)

    sarif = {
        '$schema': 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json',
        'version': '2.1.0',
        'runs': [{
            'tool': {
                'driver': {
                    'name': 'credhound',
                    'version': version,
                    'informationUri': 'https://github.com/credhound',
                    'rules': list(rule_map.values())
                }
            },
            'results': results,
            'invocations': [{
                'executionSuccessful': True,
                'endTimeUtc': datetime.now(timezone.utc).isoformat()
            }]
        }]
    }

    sarif_str = json.dumps(sarif, indent=2, ensure_ascii=False, default=str)
    if filepath:
        Path(filepath).write_text(sarif_str, encoding='utf-8')
    return sarif_str


def export_html(findings: List[Finding], stats: Dict, version: str,
                file_results: Dict = None, filepath: str = None, mask: bool = True) -> str:
    """HTML 리포트 생성"""
    by_rule = {}
    by_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for f in findings:
        by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1

    sev_colors = {'CRITICAL': '#dc3545', 'HIGH': '#fd7e14', 'MEDIUM': '#ffc107', 'LOW': '#28a745'}
    esc = _html_mod.escape

    rows = ""
    for f in sorted(findings, key=lambda x: SEVERITY_ORDER.get(x.severity, 3)):
        text = Finding._mask_text(f.matched_text) if mask else f.matched_text
        color = sev_colors.get(f.severity, '#6c757d')
        rows += f"""<tr>
            <td><span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{esc(f.severity)}</span></td>
            <td>{esc(f.rule_name)}</td>
            <td style="font-family:monospace;font-size:13px">{esc(text)}</td>
            <td style="font-size:13px">{esc(str(f.file_path))}</td>
            <td>{int(f.line_number)}</td>
            <td>{esc(f.confidence)}</td>
        </tr>"""

    chart_bars = ""
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = by_severity[sev]
        if count > 0:
            max_c = max(by_severity.values()) or 1
            width = int((count / max_c) * 200)
            chart_bars += f'<div style="margin:4px 0"><span style="display:inline-block;width:80px;font-weight:bold;color:{sev_colors[sev]}">{esc(sev)}</span><span style="display:inline-block;width:{width}px;height:20px;background:{sev_colors[sev]};border-radius:3px"></span> <b>{int(count)}</b></div>'

    rule_rows = ""
    for rule_id, count in sorted(by_rule.items(), key=lambda x: -x[1]):
        rule_rows += f"<tr><td>{esc(str(rule_id))}</td><td>{int(count)}</td></tr>"

    file_counts = {}
    for f in findings:
        file_counts[f.file_path] = file_counts.get(f.file_path, 0) + 1
    file_rows = ""
    for fp, count in sorted(file_counts.items(), key=lambda x: -x[1])[:15]:
        file_rows += f"<tr><td style='font-size:13px'>{esc(str(fp))}</td><td>{int(count)}</td></tr>"

    html_output = f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>CredHound Report</title>
<style>
body{{font-family:-apple-system,BlinkMacSystemFont,sans-serif;margin:40px;background:#f8f9fa}}
h1{{color:#212529}} h2{{color:#495057;border-bottom:2px solid #dee2e6;padding-bottom:8px}}
table{{border-collapse:collapse;width:100%;margin-bottom:30px}} th,td{{border:1px solid #dee2e6;padding:8px;text-align:left}}
th{{background:#343a40;color:#fff}} tr:nth-child(even){{background:#f8f9fa}} tr:hover{{background:#e9ecef}}
.stats{{display:flex;gap:20px;margin:20px 0;flex-wrap:wrap}} .stat-card{{background:#fff;padding:20px;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.1);flex:1;text-align:center;min-width:150px}}
.stat-card h3{{margin:0;color:#6c757d;font-size:14px}} .stat-card p{{margin:8px 0 0;font-size:28px;font-weight:bold;color:#212529}}
details{{margin:10px 0;background:#fff;border-radius:8px;padding:15px;box-shadow:0 1px 3px rgba(0,0,0,.1)}}
summary{{cursor:pointer;font-weight:bold;font-size:16px;color:#495057}}
</style></head><body>
<h1>🐕 CredHound Report</h1>
<p>스캔 시간: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | 마스킹: {'ON' if mask else 'OFF'}</p>
<div class="stats">
    <div class="stat-card"><h3>총 발견</h3><p>{len(findings)}</p></div>
    <div class="stat-card"><h3>스캔 파일</h3><p>{stats.get('files_scanned', 0):,}</p></div>
    <div class="stat-card"><h3>스캔 시간</h3><p>{stats.get('scan_time', 0):.1f}초</p></div>
    <div class="stat-card"><h3>CRITICAL</h3><p style="color:#dc3545">{by_severity['CRITICAL']}</p></div>
    <div class="stat-card"><h3>HIGH</h3><p style="color:#fd7e14">{by_severity['HIGH']}</p></div>
</div>
<h2>위험도별 분포</h2>
{chart_bars}
<details><summary>📊 룰별 요약</summary>
<table><tr><th>규칙</th><th>건수</th></tr>{rule_rows}</table>
</details>
<details><summary>📁 파일별 요약 (상위 15개)</summary>
<table><tr><th>파일</th><th>건수</th></tr>{file_rows}</table>
</details>
<h2>탐지 결과 ({len(findings)}건)</h2>
<table><tr><th>심각도</th><th>규칙</th><th>탐지 값</th><th>파일</th><th>라인</th><th>신뢰도</th></tr>
{rows}
</table>
<p style="color:#6c757d;margin-top:40px;font-size:12px">Generated by credhound v{version}</p>
</body></html>"""

    if filepath:
        Path(filepath).write_text(html_output, encoding='utf-8')
    return html_output
