#!/usr/bin/env python3
"""
Credential Scanner v2 - Main
업계 표준 CLI: argparse, CI/CD 모드, SARIF/JSON 출력, Pre-commit 훅
"""
import os
import sys
import signal
import logging
import argparse
from datetime import datetime
from pathlib import Path

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.prompt import Prompt, Confirm
from rich.text import Text

from scanner import CredentialScannerV2, Finding, EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR

console = Console()

_FORMAT_EXT = {'json': '.json', 'sarif': '.sarif', 'html': '.html'}


def _auto_output_path(fmt: str) -> str:
    """버전 + 타임스탬프 기반 자동 파일명 생성"""
    ext = _FORMAT_EXT.get(fmt, '.txt')
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"credhound_v{CredentialScannerV2.VERSION}_{ts}{ext}"


def format_size(size: int) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} TB"


def format_date(timestamp: float) -> str:
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')


def display_banner():
    banner_art = """
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║     🐕  C R E D H O U N D                                 ║
    ║                                                           ║
    ║        보안 credential 탐지 도구 (업계 표준 준수)         ║
    ║                                                           ║
    ║  ✨ 기능:                                                 ║
    ║     • 병렬 처리 / 순차 처리 선택                          ║
    ║     • SARIF 2.1.0 / JSON / HTML / 콘솔 출력              ║
    ║     • CI/CD 파이프라인 연동 (exit code)                   ║
    ║     • Pre-commit 훅 자동 설치                             ║
    ║     • Git 변경 파일만 스캔 (incremental)                  ║
    ║     • 30+ 탐지 규칙, 엔트로피 분석                       ║
    ║     • credential 마스킹 (기본 ON)                         ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """
    console.print(Panel(Text(banner_art, style="bold cyan"), border_style="bright_cyan", padding=(0, 2)))
    console.print()


def display_file_pattern_results(results: dict):
    total_files = sum(len(files) for files in results.values())
    if total_files == 0:
        return

    console.print("\n📁 파일명 기반 탐지")
    console.print("─" * 80)
    console.print()

    risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    sorted_categories = sorted(
        results.items(),
        key=lambda x: (risk_order.get(x[1][0]['severity'] if x[1] else 'LOW', 3), x[0])
    )

    for category, files in sorted_categories:
        if not files:
            continue
        severity = files[0]['severity']
        color_map = {'CRITICAL': 'red', 'HIGH': 'yellow', 'MEDIUM': 'cyan', 'LOW': 'white'}
        color = color_map.get(severity, 'white')
        console.print(f"[bold {color}]{category} ({len(files)}개)[/bold {color}]")
        console.print("─" * 80, style=color)
        for file_info in files:
            console.print(f"[cyan]경로:[/cyan] {file_info['path']}")
            console.print(f"[dim]크기: {format_size(file_info['size'])}[/dim]")
            console.print(f"[dim]수정일: {format_date(file_info['modified'])}[/dim]")
            console.print()
        console.print()


def display_content_findings(findings: list):
    if not findings:
        return

    console.print("\n🔍 내용 기반 탐지")
    console.print("─" * 80)
    console.print()

    findings_by_rule = {}
    for finding in findings:
        findings_by_rule.setdefault(finding.rule_name, []).append(finding)

    risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
    sorted_rules = sorted(
        findings_by_rule.items(),
        key=lambda x: (risk_order.get(x[1][0].severity, 3), x[0])
    )

    for rule_name, rule_findings in sorted_rules:
        severity = rule_findings[0].severity
        color_map = {'CRITICAL': 'red', 'HIGH': 'yellow', 'MEDIUM': 'cyan', 'LOW': 'white'}
        color = color_map.get(severity, 'white')
        confidence = rule_findings[0].confidence
        console.print(f"[bold {color}]{rule_name} ({len(rule_findings)}개) [dim][신뢰도: {confidence}][/dim][/bold {color}]")
        console.print("─" * 80, style=color)

        findings_by_credential = {}
        for finding in rule_findings:
            cred_key = finding.matched_text[:100]
            findings_by_credential.setdefault(cred_key, []).append(finding)

        for cred_value, cred_findings in findings_by_credential.items():
            if len(cred_findings) > 1:
                console.print(f"[yellow]{cred_value}[/yellow] [dim]({len(cred_findings)}개 파일에서 발견)[/dim]")
            else:
                console.print(f"[yellow]{cred_value}[/yellow]")
            if cred_findings[0].entropy:
                console.print(f"  [dim]엔트로피: {cred_findings[0].entropy:.2f}[/dim]")
            for finding in cred_findings:
                console.print(f"  [dim]- {finding.file_path} (라인 {finding.line_number})[/dim]")
            console.print()
        console.print()


def display_summary(file_results: dict, content_findings: list, stats: dict):
    risk_stats = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    for files in file_results.values():
        for fi in files:
            risk_stats[fi.get('severity', 'LOW')] += 1
    for finding in content_findings:
        risk_stats[finding.severity] += 1
    total_findings = sum(risk_stats.values())

    summary_table = Table(show_header=False, border_style="bright_green", padding=(0, 2), show_edge=True, box=None)
    summary_table.add_column("항목", style="bold bright_cyan", width=20)
    summary_table.add_column("값", style="bold bright_yellow", justify="right")

    scan_time = stats.get('scan_time', 0)
    time_str = f"{scan_time:.1f}초" if scan_time < 60 else f"{int(scan_time // 60)}분 {scan_time % 60:.1f}초"

    summary_table.add_row("⏱️  스캔 시간", time_str)
    summary_table.add_row("📂 발견된 파일", f"{stats['files_found']:,}개")
    summary_table.add_row("✅ 스캔 완료", f"{stats['files_scanned']:,}개")
    summary_table.add_row("🚫 제외됨", f"{stats.get('files_excluded', 0):,}개")
    if stats.get('files_failed', 0) > 0:
        summary_table.add_row("❌ 스캔 실패", f"{stats['files_failed']:,}개")
    summary_table.add_row("🔍 총 발견", f"{total_findings:,}개")
    if stats['excluded_count'] > 0:
        summary_table.add_row("🔒 Baseline 제외", f"{stats['excluded_count']:,}개")

    risk_bar = Text("\n\n위험도별 분포:\n", style="bold bright_white")
    max_count = max(risk_stats.values()) if any(risk_stats.values()) else 1
    for level, emoji, color in [('CRITICAL', '🔴', 'red'), ('HIGH', '🟠', 'yellow'), ('MEDIUM', '🟡', 'cyan'), ('LOW', '🟢', 'green')]:
        count = risk_stats[level]
        if count > 0:
            bar_length = int((count / max_count) * 30)
            risk_bar.append(f"\n{emoji} {level:8} ", style=f"bold {color}")
            risk_bar.append(f"{'█' * bar_length} ", style=f"bold {color}")
            risk_bar.append(f"{count}개", style=f"bright_{color}")

    console.print("\n")
    console.print(Panel(summary_table, title="[bold bright_green]📊 스캔 요약[/bold bright_green]", border_style="bright_green", padding=(1, 2)))
    console.print(Panel(risk_bar, border_style="bright_magenta", padding=(1, 2)))
    console.print("\n")


def save_results_text(file_results: dict, content_findings: list, scan_path: str, output_path: str = None, mask: bool = True):
    """결과를 텍스트 파일로 저장"""
    if not output_path:
        results_dir = Path("scan_results")
        results_dir.mkdir(exist_ok=True)
        existing = list(results_dir.glob("credential_scan_results_v2_*.txt"))
        numbers = []
        for fp in existing:
            try:
                numbers.append(int(fp.stem.split('_')[-1]))
            except Exception:
                continue
        next_num = max(numbers) + 1 if numbers else 1
        default_filename = f"credential_scan_results_v2_{next_num}.txt"
        output_file = Prompt.ask("[cyan]저장할 파일명[/cyan]", default=default_filename)
        output_path = str(results_dir / output_file)

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(f"Credential Scan Results\n")
        f.write(f"Scan Path: {scan_path}\n")
        f.write(f"Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")

        for category, files in file_results.items():
            if not files:
                continue
            f.write(f"{category} ({len(files)}개)\n")
            f.write("-" * 80 + "\n")
            for fi in files:
                f.write(f"경로: {fi['path']}\n크기: {format_size(fi['size'])}\n수정일: {format_date(fi['modified'])}\n\n")
            f.write("\n")

        if content_findings:
            findings_by_rule = {}
            for finding in content_findings:
                findings_by_rule.setdefault(finding.rule_name, []).append(finding)
            risk_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
            for rule_name, rule_findings in sorted(findings_by_rule.items(), key=lambda x: (risk_order.get(x[1][0].severity, 3), x[0])):
                f.write(f"{rule_name} ({len(rule_findings)}개) [신뢰도: {rule_findings[0].confidence}]\n")
                f.write("-" * 80 + "\n")
                by_cred = {}
                for finding in rule_findings:
                    key = Finding._mask_text(finding.matched_text[:100]) if mask else finding.matched_text[:100]
                    by_cred.setdefault(key, []).append(finding)
                for cred_value, cred_findings in by_cred.items():
                    if len(cred_findings) > 1:
                        f.write(f"{cred_value} ({len(cred_findings)}개 파일에서 발견)\n")
                    else:
                        f.write(f"{cred_value}\n")
                    if cred_findings[0].entropy:
                        f.write(f"  엔트로피: {cred_findings[0].entropy:.2f}\n")
                    for finding in cred_findings:
                        f.write(f"  - {finding.file_path} (라인 {finding.line_number})\n")
                    f.write("\n")
                f.write("\n")

    console.print(f"[green]✓ 결과가 '{output_path}'에 저장되었습니다.[/green]")


def interactive_baseline_update(scanner: CredentialScannerV2, findings: list):
    """인터랙티브 베이스라인 업데이트"""
    if not findings:
        console.print("[dim]업데이트할 항목이 없습니다.[/dim]")
        return

    console.print("\n[bold cyan]🔒 Baseline 업데이트 - False Positive 선택[/bold cyan]")
    console.print("─" * 80)

    for idx, f in enumerate(findings):
        color = {'CRITICAL': 'red', 'HIGH': 'yellow', 'MEDIUM': 'cyan', 'LOW': 'white'}.get(f.severity, 'white')
        console.print(f"[{color}][{idx + 1}][/{color}] [{color}]{f.severity}[/{color}] {f.rule_name}")
        console.print(f"    {f.matched_text[:80]}")
        console.print(f"    [dim]{f.file_path}:{f.line_number}[/dim]")

    console.print("\n[dim]제외할 항목 번호를 입력하세요 (쉼표 구분, 예: 1,3,5). 완료하려면 Enter[/dim]")
    selection = Prompt.ask("[cyan]선택[/cyan]", default="")

    if not selection.strip():
        return

    added = 0
    for part in selection.split(','):
        try:
            idx = int(part.strip()) - 1
            if 0 <= idx < len(findings):
                reason = Prompt.ask(f"[dim]#{idx + 1} 제외 사유[/dim]", default="False positive")
                scanner.baseline_manager.add_exclusion(findings[idx], reason)
                added += 1
        except ValueError:
            continue

    if added > 0:
        scanner.baseline_manager.save_baseline()
        console.print(f"[green]✓ {added}개 항목이 baseline에 추가되었습니다.[/green]")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='credhound',
        description='🐕 CredHound - 로컬 파일 보안 credential 탐지 도구 (업계 표준 준수)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
사용 예시:
  credhound                                            # 인터랙티브 모드 (HTML 자동 생성)
  credhound --path ~/project --ci                      # CI 모드
  credhound --path . --format html -o report.html      # HTML 리포트
  credhound --path . --format sarif -o results.sarif
  credhound --path . --format json -o results.json
  credhound --path ~ --parallel --severity HIGH        # 병렬 + HIGH 이상
  credhound --path ~ --parallel --group                # 중복 그룹핑
  credhound --path . --unmask                          # 마스킹 해제
  credhound --path . --cache                           # 변경 파일만 스캔
  credhound --path . --incremental                     # Git 변경분만
  credhound --install-hook                             # Pre-commit 훅 설치
  credhound --update-baseline                          # False positive 관리
"""
    )
    parser.add_argument('--version', '-V', action='version', version=f'credhound {CredentialScannerV2.VERSION}')
    parser.add_argument('--path', '-p', help='스캔할 경로 (기본: 현재 디렉토리)')
    parser.add_argument('--format', '-f', choices=['console', 'json', 'sarif', 'html'], default='console', help='출력 형식 (기본: console)')
    parser.add_argument('--output', '-o', help='결과 저장 파일 경로')
    parser.add_argument('--severity', '-s', choices=['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'], default='LOW', help='최소 심각도 필터 (기본: LOW)')
    parser.add_argument('--no-entropy', action='store_true', help='엔트로피 분석 비활성화')
    parser.add_argument('--entropy', action='store_true', help='엔트로피 분석 활성화 (기본 OFF)')
    parser.add_argument('--unmask', action='store_true', help='credential 값 마스킹 해제 (기본: 마스킹)')
    parser.add_argument('--group', action='store_true', help='같은 credential 값을 그룹핑하여 요약')
    parser.add_argument('--cache', action='store_true', help='변경된 파일만 스캔 (mtime 캐시 기반)')
    parser.add_argument('--baseline', help='Baseline 파일 경로')
    parser.add_argument('--update-baseline', action='store_true', help='인터랙티브 baseline 업데이트')
    parser.add_argument('--install-hook', action='store_true', help='Pre-commit 훅 설치')
    parser.add_argument('--ci', action='store_true', help='CI 모드 (비대화형, exit code 반환)')
    parser.add_argument('--parallel', action='store_true', help='병렬 처리 활성화')
    parser.add_argument('--incremental', action='store_true', help='Git 변경 파일만 스캔')
    parser.add_argument('--config', help='설정 파일 경로')
    parser.add_argument('--rules', help='규칙 파일 경로')
    parser.add_argument('--verbose', '-v', action='store_true', help='상세 출력')
    return parser


def _find_data_file(filename: str) -> str:
    """config.yaml, rules.yaml 경로 탐색"""
    candidates = [
        Path(__file__).parent / filename,           # 같은 디렉토리
        Path(sys.prefix) / 'credhound' / filename,  # pip install 경로
        Path('.') / filename,                        # 현재 디렉토리
    ]
    for p in candidates:
        if p.exists():
            return str(p)
    return filename


def init_scanner(args) -> CredentialScannerV2:
    config_path = args.config or _find_data_file('config.yaml')
    rules_path = args.rules or _find_data_file('rules.yaml')
    scanner = CredentialScannerV2(config_path=config_path, rules_path=rules_path)
    if args.no_entropy:
        scanner.entropy_analyzer.enabled = False
    if args.entropy:
        scanner.entropy_analyzer.enabled = True
    if args.baseline:
        from scanner import BaselineManager
        scanner.baseline_manager = BaselineManager(args.baseline)
    return scanner


def run_ci_mode(args):
    """CI/CD 파이프라인 모드"""
    scanner = init_scanner(args)
    scan_path = args.path or os.getcwd()

    scan_path = os.path.realpath(scan_path)
    if not os.path.exists(scan_path):
        print(f"❌ 경로가 존재하지 않습니다: {scan_path}", file=sys.stderr)
        sys.exit(EXIT_ERROR)

    try:
        if args.incremental:
            file_results, findings = scanner.scan_git_diff(scan_path)
        else:
            file_results, findings = scanner.scan(scan_path, parallel=args.parallel)
    except Exception as e:
        print(f"❌ 스캔 오류: {e}", file=sys.stderr)
        sys.exit(EXIT_ERROR)

    findings = scanner.filter_by_severity(findings, args.severity)

    if args.format == 'json':
        output = scanner.export_json(findings, file_results, args.output, mask=not args.unmask)
        if not args.output:
            print(output)
    elif args.format == 'sarif':
        output = scanner.export_sarif(findings, args.output, mask=not args.unmask)
        if not args.output:
            print(output)
    elif args.format == 'html':
        auto_path = args.output or _auto_output_path('html')
        output = scanner.export_html(findings, file_results, auto_path, mask=not args.unmask)
        if not args.output:
            print(f"✓ HTML 리포트가 '{auto_path}'에 저장되었습니다.", file=sys.stderr)
    else:
        stats = scanner.get_stats()
        if args.group:
            groups = scanner.group_findings(findings)
            print(f"스캔 완료: {stats['files_scanned']}개 파일, {len(findings)}개 발견 ({len(groups)}개 고유 credential)")
            for text, g in groups.items():
                masked = Finding._mask_text(text) if not args.unmask else text
                print(f"  [{g['severity']}] {g['rule_name']}: {masked} ({len(g['locations'])}개 위치)")
        else:
            print(f"스캔 완료: {stats['files_scanned']}개 파일, {len(findings)}개 발견")
            for f in findings:
                print(f"  [{f.severity}] {f.rule_name}: {f.file_path}:{f.line_number}")
        if args.output:
            save_results_text(file_results, findings, scan_path, args.output, mask=not args.unmask)

    exit_code = scanner.get_exit_code(findings, args.severity)
    sys.exit(exit_code)


def run_interactive_mode(args):
    """인터랙티브 모드 (기존 동작 유지)"""
    display_banner()

    scanner = init_scanner(args)

    # Pre-commit 훅 설치
    if args.install_hook:
        try:
            hook_path = scanner.generate_pre_commit_hook(args.path or '.')
            console.print(f"[green]✓ Pre-commit 훅이 설치되었습니다: {hook_path}[/green]")
        except Exception as e:
            console.print(f"[red]❌ 훅 설치 실패: {e}[/red]")
        return

    # 스캔 경로
    if args.path:
        scan_path = args.path
    else:
        default_path = os.path.expanduser('~')
        scan_path = Prompt.ask("[cyan]스캔할 경로를 입력하세요[/cyan]", default=default_path)

    scan_path = os.path.realpath(scan_path)
    if not os.path.exists(scan_path):
        console.print("[red]❌ 경로가 존재하지 않습니다.[/red]")
        sys.exit(EXIT_ERROR)

    console.print()
    if not args.path and not Confirm.ask(f"[yellow]'{scan_path}' 경로를 스캔하시겠습니까?[/yellow]", default=True):
        console.print("[dim]스캔이 취소되었습니다.[/dim]")
        sys.exit(EXIT_CLEAN)

    console.print()
    mode_str = "병렬" if args.parallel else "순차"
    console.print(f"[dim]💡 스캔 모드: {mode_str} | Ctrl+C로 중단[/dim]\n")

    try:
        with Progress(
            SpinnerColumn(), TextColumn("[progress.description]{task.description}"),
            BarColumn(), TaskProgressColumn(), console=console
        ) as progress:
            task = progress.add_task("[cyan]파일 목록 생성 중...", total=None)

            def update_progress(current, total):
                if total > 0:
                    progress.update(task, description=f"[cyan]스캔 중... ({current}/{total})", total=total, completed=current)

            if args.incremental:
                file_results, content_findings = scanner.scan_git_diff(scan_path, update_progress)
            else:
                file_results, content_findings = scanner.scan(scan_path, progress_callback=update_progress, parallel=args.parallel)

            progress.update(task, description="[green]✓ 스캔 완료", completed=True)
    except (KeyboardInterrupt, SystemExit):
        console.print("\n\n[yellow]⚠️  스캔이 사용자에 의해 중단되었습니다.[/yellow]")
        console.print(f"[dim]지금까지 스캔한 파일: {scanner.stats.get('files_scanned', 0)}개[/dim]")
        sys.exit(EXIT_CLEAN)

    # 심각도 필터링
    content_findings = scanner.filter_by_severity(content_findings, args.severity)

    console.print()

    # 출력 형식
    if args.format == 'json':
        output = scanner.export_json(content_findings, file_results, args.output, mask=not args.unmask)
        if not args.output:
            console.print(output)
        else:
            console.print(f"[green]✓ JSON 결과가 '{args.output}'에 저장되었습니다.[/green]")
    elif args.format == 'sarif':
        output = scanner.export_sarif(content_findings, args.output, mask=not args.unmask)
        if not args.output:
            console.print(output)
        else:
            console.print(f"[green]✓ SARIF 결과가 '{args.output}'에 저장되었습니다.[/green]")
    elif args.format == 'html':
        auto_path = args.output or _auto_output_path('html')
        output = scanner.export_html(content_findings, file_results, auto_path, mask=not args.unmask)
        if not args.output:
            console.print(f"[green]✓ HTML 리포트가 '{auto_path}'에 저장되었습니다.[/green]")
        else:
            console.print(f"[green]✓ HTML 리포트가 '{args.output}'에 저장되었습니다.[/green]")
    else:
        display_file_pattern_results(file_results)
        display_content_findings(content_findings)

    stats = scanner.get_stats()
    display_summary(file_results, content_findings, stats)

    # 실패한 파일
    if stats.get('files_failed', 0) > 0:
        failed_files = stats.get('failed_files_list', [])
        if failed_files:
            console.print("\n[yellow]⚠️  스캔 실패한 파일 (최대 10개):[/yellow]")
            for file_path, error in failed_files:
                console.print(f"  [dim]• {file_path}[/dim]")
                console.print(f"    [red]{error}[/red]")

    # 결과 저장
    if args.format == 'console' and not args.output:
        if Confirm.ask("\n[cyan]결과를 파일로 저장하시겠습니까?[/cyan]", default=True):
            results_dir = Path("scan_results")
            results_dir.mkdir(exist_ok=True)
            html_path = str(results_dir / _auto_output_path('html'))
            scanner.export_html(content_findings, file_results, html_path, mask=not args.unmask)
            console.print(f"[green]✓ HTML 리포트가 '{html_path}'에 저장되었습니다.[/green]")

    # Baseline 업데이트
    if args.update_baseline or (content_findings and Confirm.ask("\n[yellow]False positive를 baseline에 추가하시겠습니까?[/yellow]", default=False)):
        interactive_baseline_update(scanner, content_findings)

    # Exit code
    exit_code = scanner.get_exit_code(content_findings, args.severity)
    if exit_code == EXIT_FINDINGS:
        console.print(f"\n[red]⚠️  {len(content_findings)}개의 credential이 발견되었습니다. (exit code: {exit_code})[/red]")
    else:
        console.print(f"\n[green]✓ credential이 발견되지 않았습니다. (exit code: {exit_code})[/green]")

    sys.exit(exit_code)


def main():
    parser = build_parser()
    args = parser.parse_args()

    # 로깅 설정
    log_level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    )

    def handle_signal(signum, frame):
        console.print("\n[yellow]⚠️  신호를 받아 종료합니다.[/yellow]")
        sys.exit(EXIT_CLEAN)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    if args.ci:
        run_ci_mode(args)
    else:
        run_interactive_mode(args)


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, SystemExit) as e:
        if isinstance(e, SystemExit):
            sys.exit(e.code)
        console.print("\n\n[yellow]⚠️  프로그램이 사용자에 의해 중단되었습니다.[/yellow]")
        sys.exit(EXIT_CLEAN)
    except Exception as e:
        console.print(f"\n[red]❌ 오류 발생: {e}[/red]")
        import traceback
        traceback.print_exc()
        sys.exit(EXIT_ERROR)
