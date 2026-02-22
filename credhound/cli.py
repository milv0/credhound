"""credhound CLI 진입점 - yaml 파일 경로를 자동 설정"""
import os
import sys


def main():
    pkg_dir = os.path.dirname(os.path.abspath(__file__))
    config_path = os.path.join(pkg_dir, 'config.yaml')
    rules_path = os.path.join(pkg_dir, 'rules.yaml')

    # --config/--rules가 명시되지 않았으면 패키지 내부 yaml 사용
    if os.path.exists(config_path) and '--config' not in sys.argv:
        sys.argv.extend(['--config', config_path])
    if os.path.exists(rules_path) and '--rules' not in sys.argv:
        sys.argv.extend(['--rules', rules_path])

    from main_v2 import main as _main
    _main()


if __name__ == "__main__":
    main()
