from scanner import CredentialScannerV2

s = CredentialScannerV2(config_path='credhound/config.yaml', rules_path='credhound/rules.yaml')
for rule in s.rules:
    for p in rule.value_patterns:
        prefix = p['prefix']
        status = f'prefix={prefix!r}' if prefix else 'no prefix (full regex)'
        print(f'{rule.id:25s} | {p["name"]:35s} | {status}')