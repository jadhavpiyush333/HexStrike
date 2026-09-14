from __future__ import annotations
from pathlib import Path
import os
import yaml

class RuntimeConfig:
    def __init__(self, base_path: Path):
        self.base_path = Path(base_path)
        self.config_dir = self.base_path / 'config'

    def _load(self, name: str) -> dict:
        p = self.config_dir / name
        if not p.exists():
            return {}
        data = yaml.safe_load(p.read_text(encoding='utf-8')) or {}
        if not isinstance(data, dict):
            raise ValueError(f'{name} must contain a YAML mapping')
        return data

    def settings(self): return self._load('settings.yaml')
    def security(self): return self._load('security.yaml')
    def scan_profiles(self): return self._load('scan_profiles.yaml')
    def scanners(self): return self._load('scanners.yaml')

    def validate(self):
        errors=[]
        required=('settings.yaml','security.yaml','scan_profiles.yaml','scanners.yaml','targets.yaml')
        for name in required:
            if not (self.config_dir/name).exists(): errors.append(f'Missing config/{name}')
        try:
            s=self.security(); profiles=s.get('profiles',{})
            if not isinstance(profiles,dict) or not profiles: errors.append('No scan profiles configured')
            for name,p in profiles.items():
                if not isinstance(p,dict): errors.append(f'Profile {name}: must be a mapping'); continue
                timeout=int(p.get('timeout_seconds',0)); concurrency=int(p.get('max_concurrent',0))
                if not 1 <= timeout <= 600: errors.append(f'Profile {name}: timeout_seconds must be 1..600')
                if not 1 <= concurrency <= 10: errors.append(f'Profile {name}: max_concurrent must be 1..10')
            configured=set(self.scan_profiles().get('scan_profiles',{}))
            if configured and configured != set(profiles):
                errors.append('config/scan_profiles.yaml and config/security.yaml define different profile sets')
            scanners=self.scanners()
            if not isinstance(scanners,dict): errors.append('config/scanners.yaml must be a mapping')
            wl=os.getenv('HEXSTRIKE_WEB_WORDLIST')
            if wl and not Path(wl).is_file(): errors.append('HEXSTRIKE_WEB_WORDLIST points to a missing file')
            if not isinstance(self.settings().get('app',{}),dict): errors.append('settings.yaml: app must be a mapping')
        except (ValueError, TypeError, yaml.YAMLError) as exc:
            errors.append(f'Configuration parse/validation error: {exc}')
        return errors
