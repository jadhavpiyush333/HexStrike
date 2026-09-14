"""Configurable ScanX adapter.

Use SCANX_BIN for the executable and optionally SCANX_ARGS for arguments.
SCANX_ARGS is parsed without a shell and may contain the literal {target}
placeholder, allowing the adapter to support different ScanX distributions.
Example: SCANX_ARGS='scan {target}'
"""
import os, shlex
from ..generic.command_scanner import CommandScanner

class ScanXScanner(CommandScanner):
    name='scanx'

    @property
    def executable(self): return os.getenv('SCANX_BIN','scanx')

    def build_args(self,target,profile):
        template=os.getenv('SCANX_ARGS')
        if template:
            parts=shlex.split(template)
            if '{target}' in parts:
                return [target if p=='{target}' else p for p in parts]
            return [*parts,target]
        return [target]
