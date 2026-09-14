from ..generic.command_scanner import CommandScanner
class WhatWebScanner(CommandScanner):
    name = "whatweb"; executable = "whatweb"
    def build_args(self, target, profile): return ["--log-verbose=-", target]
