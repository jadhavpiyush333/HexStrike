from ..generic.command_scanner import CommandScanner
class HttpxScanner(CommandScanner):
    name = "httpx"; executable = "httpx"
    def build_args(self, target, profile): return ["-u", target, "-silent", "-status-code", "-title", "-tech-detect"]
