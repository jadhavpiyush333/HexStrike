from ..generic.command_scanner import CommandScanner
class SubfinderScanner(CommandScanner):
    name = "subfinder"; executable = "subfinder"
    def build_args(self, target, profile): return ["-d", target, "-silent"]
