from ..generic.command_scanner import CommandScanner
class NucleiScanner(CommandScanner):
    name = "nuclei"; executable = "nuclei"
    def build_args(self, target, profile): return ["-u", target, "-severity", "info,low,medium,high,critical", "-jsonl"]
