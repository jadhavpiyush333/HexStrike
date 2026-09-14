from ..generic.command_scanner import CommandScanner
class AmassScanner(CommandScanner):
    name = "amass"; executable = "amass"
    def build_args(self, target, profile): return ["enum", "-passive", "-d", target]
