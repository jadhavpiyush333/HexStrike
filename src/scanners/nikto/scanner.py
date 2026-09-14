from ..generic.command_scanner import CommandScanner
class NiktoScanner(CommandScanner):
    name = "nikto"; executable = "nikto"
    def build_args(self, target, profile): return ["-host", target, "-Display", "V"]
