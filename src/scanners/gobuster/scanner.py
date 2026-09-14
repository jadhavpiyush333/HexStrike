import os
from ..generic.command_scanner import CommandScanner
class GobusterScanner(CommandScanner):
    name="gobuster"; executable="gobuster"
    def build_args(self,target,profile):
        wordlist=os.getenv("HEXSTRIKE_WEB_WORDLIST")
        if not wordlist: raise ValueError("HEXSTRIKE_WEB_WORDLIST is not configured")
        return ["dir","-u",target,"-w",wordlist,"--no-error"]
