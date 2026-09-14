import os
from ..generic.command_scanner import CommandScanner
class FfufScanner(CommandScanner):
    name="ffuf"; executable="ffuf"
    def build_args(self,target,profile):
        wordlist=os.getenv("HEXSTRIKE_WEB_WORDLIST")
        if not wordlist: raise ValueError("HEXSTRIKE_WEB_WORDLIST is not configured")
        return ["-u",target.rstrip("/")+"/FUZZ","-w",wordlist,"-s"]
