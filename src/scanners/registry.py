from .nmap.scanner import NmapScanner
from .scanx.adapter import ScanXScanner
from .nikto.scanner import NiktoScanner
from .nuclei.scanner import NucleiScanner
from .whatweb.scanner import WhatWebScanner
from .httpx.scanner import HttpxScanner
from .gobuster.scanner import GobusterScanner
from .ffuf.scanner import FfufScanner
from .amass.scanner import AmassScanner
from .subfinder.scanner import SubfinderScanner

def build_registry():
    scanners = [NmapScanner(), ScanXScanner(), NiktoScanner(), NucleiScanner(), WhatWebScanner(), HttpxScanner(), GobusterScanner(), FfufScanner(), AmassScanner(), SubfinderScanner()]
    return {s.name: s for s in scanners}
