import shutil
import subprocess
import xml.etree.ElementTree as ET

from ..base import ScanResult, Scanner


class NmapScanner(Scanner):
    name = "nmap"

    def health(self) -> bool:
        return shutil.which("nmap") is not None

    def scan(self, target: str, profile: str, timeout: int = 120) -> ScanResult:
        if not self.health():
            return ScanResult(self.name, target, "unavailable", error="nmap executable not found")
        profile_args = {"safe": ["-sT", "-sV", "--version-light"], "soc_evidence": ["-sT", "-sV", "--version-light"], "aggressive": ["-A", "-T4"]}.get(profile, ["-sT", "-sV", "--version-light"])
        args = [*profile_args, "-oX", "-", target]
        try:
            proc = subprocess.run(["nmap", *args], capture_output=True, text=True, timeout=timeout, check=False)
        except subprocess.TimeoutExpired:
            return ScanResult(self.name, target, "timeout", error="scan timed out")
        findings = []
        if proc.stdout:
            try:
                root = ET.fromstring(proc.stdout)
                for host in root.findall("host"):
                    address = host.find("address")
                    for port in host.findall("./ports/port"):
                        state = port.find("state")
                        service = port.find("service")
                        if state is not None and state.attrib.get("state") == "open":
                            findings.append({
                                "host": address.attrib.get("addr") if address is not None else target,
                                "port": int(port.attrib["portid"]),
                                "protocol": port.attrib.get("protocol"),
                                "state": "open",
                                "service": service.attrib.get("name") if service is not None else None,
                                "product": service.attrib.get("product") if service is not None else None,
                                "version": service.attrib.get("version") if service is not None else None,
                            })
            except ET.ParseError:
                pass
        return ScanResult(self.name, target, "completed" if proc.returncode == 0 else "failed", findings, proc.stdout, proc.stderr or None)
