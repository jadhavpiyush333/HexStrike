"""Controlled MCP interface for HexStrike ScanX.

This server intentionally exposes named security tools rather than arbitrary shell execution.
Run only against targets explicitly present in config/targets.yaml.
"""
from mcp.server.fastmcp import FastMCP
from src.mcp.tools.scan_tools import scanner_health, scanx_scan, nmap_scan, scan_status, get_scan_results
from src.mcp.tools.analysis_tools import analyze_scan

mcp = FastMCP("HexStrike-ScanX")

@mcp.tool()
def scanner_health_tool() -> dict:
    """Return availability information for registered scanners."""
    return scanner_health()

@mcp.tool()
def scanx_scan_tool(target: str, profile: str = "safe") -> dict:
    """Run the controlled ScanX adapter against an authorized target."""
    return scanx_scan(target, profile)

@mcp.tool()
def nmap_scan_tool(target: str, profile: str = "safe") -> dict:
    """Run the controlled Nmap adapter against an authorized target."""
    return nmap_scan(target, profile)

@mcp.tool()
def scan_status_tool(scan_id: str) -> dict:
    """Retrieve a stored scan record."""
    return scan_status(scan_id)

@mcp.tool()
def get_scan_results_tool(scan_id: str) -> dict:
    """Retrieve normalized findings from a stored scan."""
    return get_scan_results(scan_id)

if __name__ == "__main__":
    mcp.run(transport="stdio")

@mcp.tool()
def analyze_scan_tool(scan_id: str) -> dict:
    """Analyze stored normalized findings without executing new commands."""
    return analyze_scan(scan_id)
