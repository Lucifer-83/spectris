"""Runtime presence check for the external system tools the backend shells out
to. These CANNOT be bundled into the app (they are root-level system packages
tied to WiFi hardware/kernel), so we detect what's installed and let the UI
tell the operator exactly what to `apt install`.
"""

import shutil
from dataclasses import dataclass

# tool -> which capability breaks without it (+ the apt package that provides it)
REQUIRED_TOOLS: dict[str, tuple[str, str]] = {
    "iw": ("adapter / monitor mode", "iw"),
    "ip": ("adapter setup", "iproute2"),
    "nmcli": ("free the adapter from NetworkManager so monitor mode sticks", "network-manager"),
    "airodump-ng": ("scanning", "aircrack-ng"),
    "aireplay-ng": ("deauth", "aircrack-ng"),
    "hcxdumptool": ("handshake/PMKID capture", "hcxdumptool"),
    "hcxpcapngtool": ("hashcat conversion", "hcxtools"),
    "hashcat": ("offline handshake crack (GPU/CPU)", "hashcat"),
    "aircrack-ng": ("offline handshake crack (CPU fallback)", "aircrack-ng"),
    "reaver": ("WPS Pixie Dust / PIN", "reaver"),
    "pixiewps": ("WPS Pixie Dust offline compute (reaver/bully call it)", "pixiewps"),
    "wash": ("WPS detection scan", "reaver"),
    "bully": ("WPS (alternative engine)", "bully"),
    "hostapd": ("evil twin AP", "hostapd"),
    "dnsmasq": ("evil twin DHCP/DNS", "dnsmasq"),
    "iptables": ("captive portal redirect", "iptables"),
}

@dataclass
class ToolInfo:
    name: str
    present: bool
    path: str | None
    capability: str
    package: str


def tools_status() -> dict:
    tools = []
    missing_packages: set[str] = set()
    for name, (capability, package) in REQUIRED_TOOLS.items():
        path = shutil.which(name)
        if path is None:
            missing_packages.add(package)
        tools.append(
            ToolInfo(name=name, present=path is not None, path=path, capability=capability, package=package)
        )
    packages = sorted(missing_packages)
    return {
        "tools": [t.__dict__ for t in tools],
        "all_present": not packages,
        "missing_packages": packages,
        "install_hint": ("sudo apt install -y " + " ".join(packages)) if packages else None,
    }
