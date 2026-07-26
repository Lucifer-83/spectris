"""Wraps Linux wireless tooling (iw) to detect adapters and toggle monitor mode.

Intended to run inside the WSL2 distro the USB adapter is passed through to
via usbipd-win. All state-changing calls require root privileges.
"""

import os
import re
import subprocess
from dataclasses import dataclass, field


class AdapterCommandError(Exception):
    pass


def _run(cmd: list[str]) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except FileNotFoundError as exc:
        raise AdapterCommandError(f"Required tool not found: {cmd[0]}") from exc
    if proc.returncode != 0:
        raise AdapterCommandError(f"{' '.join(cmd)} failed: {proc.stderr.strip()}")
    return proc.stdout


def _run_optional(cmd: list[str]) -> None:
    """Best-effort: run a command but never fail the operation if it errors — used
    for nmcli, which is absent on hosts that don't run NetworkManager."""
    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.SubprocessError):
        pass


@dataclass
class WirelessInterface:
    name: str
    phy: str
    mode: str  # "managed" | "monitor" | "unknown"
    supports_monitor: bool
    # Everything below is best-effort identity info so the operator can tell one
    # adapter from another when several dongles are plugged in at once.
    driver: str = ""            # kernel driver: iwlwifi, rt2800usb, 88XXau, ...
    bus: str = "unknown"        # "usb" | "pci" | "unknown"
    connection: str = "unknown"  # "external" (USB dongle) | "internal" (built-in PCI)
    chipset: str = ""           # human model string, e.g. "Ralink 802.11n (148f:5370)"
    bands: list[str] = field(default_factory=list)  # ["2.4 GHz", "5 GHz"]


_IFACE_BLOCK_RE = re.compile(
    r"phy#(?P<phy>\d+).*?Interface (?P<name>\S+).*?type (?P<mode>\S+)",
    re.DOTALL,
)

# a frequency line in `iw phy <phy> info`, e.g.  "* 2412.0 MHz [1] (20.0 dBm)"
_FREQ_RE = re.compile(r"\*\s*(\d+(?:\.\d+)?)\s*MHz")

# PCI vendor id -> friendly name, so an internal card reads as "Intel (iwlwifi)"
# rather than just a raw driver. Only the common wireless vendors.
_PCI_VENDORS = {
    "8086": "Intel",
    "10ec": "Realtek",
    "168c": "Qualcomm Atheros",
    "14e4": "Broadcom",
    "1814": "Ralink/MediaTek",
    "17cb": "Qualcomm",
    "1a56": "Killer",
}


def list_interfaces() -> list[WirelessInterface]:
    output = _run(["iw", "dev"])
    interfaces = []
    for block in re.split(r"(?=phy#)", output):
        match = _IFACE_BLOCK_RE.search(block)
        if not match:
            continue
        phy = f"phy{match.group('phy')}"
        name = match.group("name")
        supports_monitor, bands = phy_capabilities(phy)
        dev = _device_info(name)
        interfaces.append(
            WirelessInterface(
                name=name,
                phy=phy,
                mode=match.group("mode"),
                supports_monitor=supports_monitor,
                driver=dev["driver"],
                bus=dev["bus"],
                connection=dev["connection"],
                chipset=dev["chipset"],
                bands=bands,
            )
        )
    return interfaces


def _phy_info_text(phy: str) -> str:
    try:
        return _run(["iw", phy, "info"])
    except AdapterCommandError:
        return ""


def phy_capabilities(phy: str) -> tuple[bool, list[str]]:
    """(supports_monitor, bands) from a single `iw <phy> info` call — cheaper than
    querying twice, and bands tells the operator 2.4 GHz vs 5 GHz support."""
    info = _phy_info_text(phy)
    return ("monitor" in info.lower(), _bands_from_phy_info(info))


def phy_supports_monitor(phy: str) -> bool:
    return phy_capabilities(phy)[0]


def _bands_from_phy_info(info: str) -> list[str]:
    """Classify every advertised frequency into a band label. Robust across
    single/dual/tri-band cards — we read the actual frequencies rather than
    trusting the "Band N:" numbering."""
    seen: dict[str, int] = {}
    order = {"2.4 GHz": 0, "5 GHz": 1, "6 GHz": 2}
    for m in _FREQ_RE.finditer(info):
        mhz = float(m.group(1))
        if 2300 <= mhz < 2600:
            label = "2.4 GHz"
        elif 4900 <= mhz < 5925:
            label = "5 GHz"
        elif 5925 <= mhz < 7200:
            label = "6 GHz"
        else:
            continue
        seen.setdefault(label, order[label])
    return sorted(seen, key=lambda b: seen[b])


def _read_sysfs(path: str) -> str:
    try:
        with open(path) as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _usb_model(dev_path: str) -> str:
    """Walk up the resolved sysfs device path to the USB device node (the one
    that carries idVendor) and build a readable model string from its strings."""
    node = dev_path
    for _ in range(6):
        if os.path.exists(os.path.join(node, "idVendor")):
            vid = _read_sysfs(os.path.join(node, "idVendor"))
            pid = _read_sysfs(os.path.join(node, "idProduct"))
            manufacturer = _read_sysfs(os.path.join(node, "manufacturer"))
            product = _read_sysfs(os.path.join(node, "product"))
            name = " ".join(p for p in (manufacturer, product) if p).strip()
            ids = f"{vid}:{pid}" if vid and pid else ""
            if name and ids:
                return f"{name} ({ids})"
            return name or ids
        parent = os.path.dirname(node)
        if parent in ("", "/", node):
            break
        node = parent
    return ""


def _device_info(interface: str) -> dict:
    """Best-effort adapter identity from sysfs alone (no lsusb/lspci needed, so it
    works in the frozen binary and the container). Linux-only; on anything else
    every field comes back empty/"unknown"."""
    info = {"driver": "", "bus": "unknown", "connection": "unknown", "chipset": ""}
    base = f"/sys/class/net/{interface}/device"
    if not os.path.exists(base):
        return info

    driver_link = os.path.join(base, "driver")
    if os.path.islink(driver_link):
        info["driver"] = os.path.basename(os.path.realpath(driver_link))

    dev_path = os.path.realpath(base)
    if "/usb" in dev_path:
        info["bus"] = "usb"
        info["connection"] = "external"
        info["chipset"] = _usb_model(dev_path)
    elif "/pci" in dev_path:
        info["bus"] = "pci"
        info["connection"] = "internal"
        vendor_id = _read_sysfs(os.path.join(base, "vendor")).removeprefix("0x").lower()
        vendor = _PCI_VENDORS.get(vendor_id, "")
        if vendor and info["driver"]:
            info["chipset"] = f"{vendor} ({info['driver']})"
        else:
            info["chipset"] = vendor or info["driver"]
    return info


def interface_mode(interface: str) -> str | None:
    """Current mode ("managed"/"monitor"/...) of one interface, or None if it's
    not present. Used to verify a mode switch stuck and to gate the scan."""
    for iface in list_interfaces():
        if iface.name == interface:
            return iface.mode
    return None


def is_internal(interface: str) -> bool:
    """True for a built-in (PCI) adapter — the host's likely internet card. We
    refuse to disrupt these (monitor mode / NM kill) because doing so drops the
    system's Wi-Fi and can leave NetworkManager in a bad state."""
    return _device_info(interface).get("connection") == "internal"


def set_monitor_mode(interface: str, enable: bool) -> str:
    """Enable/disable monitor mode on `interface` (link down → change type → up).
    Requires root, hence `sudo`.

    The usual reason monitor mode "won't stick" is NetworkManager: it owns the
    interface and keeps yanking it back to managed to (re)connect a saved network,
    so airodump then sees a managed interface and silently returns nothing. So when
    enabling we first tell NM to stop managing THIS ONE interface
    (`nmcli dev set <iface> managed no`) — surgical, so the host's other WiFi
    (internet) stays up, unlike `airmon-ng check kill`. When disabling we hand it
    back. Either way we then VERIFY the mode actually took and fail loudly if not,
    instead of reporting a success that silently reverted."""
    target_mode = "monitor" if enable else "managed"
    # NOTE: we do NOT block the internal adapter — with only one external card the
    # operator legitimately needs the built-in one as a second adapter (e.g. evil
    # twin needs two). Monitor mode on it will drop the host's Wi-Fi/internet; the
    # UI warns about that. We only avoid the *destructive* global NM kill (see
    # kill_interfering_processes).
    if enable:
        # stop NM reclaiming the interface before we switch it
        _run_optional(["sudo", "-n", "nmcli", "dev", "set", interface, "managed", "no"])
    _run(["sudo", "-n", "ip", "link", "set", interface, "down"])
    _run(["sudo", "-n", "iw", interface, "set", "type", target_mode])
    _run(["sudo", "-n", "ip", "link", "set", interface, "up"])
    if not enable:
        # give the interface back to NetworkManager so normal WiFi resumes
        _run_optional(["sudo", "-n", "nmcli", "dev", "set", interface, "managed", "yes"])

    actual = interface_mode(interface)
    if actual is not None and actual != target_mode:
        raise AdapterCommandError(
            f"{interface} is still '{actual}' after switching to {target_mode} — "
            "NetworkManager is likely reclaiming it. Click 'Kill interfering processes' "
            "in Setup, then enable monitor mode again."
        )
    return actual or target_mode


def reset_all_to_managed() -> list[str]:
    """Revert EVERY monitor-mode interface back to managed and hand it back to
    NetworkManager — so the host's normal Wi-Fi works again after the tool closes.
    Best-effort, never raises. Returns the interfaces it reverted."""
    reverted = []
    try:
        interfaces = list_interfaces()
    except AdapterCommandError:
        return reverted
    for iface in interfaces:
        if iface.mode == "monitor":
            try:
                set_monitor_mode(iface.name, False)
                reverted.append(iface.name)
            except AdapterCommandError:
                pass
    return reverted


def kill_interfering_processes(interface: str) -> str:
    """Free ONE adapter from NetworkManager so it stops fighting monitor mode —
    the usual cause of reaver/aireplay deauth+timeout loops.

    This is SURGICAL: it only tells NM to stop managing `interface`
    (`nmcli dev set <iface> managed no` + `disconnect`). It deliberately does NOT
    run `airmon-ng check kill`, which kills NetworkManager globally — that makes
    the host's built-in Wi-Fi vanish from the network menu and can wedge the
    driver. Works on any adapter (releasing the internal one drops that card's
    internet, but it's reversible — `managed yes` on disable restores it)."""
    _run_optional(["sudo", "-n", "nmcli", "dev", "set", interface, "managed", "no"])
    _run_optional(["sudo", "-n", "nmcli", "dev", "disconnect", interface])
    warn = " (this is your internal/internet card — it drops that Wi-Fi until you disable monitor)" if is_internal(interface) else ""
    return f"{interface} released from NetworkManager (managed=no){warn}. Other adapters untouched."


def adapter_status() -> dict:
    interfaces = list_interfaces()
    return {
        "interfaces": [iface.__dict__ for iface in interfaces],
        "monitor_capable_found": any(i.supports_monitor for i in interfaces),
    }
