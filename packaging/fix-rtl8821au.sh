#!/usr/bin/env bash
# Fix RTL8811AU/RTL8812AU/RTL8821AU USB adapters (TP-Link Archer T2U / T2U Plus,
# many "AC600/AC1200" dongles) stuck on the IN-KERNEL rtw88 driver, which sets
# monitor mode but CAPTURES NOTHING and can't inject (scan/capture/deauth silently
# fail). Installs + BUILDS the out-of-tree 88XXau driver (real monitor + injection).
#
# It VERIFIES the build. If 88XXau builds, it blacklists the in-kernel drivers so
# the dongle binds 88XXau. If the build FAILS (e.g. kernel too new for the driver),
# it REVERTS the blacklist so your adapter isn't left driver-less, and tells you.
#
#   sudo bash packaging/fix-rtl8821au.sh      # then UNPLUG + REPLUG the adapter
#
set -u
BLACKLIST=/etc/modprobe.d/blacklist-rtw88-8821au.conf

if [ "$(id -u)" -ne 0 ]; then
  echo "Run me with sudo:  sudo bash packaging/fix-rtl8821au.sh" >&2
  exit 1
fi

KREL="$(uname -r)"
echo "[*] kernel: $KREL"

echo "[*] making sure kernel headers are present ..."
apt-get install -y "linux-headers-$KREL" 2>/dev/null || apt-get install -y linux-headers-amd64 2>/dev/null || true

echo "[*] installing the 88XXau driver source (realtek-rtl88xxau-dkms) ..."
apt-get install -y realtek-rtl88xxau-dkms || true

echo "[*] forcing the DKMS build for this kernel (this can take a minute) ..."
dkms autoinstall -k "$KREL" 2>&1 | tail -20 || true

# did it actually build + install?
if dkms status realtek-rtl88xxau 2>/dev/null | grep -q "installed" && modinfo 88XXau >/dev/null 2>&1; then
  echo "[+] 88XXau built OK — switching the dongle onto it."
  cat > "$BLACKLIST" <<'EOF'
# WiFi Pentest Toolkit: force RTL88xxAU dongles onto the 88XXau driver
# (real monitor + injection) instead of the in-kernel drivers.
blacklist rtw88_8821au
blacklist rtw88_8821cu
blacklist rtw88_8822bu
blacklist rtl8xxxu
EOF
  modprobe -r rtw88_8821au rtw88_8821cu rtl8xxxu 2>/dev/null || true
  depmod -a
  modprobe 88XXau 2>/dev/null || true
  echo
  echo "[+] DONE. Now UNPLUG and REPLUG the USB adapter, then check:"
  echo "      ls -l /sys/class/net/wlan*/device/driver   # should show 88XXau"
else
  echo "[!] 88XXau did NOT build for kernel $KREL (likely too new for this driver)."
  echo "[!] Reverting the blacklist so your adapter still gets its in-kernel driver back."
  rm -f "$BLACKLIST"
  depmod -a
  modprobe rtw88_8821au 2>/dev/null || modprobe rtl8xxxu 2>/dev/null || true
  echo
  echo "    UNPLUG + REPLUG the adapter — it will come back (as wlanX on rtw88)."
  echo "    BUT rtw88 can't really capture, so for scans/attacks use a"
  echo "    Ralink RT5370 (rt2800usb) or Atheros USB adapter — those work out of the box."
fi
