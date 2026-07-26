#!/bin/bash
# Spectris — package post-remove hook (deb & rpm).
# Revoke the passwordless-sudo grant added by postinstall.sh so nothing is left
# behind on uninstall.
set -e
rm -f /etc/sudoers.d/spectris
exit 0
