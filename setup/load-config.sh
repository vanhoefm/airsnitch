#!/bin/bash
set -e

# Usage and example.
if [[ $# -eq 0 ]] ; then
    echo "Usage; $0 configuration [configuration-supplicant]"
    echo "Example; $0 wpa3-personal-pmf"
    exit 1
fi

# Take in command line arguments.
HOSTAPD_CONF="hostapd-$1.conf"
SUPPLICANT_CONF=${2:-$1} # Use $1 as a default.
SUPPLICANT_CONF="supplicant-$SUPPLICANT_CONF.conf"

# Sanity checks.
if [ ! -f $HOSTAPD_CONF ]; then
    echo "File $HOSTAPD_CONF not found!"
    exit 1
fi
if [ ! -f $SUPPLICANT_CONF ]; then
    echo "File $SUPPLICANT_CONF not found!"
    exit 1
fi

# Remove any symbolic links.
rm supplicant.conf
rm hostapd.conf

# Create the symbolic links.
ln -s $HOSTAPD_CONF hostapd.conf
ln -s $SUPPLICANT_CONF supplicant.conf

# Debug messages.
echo "Loaded $HOSTAPD_CONF"
echo "Loaded $SUPPLICANT_CONF"

