# EtherExists
This codebase builds upon the public repository [macstealer](https://github.com/vanhoefm/macstealer/).

# Usage
As our tool is an extension of macstealer, you can follow macstealer's [README](https://github.com/vanhoefm/macstealer/blob/main/README.md) to install and use it. 
In the extended [macstealer.py](https://github.com/zhouxinan/EtherExists/blob/main/macstealer/research/macstealer.py), we add several new options:

`--check-gtk-shared`: Checking if second given interface receives the same GTK from BSSID.

`--c2c-port-steal`: Second interface to test port stealing (downlink).

`--c2c-port-steal-uplink`: Second interface to test port stealing (uplink).
