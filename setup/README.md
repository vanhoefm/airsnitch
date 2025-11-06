# Setup

The framework can be used both on a native Linux installation and in a virtual machine.

## Installation

Depending on your system, pre-requirements to install (for example, for `hostap`) often are the following:
```
apt-get update
apt-get install git make gcc python3-venv net-tools
apt-get install libdbus-1-dev libnl-3-dev libnl-genl-3-dev libnl-route-3-dev libssl-dev 
```

You can now install the framework using:
```
cd ../dependencies
./build.sh
cd ../setup
./pysetup.sh
```

This will first compile our customized version of `hostap` that extends the control interface.
It also creates a virtual python environment to manage all dependencies for the framework and installs all [requirements](requirements.txt) in this virtual python environment.


## Libwifi

The [libwifi](https://github.com/vanhoefm/libwifi) library is tracked as a git submodule and you will have to manually pull it using:
```
git submodule init
git submodule update
```

## Usage

After executing the above, see the [usage guide](../docs/USAGE.md) on how to use the framework.

