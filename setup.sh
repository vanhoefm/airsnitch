#!/bin/bash
set -e

cd dependencies
git submodule add https://github.com/vanhoefm/libwifi/
./build.sh
cd ../setup
./pysetup.sh