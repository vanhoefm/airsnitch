#!/bin/bash
set -e

cd dependencies
./build.sh
cd ../setup
./pysetup.sh