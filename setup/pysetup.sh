#!/bin/bash

# Start clean environment.
rm -rf venv/

# Create Python3 virtual environment.
python3 -m venv venv
source venv/bin/activate

# Install requirements.
pip install wheel
pip install -r requirements.txt
