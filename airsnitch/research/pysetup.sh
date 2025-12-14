#!/bin/bash
# Copyright (c) 2022, Mathy Vanhoef <mathy.vanhoef@kuleuven.be>
#
# This code may be distributed under the terms of the BSD license.
# See README for more details.

# Start from a clean environment
rm -rf venv/

# Basic python3 virtual environment
python3 -m venv venv
source venv/bin/activate
pip install wheel
pip install -r requirements.txt

