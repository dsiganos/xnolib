#!/bin/sh -l

set -e

pwd
ls -l

python3 -m pip install -r requirements.txt
python3 block.py
