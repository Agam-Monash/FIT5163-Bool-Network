# FIT5163-Bool-Network
Implementation of Bool Network in https://eprint.iacr.org/2022/1290.pdf

## Setup
1: py -m venv .venv

2: .\venv\Scripts\activate.ps1 (or .bat depending on the system)

3: pip install ecdsa

4: pip install cryptography

5: choose parameters in main.py and run


## notes on files

bool_net folder contains all modules and their implementations:

- DKG
- Ring VRF
- Commitee Handover
- Threshold Signing

curve.py contains shared helper functions such as polynomial evaluaters, reconstructors, and other modular arithmetic functions

board represents the blockchain message channel

epoch is the manager for each commitee and epoch cycle

main contains a simulated run of 3 epoch cycles