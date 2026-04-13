# test_shadow.py
# This file imports a typosquatted package but does not list it in any manifest.
# SusCheck should detect this via 'Shadow Dependency Detection'.

import os
import sys
import requesrs # Typosquat of 'requests'

def main():
    print("Testing shadow imports...")
    requesrs.get("https://google.com")

if __name__ == "__main__":
    main()
