# Binary Ninja Security Policy

## Supported Versions

Please note that Binary Ninja supports the [current development branch](https://github.com/Vector35/binaryninja-api) and the [latest stable](https://github.com/Vector35/binaryninja-api/tree/master) for security issues.

Bug reports are typically only supported the latest development branch.

## Reporting a Vulnerability

Please contact security@vector35.com (using the below [GPG key](#gpg-key) if desired) if you find a security vulnerability in Binary Ninja including (but not limited to):

 - code execution merely by opening an executable file for analysis
 - https://binary.ninja/ or any subdomains
 - vulnerabilities in the master update server or update process (unencrypted update files is NOT a security vulnerability as files are additionally verified with a signing key)
 - vulnerabilities in https://cloud.binary.ninja/
 - any vulnerability that leaks sensitive customer information (customer email addresses, serial numbers. etc)
  
Note that this does NOT include:
 - mis-use of APIs by plugins (they're already running native code)
 - malicious code being executed by the debugger
 
  ## GPG Key
 
 For encrypted communications, please use the following public key:
``` 
 -----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBF6yNEIBCACzsuZfFdqDX7KJh+6R4u9wo/jix5SevIPVdLZXtf/pI+TXNNwV
x3NPGnoM3V2pSsmT3qlj4C0RtZORw6AhJmqcpe/ze6mwqyzej4zABowdlCD/hGpn
lmvpjbY/TWjftGZEt/KUammCIl0wh8ma2LdwOq5VAkpS5bFzYDpgKegW7pFaIZsT
gt6ITNQ3cgH/A7dn5eluLE84pkoHsJhSTM7wlhCXGywqJi/QUrRWZI5kOgCs4rfn
CW9SsZ5ADAhucHK/MZKSwHLIzHozM2EMmXTNnqmcabRea61QLz6YubUmrZ0NC26M
6rp3oeEUHB4OThQlmnISCzDgGe0XBXmEwQJnABEBAAG0U1ZlY3RvciAzNSBTZWN1
cml0eSAoRm9yIHJlcG9ydGluZyBzZWN1cml0eSB2dWxuZXJhYmlsaXRpZXMpIDxz
ZWN1cml0eUB2ZWN0b3IzNS5jb20+iQFUBBMBCAA+FiEEJjxVVmC43ACIAISHsUtI
bZKwCHgFAl6yNEICGwMFCQlmAYAFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQ
sUtIbZKwCHgn3Qf/bBncAc6P0/jJe2DeUHeOYJqze3IFRIL/Ab5fGmCKD8uH70WJ
s9vjwmpjqot/RQV2vcgOc2M30vgnllbljCv+LOEJxOAIzyEb63vN4PMjyo3lp+R/
tm2GlBCI2W4PhP+20zuXQ1qUCG/idId/roq89niXkDjxz/j4C6rM9wda5tfthUVB
wx3sTtHUXTnS5q7ZX0xV9AcmLPZ/ITGbaiiSO4IwcZC4CvVbegDM6rTTa0R4gyXT
YQPPBm/D2h7BcycRISFrTGtUgLgYKCPlaHFCmJ/lZ0VKBL0DwVhN1rkfL2gdn5As
Qleig7/qZGenBQP4csLun1k1eZJLby8HSeK8d7kBDQResjRCAQgA9E/2N5ohRX+q
Nxg8Yhnm4jJrPZEJ7ELwzXq1TkRoYLl40KpwSC57ICs6LHVX8lfe1pATuRJDbzlI
vlJwM7GUUiIQhzjoeUt6efg+B3DJUc3jUps1NCoAdQQz/NZyr7jpnOu3WLHWMW/0
2kdc8P6C5IdX2P+FpwA70bDi3GZsmfOveIPZXcZhZKa28UzTrdlbkFyoyi8RSxFh
o6OMHOayvaaLsa9uTDx5XtyXvqtqso6wPdHZlU74/HWwT2EEuDnG0hrU7CYD2jCm
XqsOzjivD3CLla1JGNC+ULlH8CDNchLwzrqBKjxvBVZ+qJsB5A9IFAi/p188HEI6
ghk9Vt1EUQARAQABiQE8BBgBCAAmFiEEJjxVVmC43ACIAISHsUtIbZKwCHgFAl6y
NEICGwwFCQlmAYAACgkQsUtIbZKwCHiskgf/cf8tTpdA4AAZ12h8GVulukJOD2bi
y/fLAhVMXnNpHLZCsTYvcGC9XjKTRmcC1yD1hYAtOZEHv/JY/CgzOMmRxlivu+9X
/Pn1K6TndYDGlmMcA4HkOm92pCKMU35QJ+R5iDaRtWADWzbOtXZZMtk/e4hpX/PY
H8DSQ4tkaQtGuP7BBWKz1X9cUx7Z3ZXP9FMEmzAOvPNstSx34iWdum0ebxZfz322
wEFK0ugXSniCfMGNI2vKwUn2FX/L9IVpLWlyIVrF2xhSjENRzlDCNNKh+6uuXJ3e
AIR2AC/xrsBYuf8bQl4CyWhQiOEfhgpbbSfFMOeC4ww50pALu67WUk1QAw==
=KAef
-----END PGP PUBLIC KEY BLOCK-----
```
