   
Secure Remote Administration Tool — GUI Server  
Requires: Python 3.8+  
Optional: pip install cryptography   (for automatic TLS cert generation)  
  
On first run the server creates:  
  rat_server.crt / rat_server.key  — self-signed TLS certificate (10 years)  
  rat_psk.txt                      — pre-shared key for agent HMAC authentication  
  rat_fingerprint.txt              — cert SHA-256 fingerprint to paste into agent.ps1  
  rat_audit.log                    — rotating audit log of all connections & commands  
  
Usage:  
  python server.py                              # 0.0.0.0:4444, auto TLS + PSK  
  python server.py --port 5555  
  python server.py --psk "MySecret"            # explicit pre-shared key  
  python server.py --allow 10.0.0.0/8          # restrict to subnet (repeatable)  
  python server.py --cert my.crt --key my.key  # use existing certificate  
  python server.py --no-tls                    # disable TLS (NOT recommended)  

  FOR EDUCATIONAL PURPOSES ONLY, DONT BE THAT IDIOT.  
