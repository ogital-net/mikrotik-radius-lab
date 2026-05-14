# RadSec (RFC 6614) setup for the hotspot lab.
# Prereq: ca.crt, client.crt, client.key uploaded to /file by run.sh.

/certificate import file-name=ca.crt     name=radsec-ca     passphrase=""
/certificate import file-name=client.crt name=radsec-client passphrase=""
/certificate import file-name=client.key                    passphrase=""

# Shared secret is the literal "radsec" per RFC 6614 §2.2; mTLS is the
# trust boundary. Transport is TCP/2083 — no auth/acct port split.
/radius add service=hotspot address=10.0.2.2 protocol=radsec certificate=radsec-client secret=radsec
