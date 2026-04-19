#!/usr/bin/env python3
"""Minimal RADIUS server for testing Mikrotik HotSpot authentication."""

import hashlib
import hmac
import socket
import struct

SECRET = b"secret"
VALID_USER = b"admin"
VALID_PASS = b"p@ssw0rd"

ATTR_NAMES = {
    1: "User-Name", 2: "User-Password", 4: "NAS-IP-Address",
    5: "NAS-Port", 6: "Service-Type", 31: "Calling-Station-Id",
    32: "NAS-Identifier", 61: "NAS-Port-Type", 80: "Message-Authenticator",
}


def decrypt_user_password(encrypted, req_auth, secret):
    result = b""
    prev = req_auth
    for i in range(0, len(encrypted), 16):
        chunk = encrypted[i : i + 16]
        key = hashlib.md5(secret + prev).digest()
        decrypted = bytes(a ^ b for a, b in zip(chunk, key))
        result += decrypted
        prev = chunk
    return result.rstrip(b"\x00")


def parse_attributes(data):
    attrs = {}
    i = 0
    while i < len(data):
        attr_type = data[i]
        attr_len = data[i + 1]
        attr_value = data[i + 2 : i + attr_len]
        attrs[attr_type] = attr_value
        i += attr_len
    return attrs


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", 1812))
    print("[+] RADIUS test server listening on 0.0.0.0:1812")

    while True:
        data, addr = sock.recvfrom(4096)
        code, ident, length = struct.unpack("!BBH", data[:4])
        req_auth = data[4:20]
        attrs = parse_attributes(data[20:length])

        # Log all attributes
        print(f"\n[i] Request from {addr} (code={code}, id={ident}, len={length})")
        for attr_type, attr_value in sorted(attrs.items()):
            name = ATTR_NAMES.get(attr_type, f"Unknown-{attr_type}")
            if attr_type == 2:
                display = f"<encrypted {len(attr_value)} bytes>"
            elif attr_type == 80:
                display = f"<{len(attr_value)} bytes>"
            else:
                try:
                    display = attr_value.decode()
                except Exception:
                    display = attr_value.hex()
            print(f"    {name} ({attr_type}): {display}")

        user_name = attrs.get(1, b"").decode()
        user_pass_enc = attrs.get(2, b"")
        user_pass = decrypt_user_password(user_pass_enc, req_auth, SECRET).decode()
        has_msg_auth = 80 in attrs

        print(f"[i] user={user_name} pass={user_pass} msg-auth={has_msg_auth}")

        if user_name == VALID_USER.decode() and user_pass == VALID_PASS.decode():
            resp_code = 2  # Access-Accept
            print(f"[+] Access-Accept")
        else:
            resp_code = 3  # Access-Reject
            print(f"[-] Access-Reject")

        # Build response WITH Message-Authenticator (attr 80)
        # Message-Authenticator = HMAC-MD5 of entire response packet
        msg_auth_placeholder = struct.pack("BB", 80, 18) + b"\x00" * 16
        resp_attrs = msg_auth_placeholder
        resp_length = 20 + len(resp_attrs)

        # Step 1: Build packet with RequestAuth and zeroed Message-Authenticator
        pkt_for_hmac = struct.pack("!BBH", resp_code, ident, resp_length)
        pkt_for_hmac += req_auth
        pkt_for_hmac += resp_attrs

        # Step 2: Compute HMAC-MD5 for Message-Authenticator
        msg_auth_value = hmac.new(SECRET, pkt_for_hmac, hashlib.md5).digest()
        resp_attrs_final = struct.pack("BB", 80, 18) + msg_auth_value

        # Step 3: Compute Response Authenticator
        # MD5(Code + ID + Length + RequestAuth + Attributes + Secret)
        auth_input = struct.pack("!BBH", resp_code, ident, resp_length)
        auth_input += req_auth
        auth_input += resp_attrs_final
        auth_input += SECRET
        resp_auth = hashlib.md5(auth_input).digest()

        # Final response
        resp = struct.pack("!BBH", resp_code, ident, resp_length)
        resp += resp_auth
        resp += resp_attrs_final

        sock.sendto(resp, addr)
        print(f"[+] Sent {len(resp)} bytes (with Message-Authenticator)")


if __name__ == "__main__":
    main()
