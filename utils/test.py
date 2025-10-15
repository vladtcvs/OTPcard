from smartcard.System import readers
from smartcard.util import toHexString

import hmac
import hashlib

def get_reader():
    r = readers()
    if not r:
        raise Exception("No smartcard readers found")

    reader = r[1]
    return reader
    
def get_connection(reader):
    print(f"Using reader: {reader}")

    # Connect to the card
    connection = reader.createConnection()
    connection.connect()
    return connection


def send_apdu(CLA, INS, P1, P2, Le, payload, connection):
    Lc = len(payload)
    if Lc == 0:
        Lc = 1
        payload = [0x00]

    apdu = [CLA, INS, P1, P2, Lc] + payload
    if Le > 0:
        apdu += [Le]

    # Send APDU
    print(f"Sending APDU: {toHexString(apdu)}")
    response, sw1, sw2 = connection.transmit(apdu)

    print(f"Response: {toHexString(response)}")
    print(f"Status Word: {hex(sw1)} {hex(sw2)}")

    return response, sw1, sw2


def calculate_hmac_sha1(key_bytes: bytes, message_bytes: bytes) -> str:
    # Create HMAC-SHA1 digest
    hmac_obj = hmac.new(key_bytes, message_bytes, hashlib.sha1)
    
    # Return hexadecimal representation
    return list(bytes.fromhex(hmac_obj.hexdigest()))

if __name__ == "__main__":
    reader = get_reader()
    connection = get_connection(reader)

#    AID = [0xA0, 0x00, 0x00, 0x00, 0x02, 0x02, 0x01, 0x01]
    AID = [0xA0, 0x00, 0x00, 0x00, 0x02, 0x02, 0x01, 0x01]

    CLA = 0x00
    INS = 0xA4
    P1 = 0x04
    P2 = 0x00
    Le = 0
    send_apdu(CLA, INS, P1, P2, Le, AID, connection)

    args = []
    CLA = 0x00
    INS = 0x08 # GetINFO
    P1 = 0x00
    P2 = 0x00
    Le = 2
    response, sw1, sw2 = send_apdu(CLA, INS, P1, P2, Le, args, connection)

    pin = b'123456'
    secret_id = 0
    args = [len(pin)] + list(pin) + [secret_id]
    CLA = 0x00
    INS = 0x02 # Get secret status
    P1 = 0x00
    P2 = 0x00
    Le = 0
    response, sw1, sw2 = send_apdu(CLA, INS, P1, P2, Le, args, connection)

    secret = b'SECRET'
    name = b'NAME'
    method = 1
    if False:
        args = [len(pin)] + list(pin) + [secret_id] + [len(secret)] + list(secret) + [len(name)] + list(name) + [method]
        CLA = 0x00
        INS = 0x03 # Save secret
        P1 = 0x00
        P2 = 0x00
        Le = 0
        response, sw1, sw2 = send_apdu(CLA, INS, P1, P2, Le, args, connection)
    
    challenge = b'CHALLENGE'
    args = [len(pin)] + list(pin) + [secret_id] + [len(challenge)] + list(challenge)
    CLA = 0x00
    INS = 0x01 # Generate HMAC
    P1 = 0x00
    P2 = 0x00
    Le = 0
    response, sw1, sw2 = send_apdu(CLA, INS, P1, P2, Le, args, connection)


    expected = calculate_hmac_sha1(secret, challenge)
    print(f"Received: {toHexString(response)}")
    print(f"Expected: {toHexString(expected)}")
