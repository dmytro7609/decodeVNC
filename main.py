import d3des as d

import binascii


def vnc_crypt(vncpass, decrypt=True):
    if decrypt:
        try:
            passpadd = binascii.unhexlify(vncpass)  # Convert hex to bytes
        except binascii.Error as e:
            if "Odd-length string" in str(e):
                print(f'WARN: {str(e)}. Chopping last char off... "{vncpass[:-1]}"')
                passpadd = binascii.unhexlify(vncpass[:-1])
            else:
                raise
        print(f"Decryption input (hex decoded): {passpadd}")
    else:
        passpadd = (vncpass + "\x00" * 8)[:8].encode('utf-8')  # Pad and encode to bytes
        print(f"Encryption input (padded): {passpadd}")

    strkey = bytes(d.vnckey)  # Convert key to bytes
    print(f"Using DES key: {strkey}")
    key = d.deskey(strkey, decrypt)
    print(f"Generated DES key: {key}")

    crypted = d.desfunc(passpadd, key)
    print(f"DES function output: {crypted}")

    if decrypt:
        try:
            # Remove trailing null bytes
            result = crypted.rstrip(b'\x00').decode('utf-8')  # Strip padding and decode to a string
            print(f"Decrypted result: {result}")
            return result
        except UnicodeDecodeError:
            print("ERROR: Decrypted output is not valid UTF-8.")
            return crypted  # Return raw bytes for debugging
    else:
        result = binascii.hexlify(crypted).decode('utf-8')  # Return hex string
        print(f"Encrypted result (hex): {result}")
        return result


get_hex = input('Enter the HEX code: ')
vnc_crypt(get_hex)

