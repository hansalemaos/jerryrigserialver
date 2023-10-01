import subprocess
from base64 import urlsafe_b64encode
from datetime import datetime
from cryptography.fernet import Fernet
import hashlib
import requests
import math
import os
from time import time
import dill
import sys

keyba = None
ver = sys.version_info
out = sys.stdout.flush
import base64
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding


def encrypt_with_public_key(message, public_key):
    public_key = serialization.load_pem_public_key(public_key)

    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    ciphertext = base64.encodebytes(ciphertext)
    return ciphertext


def decrypt_with_private_key(message, private_key):
    private_key = serialization.load_pem_private_key(private_key, password=None)
    plaintext = private_key.decrypt(
        base64.decodebytes(message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext.decode()


def hex_to_str(x):
    return "".join([chr(int(x[i : i + 2], 16)) for i in range(0, len(x), 2)])


def str_to_hex(s):
    return "".join([("0" + hex(ord(c)).split("x")[1])[-2:] for c in s])


def create_license(message):

    key = base64.decodebytes(keyba)
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode("utf-8"))
    encrypted_key = base64.b64encode(ciphertext + tag).decode("utf-8")
    decoded_key = base64.b64decode(encrypted_key)
    ciphertext = decoded_key[:-16]
    tag = decoded_key[-16:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=cipher.nonce)
    original_message = cipher.decrypt(ciphertext).decode("utf-8")
    return ciphertext, tag, original_message, encrypted_key, key, cipher


def check(encrypted_key, cipher, ciphertext):
    key = base64.decodebytes(keyba)

    decoded_key = base64.b64decode(encrypted_key)
    ciphertext = decoded_key[:-16]
    cipher = AES.new(key, AES.MODE_EAX, nonce=cipher.nonce)
    original_message = cipher.decrypt(ciphertext).decode("utf-8")
    return original_message


def get_k(myprod):
    ciphertext, tag, original_message, encrypted_key, key, cipher = create_license(
        myprod
    )
    a = (
        dill.dumps(
            [
                ciphertext,
                tag,
                original_message,
                encrypted_key,
                key,
            ]
        ),
        cipher,
    )
    serialnumber, b = a
    baaa = base64.b64encode(serialnumber).decode("utf-8")
    return str_to_hex(baaa)


def get_infos_from_serial(serialnumberk):
    serialnumber = base64.b64decode(hex_to_str(serialnumberk).encode())
    myprod = dill.loads(serialnumber)[2]
    ciphertext, tag, original_message, encrypted_key, key, cipher = create_license(
        myprod
    )
    orgmessage = check(encrypted_key, cipher, ciphertext)
    p, d, ts, otherinformation = original_message.split("####")
    d = int(d)
    ts = int(ts)
    duid = {}
    duid["ciphertext"] = ciphertext
    duid["tag"] = tag
    duid["original_message"] = original_message
    duid["encrypted_key"] = encrypted_key
    duid["key"] = key
    duid["cipher"] = cipher
    duid["orgmessage"] = orgmessage
    duid["days"] = d
    duid["timestamp"] = ts
    duid["daysleft"] = math.ceil(((duid["timestamp"] + d * 86400) - time()) / 86400)
    duid["product"] = p
    duid["otherinformation"] = otherinformation
    duid["cipher"] = duid["cipher"].__dict__["nonce"]
    return duid


def get_key_from_uuid(rev=False):

    uuid = get_machine_id()
    if rev:
        uuid = uuid[::-1]
    key = hashlib.sha256(uuid).digest()
    key = urlsafe_b64encode(key)
    padding = b"=" * (32 - len(key))
    key += padding
    cipher = Fernet(key)
    return cipher


def encrypt(cipher, message):
    encrypted_message = cipher.encrypt(message)
    return encrypted_message


def decrypt(cipher, encrypted_message):
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message


def download_message_and_decrypt(link, password=None):
    # if password:
    #     headers2 = {
    #         "X-Decrypt-Password": password,
    #     }
    #     response2 = requests.get(link, headers=headers2)
    # else:
    response2 = requests.get(link)
    return response2


def get_machine_id():
    return sorted(
        subprocess.run(
            [
                os.path.normpath(
                    os.path.join(
                        os.path.dirname(os.environ.get("comspec")), "wbem", "wmic.exe"
                    )
                ),
                "csproduct",
                "get",
                "UUID",
            ],
            capture_output=True,
        ).stdout.splitlines(),
        key=lambda x: len(x),
    )[-1].strip()


def open_serial_number_file(filepath, decy):
    with open(filepath, mode="rb") as f:
        data = f.read()
    data = decrypt(decy, data)
    return data.strip()


class Cryptor:
    # https://stackoverflow.com/a/75713952/15096247
    def __init__(self, key):
        self.SECRET_KEY = str(key).encode("utf-8")
        self.BLOCK_SIZE = 32
        self.CIPHER = AES.new(self.SECRET_KEY, AES.MODE_ECB)

    def encrypt(self, text):
        text = str(text).encode("utf-8")
        return base64.b64encode(self.CIPHER.encrypt(pad(text, self.BLOCK_SIZE))).decode(
            "utf-8"
        )

    def decrypt(self, encoded_text):
        self.CIPHER = AES.new(self.SECRET_KEY, AES.MODE_ECB)
        return unpad(
            self.CIPHER.decrypt(base64.b64decode(encoded_text)), self.BLOCK_SIZE
        ).decode("utf-8")


def get_internet_datetime(time_zone: str = "etc/utc"):
    timeapi_url = "https://www.timeapi.io/api/Time/current/zone"
    headers = {
        "Accept": "application/json",
    }
    params = {"timeZone": time_zone}

    try:
        request = requests.get(timeapi_url, headers=headers, params=params)
        r_dict = request.json()
        dt = datetime(
            year=r_dict["year"],
            month=r_dict["month"],
            day=r_dict["day"],
            hour=r_dict["hour"],
            minute=r_dict["minute"],
            second=r_dict["seconds"],
            microsecond=r_dict["milliSeconds"] * 1000,
        ).timestamp()
    except Exception:
        try:
            t = requests.get("http://just-the-time.appspot.com/").content
            dt = int(datetime.fromisoformat(t.decode("utf-8").strip()).timestamp())
        except Exception as fe:
            return 0
    return dt


def check_serial(
    hardcodedpasswort_transfer,
    hardcodedpasswort_url,
    serialnumber,
    notvalidanymore=f"The license you're using is not valid anymore. It expired %s day[s] ago",
    stillvalid=f"The license you're using is valid for %s more day[s].",
    serialusedanotherpc="The license has been used on another PC",
):
    global keyba
    signature_hex = serialnumber[-32:]
    serialnumber = serialnumber[:-32]
    byx = bytes.fromhex(signature_hex)
    keyba = base64.encodebytes(byx)

    cipher2 = get_key_from_uuid()
    cipher2rev = get_key_from_uuid(rev=True)

    serialnumber = hex_to_str(serialnumber)

    cryptor = Cryptor(hardcodedpasswort_url)
    decryptedurl = cryptor.decrypt(serialnumber)

    serialfile = os.path.normpath(os.path.join(os.path.dirname(__file__), "reglic.bin"))
    try:
        with requests.get(url=decryptedurl, timeout=30) as response:
            cont = response.content
            if response.status_code == 200:
                with open(serialfile, mode="wb") as f:
                    f.write(encrypt(cipher2rev, cont))

    except Exception as fe:
        pass

    serialnumberk = open_serial_number_file(filepath=serialfile, decy=cipher2rev)

    duid = get_infos_from_serial(serialnumberk)
    link, filehash, privkeyent, *_ = duid["otherinformation"].split("ÇÇÇ")
    licensefileonhdd = os.path.normpath(
        os.path.join(os.path.dirname(__file__), "mylicense_reglic.bin")
    )
    try:
        res = download_message_and_decrypt(link, password=hardcodedpasswort_transfer)
        if res.status_code == 200:
            with open(licensefileonhdd, mode="wb") as f:
                cryptkey = res.content
                randomcode = os.urandom(16).decode("utf-8", "ignore")
                enc = encrypt_with_public_key(randomcode.encode(), privkeyent.encode())
                dec = decrypt_with_private_key(enc, cryptkey)
                if randomcode == dec:
                    maid = get_machine_id()
                    duid["hardwareid"] = encrypt(cipher2rev, maid)
                    duid["sno"] = serialnumberk
                mess2 = dill.dumps(duid)
                emcry = encrypt(cipher2, mess2)
                f.write(emcry)

    except Exception:
        pass

    with open(licensefileonhdd, mode="rb") as f:
        datax = f.read()

    duid2 = dill.loads(decrypt(cipher2, datax))

    isonrightmachine = get_machine_id() == decrypt(cipher2rev, duid2["hardwareid"])
    if isonrightmachine:
        if duid2["timestamp"] - duid["timestamp"] == 0:
            for k in set(duid.keys()) & set(duid2.keys()):
                if k not in ["sno"]:
                    continue
                if duid[k] != duid2[k]:
                    return False, None, None, None, None
            else:
                timen = get_internet_datetime(time_zone="etc/utc")
                durationoflic = duid["days"]
                product = duid["product"]
                otherinfos = duid["otherinformation"].split("ÇÇÇ")[3:]
                dli = duid["timestamp"] + (duid["days"] * 86400) - timen
                daysleft = math.ceil(dli / 86400)
                if daysleft < 0:
                    if "%d" in notvalidanymore:
                        print(notvalidanymore % abs(daysleft))
                    else:
                        print(notvalidanymore)
                    return False, daysleft, durationoflic, product, otherinfos

                else:
                    if "%d" in stillvalid:
                        print(stillvalid % abs(daysleft))
                    else:
                        print(stillvalid)

                    return True, daysleft, durationoflic, product, otherinfos

    else:
        print(serialusedanotherpc)
        return False, None, None, None, None


