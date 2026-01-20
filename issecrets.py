import os, sys, json, time, getpass, copy, base58, requests, ctypes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from hashlib import sha256, pbkdf2_hmac
from termcolor import colored
from datetime import datetime
from pathlib import Path

with open("config.json", "r") as r:
  config = json.load(r)
with open("formats/secret.json", "r") as r:
  secret = json.load(r)
secret = copy.deepcopy(secret)

password = None

def clear():
  os.system('cls' if os.name == 'nt' else 'clear')

def hash():
  status = None
  try:
    test = requests.get(config["metadata"]["external"])
    test.raise_for_status()
    if bool(test.json()):
      status = 1
    else:
      status = 0
  except:
    status = 2

  if status == 1:
    connection = requests.get(config["metadata"]["external"]).json()
    exStatic = (connection["metadata"]["version"].to_bytes((connection["metadata"]["version"].bit_length() + 7) // 8, "big") + connection["metadata"]["developer"].encode("utf-8") + connection["metadata"]["github"].encode("utf-8") + connection["metadata"]["external"].encode("utf-8") + connection["metadata"]["created"].to_bytes((connection["metadata"]["created"].bit_length() + 7) // 8, "big"))
    inStatic = (config["metadata"]["version"].to_bytes((config["metadata"]["version"].bit_length() + 7) // 8, "big") + config["metadata"]["developer"].encode("utf-8") + config["metadata"]["github"].encode("utf-8") + config["metadata"]["external"].encode("utf-8") + config["metadata"]["created"].to_bytes((config["metadata"]["created"].bit_length() + 7) // 8, "big"))

    if config["metadata"]["verifyHash"] == connection["metadata"]["verifyHash"] and sha256(inStatic).hexdigest() == sha256(exStatic).hexdigest():
      config["tampered"] = False
    else:
      config["tampered"] = True
  else:
    config["tampered"] = 404
  with open("config.json", "w") as w:
    json.dump(config, w, indent=4)

def lock():
  global password
  hash()
  if config["aes"]["passHash"] == None:
    print(colored("""
██╗░██████╗░██████╗███████╗░█████╗░██████╗░███████╗████████╗░██████╗
██║██╔════╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██╔════╝
██║╚█████╗░╚█████╗░█████╗░░██║░░╚═╝██████╔╝█████╗░░░░░██║░░░╚█████╗░
██║░╚═══██╗░╚═══██╗██╔══╝░░██║░░██╗██╔══██╗██╔══╝░░░░░██║░░░░╚═══██╗
██║██████╔╝██████╔╝███████╗╚█████╔╝██║░░██║███████╗░░░██║░░░██████╔╝
╚═╝╚═════╝░╚═════╝░╚══════╝░╚════╝░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░╚═════╝░""", "red", attrs=["bold"]))
    print(colored("\n---\n", "white", attrs=["bold"]))
    if config["tampered"]:
      print(colored("Variant: Tampered", "red", attrs=["bold"]))
    elif config["tampered"] == False:
      print(colored("Variant: Original", "green", attrs=["bold"]))
    else:
      print(colored("Variant: Unknown", "yellow", attrs=["bold"]))
    print(colored("\n---\n", "white", attrs=["bold"]))
    print(colored("""\n
█▀ █▀▀ █▀▀ █░█ █▀█ █ ▀█▀ █▄█
▄█ ██▄ █▄▄ █▄█ █▀▄ █ ░█░ ░█░\n\n""", "white", attrs=["bold"]))
    password = ctypes.create_string_buffer(getpass.getpass(colored("Create A New Password: ", "white", attrs=["bold"])).encode("utf-8"))
    if len(password.decode("utf-8")) <= 8:
      print(colored("Password - Insecure", "red", attrs=["bold"]))
      time.sleep(1)
      clear()
    elif len(password.decode("utf-8")) > 8 and len(password.decode("utf-8")) <= 11:
      print(colored("Password - Moderate", "yellow", attrs=["bold"]))
      time.sleep(1)
      clear()
    elif len(password.decode("utf-8")) > 11:
      print(colored("Password - Secure", "green", attrs=["bold"]))
      time.sleep(1)
      clear()
    salt = os.urandom(config["aes"]["salt"])
    config["aes"]["passHash"] = f"{salt.hex()}{(pbkdf2_hmac("sha256", password, salt, config["aes"]["iterations"], dklen=32)).hex()}"
    with open("config.json", "w") as w:
      json.dump(config, w, indent=4)
    menu()
  else:
    while True:
      print(colored("""
  ██╗░██████╗░██████╗███████╗░█████╗░██████╗░███████╗████████╗░██████╗
  ██║██╔════╝██╔════╝██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝██╔════╝
  ██║╚█████╗░╚█████╗░█████╗░░██║░░╚═╝██████╔╝█████╗░░░░░██║░░░╚█████╗░
  ██║░╚═══██╗░╚═══██╗██╔══╝░░██║░░██╗██╔══██╗██╔══╝░░░░░██║░░░░╚═══██╗
  ██║██████╔╝██████╔╝███████╗╚█████╔╝██║░░██║███████╗░░░██║░░░██████╔╝
  ╚═╝╚═════╝░╚═════╝░╚══════╝░╚════╝░╚═╝░░╚═╝╚══════╝░░░╚═╝░░░╚═════╝░""", "red", attrs=["bold"]))
      print(colored("\n---\n", "white", attrs=["bold"]))
      if config["tampered"]:
        print(colored("Variant: Tampered", "red", attrs=["bold"]))
      elif config["tampered"] == False:
        print(colored("Variant: Original", "green", attrs=["bold"]))
      else:
        print(colored("Variant: Unknown", "yellow", attrs=["bold"]))
      print(colored("\n---\n", "white", attrs=["bold"]))
      password = ctypes.create_string_buffer(getpass.getpass(colored("Enter your Password: ", "white", attrs=["bold"])).encode("utf-8"))
      if pbkdf2_hmac("sha256", password, bytes.fromhex(config["aes"]["passHash"][:(config["aes"]["salt"] * 2)]), config["aes"]["iterations"], dklen=32).hex() == config["aes"]["passHash"][(config["aes"]["salt"] * 2):]:
        print(colored("Password Correct!", "green", attrs=["bold"]))
        time.sleep(1)
        clear()
        menu()
        break
      else:
        print(colored("Wrong Password!", "red", attrs=["bold"]))
        time.sleep(1)
        clear() 

def secrets(title, sensitive, password):
  os.makedirs(config["aes"]["directory"], exist_ok=True)
  secret["version"] = config["metadata"]["version"]
  secret["timestamp"] = round(time.time())
  secret["id"] = base58.b58encode(os.urandom(config["aes"]["id"])).decode()
  secret["metadata"]["hashing"] = config["aes"]["hashing"]
  secret["metadata"]["encryption"] = config["aes"]["encryption"]

  salt = os.urandom(config["aes"]["salt"])
  passHash = ctypes.create_string_buffer(pbkdf2_hmac("sha256", password, salt, config["aes"]["iterations"], dklen=32))
  aes = AESGCM(passHash)
  
  nonce = os.urandom(config["aes"]["nonce"])
  secret["body"]["title"] = salt.hex() + nonce.hex() + aes.encrypt(nonce, title.encode("utf-8"), None).hex()
  nonce = os.urandom(config["aes"]["nonce"])
  secret["body"]["secret"] = salt.hex() + nonce.hex() + aes.encrypt(nonce, sensitive.encode("utf-8"), None).hex()
  with open(f"{config["aes"]["directory"]}/{sha256(secret["id"].encode("utf-8")).hexdigest()[:10]}.json", "w") as w:
    json.dump(secret, w, indent=4)
  ctypes.memset(ctypes.addressof(passHash), 0, len(passHash))

def reveal(sensitive, password):
  salt = bytes.fromhex(sensitive[:(config["aes"]["salt"] * 2)])
  nonce = bytes.fromhex(sensitive[(config["aes"]["salt"] * 2):(config["aes"]["salt"] * 2 + config["aes"]["nonce"] * 2)])
  ciphertext = bytes.fromhex(sensitive[(config["aes"]["nonce"] * 2 + config["aes"]["salt"] * 2):])

  passHash = ctypes.create_string_buffer(pbkdf2_hmac("sha256", password, salt, config["aes"]["iterations"], dklen=32))
  aes = AESGCM(passHash)
  plaintext = aes.decrypt(nonce, ciphertext, None).decode("utf-8")
  ctypes.memset(ctypes.addressof(passHash), 0, len(passHash))
  return plaintext

def view():
  print(colored("""
█░█ █ █▀▀ █░█░█
▀▄▀ █ ██▄ ▀▄▀▄▀\n""", "white", attrs=["bold"]))
  SECRETS = []
  for secs in Path(config["aes"]["directory"]).rglob("*.json"):
    with secs.open("r") as r:
      secrets = json.load(r)
    SECRETS.append(secrets)
  for index, id in enumerate(SECRETS, start=1):
    print(colored(f"\nIndex: {index}\nID: {id.get("id")}\n", "white", attrs=["bold"]))
  print(colored("---", "white", attrs=["bold"]))

def menu():
  while True:
    print(colored("""
  █▀▄▀█ █▀▀ █▄░█ █░█
  █░▀░█ ██▄ █░▀█ █▄█\n\n""", "white", attrs=["bold"]))
    print(colored("[N] - New Secret\n", "green", attrs=["bold"]))
    print(colored("[V] - View Secrets\n", "yellow", attrs=["bold"]))
    print(colored("[R] - Remove Secret\n", "red", attrs=["bold"]))
    print(colored("[X] - Exit\n", "red", attrs=["bold"]))
    option = input(colored(">> ", "white", attrs=["bold"]))
    if option.upper() in ["X", "[X]"]:
      clear()
      ctypes.memset(ctypes.addressof(password), 0, len(password))
      sys.exit(0)
    elif option.upper() in ["N", "[N]"]:
      clear()
      print(colored("Create New Secret:\n\n", "white", attrs=["bold"]))
      title = input(colored("Title of Secret: ", "white", attrs=["bold"]))
      sensitive = input(colored("Secret: ", "white", attrs=["bold"]))
      secrets(title, sensitive, password)
      clear()
      print(colored("Successfully Created Secret!", "green", attrs=["bold"]))
      time.sleep(1)
      clear()
    elif option.upper() in ["V", "[V]"]:
      clear()
      print(colored("View Secrets:\n\n", "white", attrs=["bold"]))
      view()
      print("\n\n")
      select = input(colored("View Secret By ID: ", "white", attrs=["bold"]))
      if Path(f"{config["aes"]["directory"]}/{sha256(select.encode("utf-8")).hexdigest()[:10]}.json").is_file():
        with open(f"{config["aes"]["directory"]}/{sha256(select.encode("utf-8")).hexdigest()[:10]}.json", "r") as r:
          confidential = json.load(r)
        clear()
        print(colored(f"ID: {confidential["id"]}\nTimestamp: {datetime.fromtimestamp(confidential["timestamp"])}\nTitle: {reveal(confidential["body"]["title"], password)}\nSecret: {reveal(confidential["body"]["secret"], password)}\n\n", "white", attrs=["bold"]))
        action = input(colored("(L to Leave): ", "white", attrs=["bold"]))
        if action.upper() == "L":
          clear()
        else:
          clear()
      else:
        clear()
        print(colored("Error - Nonexistent Secret!", "red", attrs=["bold"]))
        time.sleep(1)
        clear()
    elif option.upper() in ["R", "[R]"]:
      clear()
      print(colored("Remove Secrets:\n\n", "white", attrs=["bold"]))
      view()
      print("\n\n")
      select = input(colored("Remove Secret By ID: ", "white", attrs=["bold"]))
      if Path(f"{config["aes"]["directory"]}/{sha256(select.encode("utf-8")).hexdigest()[:10]}.json").is_file():
        os.remove(f"{config["aes"]["directory"]}/{sha256(select.encode("utf-8")).hexdigest()[:10]}.json")
        clear()
        print(colored(f"Removed Secret!\nChecksum: {sha256(select.encode("utf-8")).hexdigest()[:10]}", "green", attrs=["bold"]))
        time.sleep(1)
        clear()
      else:
        clear()
        print(colored("Error - Nonexistent Secret!", "red", attrs=["bold"]))
        time.sleep(1)
        clear()
    else:
      clear()
      print(colored("Error - Function Dosen't Exist!", "red", attrs=["bold"]))
      time.sleep(1)
      clear()

lock()
