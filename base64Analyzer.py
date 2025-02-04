import base64
import math
import requests
import hashlib

# API Keys (Replace with your own)
VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
ABUSEIPDB_API_KEY = "your_abuseipdb_api_key"

def the_entropy(data):
    if not data:
        return 0
    frequency = {byte: data.count(byte) for byte in set(data)}
    entropy = -sum((count / len(data)) * math.log2(count / len(data)) for count in frequency.values())
    return entropy

def analyze_length(byte_length):
    length_mapping = {
        4: "Possibly an IPv4 Address",
        6: "Possibly a MAC Address",
        8: "Possibly a DES Encryption Key",
        12: "Possibly an AES-GCM Nonce or ChaCha20 Nonce",
        16: "Possibly an AES-128 Key, AES IV, BLAKE2s-128, UUID, or IPv6 Address",
        20: "Possibly SHA-1, HMAC-SHA1, or DSA-1024 q value",
        24: "Possibly AES-192 Key, Tiger Hash, or Triple DES",
        28: "Possibly SHA-224 or SHA3-224 Hash",
        32: "Possibly AES-256 Key, SHA-256, SHA3-256, BLAKE2b-256, X25519, ECDSA P-256, HMAC-SHA256",
        40: "Possibly DSA-1024 Signature",
        48: "Possibly SHA-384, SHA3-384, BLAKE2b-384, ECDSA P-384, HMAC-SHA384",
        64: "Possibly SHA-512, SHA3-512, BLAKE2b-512, Whirlpool, ECDSA P-521, HMAC-SHA512",
        66: "Possibly ECDSA P-521 Private Key",
        128: "Possibly RSA-1024 Encrypted Block or DSA-1024 Public Key",
        132: "Possibly ECDSA P-521 Public Key",
        256: "Possibly RSA-2048 Encrypted Block, DSA-2048 Public Key",
        384: "Possibly RSA-3072 Encrypted Block",
        512: "Possibly RSA-4096 Encrypted Block",
    }

    if byte_length in length_mapping:
        return length_mapping[byte_length]
    if byte_length % 3 == 0:
        return "Possibly Base64-encoded Data"
    if byte_length % 2 == 0:
        return "Possibly Hex-encoded Data"
    return f"Unknown Data Type ({byte_length} bytes)"

def checking_virustotal(hash_value):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return "Hash Found in VirusTotal Database"
    return "Hash Not Found in VirusTotal"

def checking_abuseipdb(ip_address):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
    headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code == 200 and response.json()["data"]["abuseConfidenceScore"] > 50:
        return f"IP {ip_address} has a high abuse confidence score!"
    return f"IP {ip_address} is clean."

def decode_and_analyze(encoded_data):
    try:
        decoded_bytes = base64.b64decode(encoded_data)
        byte_length = len(decoded_bytes)
        entropy = the_entropy(decoded_bytes)

        print(f"Decoded Length: {byte_length} bytes")
        print(f"Decoded Hex: {decoded_bytes.hex()}")
        print(f"Data Type Analysis: {analyze_length(byte_length)}")
        print(f"Entropy Score: {entropy:.4f} (Higher entropy suggests encrypted data)")

        # Check for known malware hashes
        sha256_hash = hashlib.sha256(decoded_bytes).hexdigest()
        print(f"Checking VirusTotal for SHA-256 Hash: {sha256_hash}")
        print(checking_virustotal(sha256_hash))

        # Check if the decoded value is an IP address and look it up
        if byte_length == 4:
            ip_address = ".".join(str(b) for b in decoded_bytes)
            print(f"Checking AbuseIPDB for IP Address: {ip_address}")
            print(checking_abuseipdb(ip_address))

    except Exception as e:
        print(f"Error: Invalid Base64 input. {e}")

encoded_data = input("Enter the Base64-encoded string: ")
decode_and_analyze(encoded_data)
