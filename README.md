# Threat-Intelligence-Analyzer

## Overview
A python script designed for threat intelligence researchers and digital forensic analysts to quickly classify encoded data and uncover potential security threats. 
It decodes Base64 encoded data and analyzes its cryptographic or network related type. Includes entropy analysis, malware hash database checking, and threat intelligence API integration to determine whether the decoded data is a known malware hash from threat intelligence databases.

**Decodes Base64-encoded data into its raw byte representation**

**Identifies known cryptographic hashes (SHA, MD5, RIPEMD, BLAKE2, etc.)**

**Detects encryption keys (AES, RSA, DES, ECDSA, Ed25519, etc.)**

**Recognizes networking identifiers (MAC, IPv4, IPv6, UUIDs, etc.)**

**Classifies Base64 & Hex-encoded formats based on byte structure**

**Helps in malware analysis, forensic investigations, and threat intelligence research**

**Entropy Analysis: Detects if the data is random (encryption) or structured (hashing)**

**Automated Malware Hash Lookup: Checks against known malware databases (VirusTotal, AbuseIPDB)**

## USE CASES
### THREAT INTELLIGENCE & MALWARE ANALYSIS
**Analyze Base64-encoded payloads in phishing emails and command-and-control (C2) traffic**

**Identify encoded cryptographic keys used in malware strains**

**Determine if a hash is linked to password dumps from data breaches**

### Digital Forensics & Incident Response (DFIR)
**Detect Base64-encoded commands used in PowerShell and fileless malware attacks**

**Extract and classify digital evidence from encoded logs or network captures**

**Verify integrity and match cryptographic hashes in forensic investigations**

### Network Security & Red Teaming
**Identify key material in intercepted network traffic**

**Extract and analyze encryption keys in captured packets**

**Classify authentication tokens and signatures in web applications**

### How It Works
Accepts a Base64-encoded input string

Decodes it into raw bytes

Prints the hex representation for forensic analysis

Matches exact lengths to known cryptographic algorithms

If no match is found, detects if data is likely Base64 or Hex-encoded

Returns a detailed classification of the data
### Optional But Recommended

**Sign up for VirusTotal API Key**

**Sign up for AbuseIPDB API Key**

### Install dependencies using

  ```bash
  pip install requests
  ```

**EXAMPLE USAGE AND OUTPUT**

  ```bash
  Enter the Base64-encoded string: nG/JCRYUiXrodZd+1v4hWw==
  Decoded Length: 16 bytes
  Decoded Hex: 9c6fc9091614897ae875977ed6fe215b
  Data Type Analysis: Possibly an AES-128 Key, AES IV, BLAKE2s-128, UUID, or IPv6 Address
  Entropy Score: 4.0000 (Higher entropy suggests encrypted data)
  Checking VirusTotal for SHA-256 Hash: 267a36c59037b2786196b7acae36402f84a42a89dab629753412c0ec49874dcf
  Hash Not Found in VirusTotal
  ```

