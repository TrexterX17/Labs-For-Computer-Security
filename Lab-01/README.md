# Lab 01: Classical and Modern Cryptography - Encryption Analysis & Attack Vectors

## 🎯 Lab Overview

This lab demonstrates comprehensive hands-on experience with both classical cryptanalysis and modern encryption systems. The project showcases practical attacks on weak encryption implementations, comparative analysis of encryption modes, and exploitation of cryptographic vulnerabilities in real-world scenarios.

**Security Focus Areas:**
- Frequency analysis attacks on substitution ciphers
- Symmetric encryption implementation (AES, DES, Blowfish)
- Block cipher mode vulnerabilities (ECB vs CBC)
- Padding oracle attacks
- Error propagation in cipher modes
- IV reuse attacks and cryptographic oracle exploitation

---

## 🛠️ Technical Environment

**Tools & Technologies:**
- **Operating System:** Linux (Ubuntu-based environment)
- **Cryptographic Libraries:** OpenSSL 1.1+
- **Programming Languages:** Python 3.x, Bash scripting
- **Analysis Tools:** 
  - Custom frequency analysis scripts
  - Hex editors (xxd, hexdump, bless)
  - Image viewers (eog)
- **Network Tools:** Netcat (nc) for oracle communication

**Lab Setup:**
- Pre-configured Docker containers for isolated cryptographic operations
- Oracle server for IV reuse attack simulation (10.9.0.80:3000)

---

## 📋 Tasks Completed

### Task 1: Frequency Analysis - Breaking Classical Ciphers

**Objective:** Decrypt a monoalphabetic substitution cipher using frequency analysis techniques.

**Methodology:**
1. **Initial Analysis:**
   - Executed `freq.py` to generate frequency distribution of letters and n-grams in ciphertext
   - Compared ciphertext letter frequencies with standard English language frequencies
   - Identified high-frequency letters likely representing common English letters (E, T, A, O, I, N)

2. **Iterative Decryption:**
   - Used `tr` (translate) command for character substitution mapping
   - Applied trial-and-error approach guided by:
     - Letter frequency patterns
     - Common digraphs (TH, HE, AN, IN)
     - Common trigraphs (THE, AND, ING)
   - Command structure: `tr 'nyv...' 'ETI...' <ciphertext.txt > partial_decrypt_v2.txt`

3. **Progressive Refinement:**
   - Iteratively mapped cipher letters to plaintext equivalents
   - Validated partial decryptions for linguistic coherence
   - Continued until achieving fully readable plaintext

**Key Findings:**
- Successfully decrypted entire ciphertext through statistical analysis
- Demonstrated vulnerability of simple substitution ciphers to frequency analysis
- Highlighted importance of confusion and diffusion in modern cryptography

**Skills Demonstrated:**
- Classical cryptanalysis techniques
- Statistical analysis and pattern recognition
- Linux command-line proficiency
- Iterative problem-solving in cryptographic contexts

---

### Task 2: Symmetric Encryption - Algorithm Comparison

**Objective:** Implement and compare encryption using AES-128, DES, and Blowfish algorithms in CBC mode.

**Implementation Process:**

1. **Setup Phase:**
   - Generated plaintext file: `echo -n "This is a secret file." > plain.txt`
   - Created cryptographic keys:
     - **KEY:** 32 hexadecimal digits (128-bit key)
     - **IV (Initialization Vector):** 16 hexadecimal digits (64-bit IV)

2. **Encryption Execution:**

   **AES-128-CBC:**
   ```bash
   openssl enc -aes-128-cbc -e -in plain.txt -out aes.txt -K $KEY -iv $IV
   ```

   **DES-CBC:**
   ```bash
   openssl enc -des-cbc -e -in plain.txt -out des.txt -K $KEY -iv $IV
   ```

   **Blowfish-CBC:**
   ```bash
   openssl enc -bf-cbc -e -in plain.txt -out bf.txt -K $KEY -iv $IV
   ```

3. **Output Analysis:**
   - Examined encrypted outputs using `xxd` (hex dump utility)
   - Observed ciphertext structure and padding implementation
   - All three algorithms produced different ciphertext from identical plaintext

**Comparative Analysis:**

| Algorithm | Block Size | Key Size | Security Status | Use Case |
|-----------|-----------|----------|-----------------|----------|
| AES-128 | 128 bits | 128 bits | Strong (Current standard) | Modern applications |
| DES | 64 bits | 56 bits | Weak (Deprecated) | Legacy systems only |
| Blowfish | 64 bits | Variable (32-448 bits) | Moderate | Specialized applications |

**Skills Demonstrated:**
- Symmetric encryption implementation
- OpenSSL command-line operations
- Understanding of encryption parameters (keys, IVs)
- Hexadecimal analysis and interpretation
- Security algorithm evaluation

---

### Task 3: Encryption Mode Analysis - ECB vs CBC Vulnerability

**Objective:** Demonstrate visual pattern leakage in ECB mode compared to CBC mode through image encryption.

**Experimental Setup:**
1. **Image Preparation:**
   - Source: `pic_original.bmp` (Bitmap image)
   - Format consideration: BMP files contain 54-byte header (must be preserved for viewability)

2. **Encryption Process:**

   **CBC Mode:**
   ```bash
   openssl enc -aes-128-cbc -in pic_original.bmp -out pic_cbc.bmp -K $KEY -iv $IV
   ```

   **ECB Mode:**
   ```bash
   openssl enc -aes-128-ecb -in pic_original.bmp -out pic_ecb.bmp -K $KEY
   ```
   *Note: ECB doesn't require IV (no chaining between blocks)*

3. **Header Preservation:**
   - Extracted 54-byte header from original file
   - Replaced encrypted headers with original header to maintain BMP structure
   - Commands used for header manipulation:
   ```bash
   head -c 54 pic_original.bmp > header
   tail -c +55 pic_ecb.bmp > body
   cat header body > view_ecb.bmp
   ```

4. **Visual Analysis:**
   - Viewed encrypted images using: `eog view_ecb.bmp` and `eog view_cbc.bmp`

**Critical Findings:**

**ECB Mode Vulnerability:**
- ❌ **Pattern Leakage:** Visual structures clearly visible in encrypted image
- ❌ **Deterministic Encryption:** Identical plaintext blocks → identical ciphertext blocks
- ❌ **Shape Recognition:** Identifiable objects (marked with blue oval and red rectangle)
- ❌ **Information Disclosure:** Reveals spatial relationships and patterns

**CBC Mode Security:**
- ✅ **Pattern Obfuscation:** No discernible patterns in encrypted image
- ✅ **Probabilistic Encryption:** IV ensures different ciphertext for same plaintext
- ✅ **Block Chaining:** Each block's encryption depends on previous block
- ✅ **Visual Randomness:** Complete noise distribution

**Real-World Implications:**
- ECB mode is **unsuitable for encrypting structured data** (images, databases, formatted documents)
- Demonstrates why ECB is deprecated in modern cryptographic standards
- Highlights importance of proper cipher mode selection in security implementations

**Skills Demonstrated:**
- Practical vulnerability demonstration
- Understanding of block cipher modes
- File manipulation and binary operations
- Security analysis through visual cryptanalysis
- Ability to explain complex cryptographic concepts clearly

---

### Task 4: Padding Schemes - Block Cipher Mechanics

**Objective:** Analyze padding behavior across different cipher modes and understand PKCS#7 padding implementation.

**Part A: Mode-Specific Padding Analysis**

1. **Encryption Across Four Modes:**
   - Created plaintext file: `echo -n "This is a secret file." > plain.txt`
   - Encrypted using identical keys/IVs with different modes:

   ```bash
   # Block Cipher Modes (require padding)
   openssl enc -aes-128-ecb -e -in plain.txt -out ecb.txt -K $KEY
   openssl enc -aes-128-cbc -e -in plain.txt -out cbc.txt -K $KEY -iv $IV
   
   # Stream Cipher Modes (no padding required)
   openssl enc -aes-128-cfb -e -in plain.txt -out cfb.txt -K $KEY -iv $IV
   openssl enc -aes-128-ofb -e -in plain.txt -out ofb.txt -K $KEY -iv $IV
   ```

2. **Padding Observation:**
   - Examined output using: `xxd ecb.txt`, `xxd cbc.txt`, `xxd cfb.txt`, `xxd ofb.txt`

**Results:**
| Mode | Cipher Type | Padding Present | Reason |
|------|-------------|-----------------|--------|
| ECB | Block | ✅ Yes | Must fill complete 16-byte blocks |
| CBC | Block | ✅ Yes | Must fill complete 16-byte blocks |
| CFB | Stream | ❌ No | Operates on individual bytes |
| OFB | Stream | ❌ No | Operates on individual bytes |

**Part B: PKCS#7 Padding Investigation**

1. **Variable-Length Plaintext Creation:**
   ```bash
   echo -n "12345" > f1.txt      # 5 bytes → needs 11-byte padding
   echo -n "123456789A" > f2.txt  # 10 bytes → needs 6-byte padding
   echo -n "123456789ABCDEF" > f3.txt  # 15 bytes → needs 1-byte padding
   ```

2. **Encryption with CBC Mode:**
   ```bash
   openssl enc -aes-128-cbc -e -in f1.txt -out encf1.txt -K $KEY -iv $IV
   openssl enc -aes-128-cbc -e -in f2.txt -out encf2.txt -K $KEY -iv $IV
   openssl enc -aes-128-cbc -e -in f3.txt -out encf3.txt -K $KEY -iv $IV
   ```

3. **Decryption Without Padding Removal:**
   ```bash
   openssl enc -aes-128-cbc -d -nopad -in encf1.txt -out decf1.txt -K $KEY -iv $IV
   # Repeated for encf2.txt and encf3.txt
   ```

4. **Padding Analysis:**
   ```bash
   hexdump -C decf1.txt
   hexdump -C decf2.txt
   hexdump -C decf3.txt
   ```

**PKCS#7 Padding Results:**

| File | Original Length | Padding Bytes Needed | Padding Value (Hex) | Observation |
|------|----------------|---------------------|---------------------|-------------|
| f1.txt | 5 bytes | 11 bytes | `0b 0b 0b 0b 0b 0b 0b 0b 0b 0b 0b` | Each padding byte = 0x0B (11 in decimal) |
| f2.txt | 10 bytes | 6 bytes | `06 06 06 06 06 06` | Each padding byte = 0x06 (6 in decimal) |
| f3.txt | 15 bytes | 1 byte | `01` | Single padding byte = 0x01 |

**Key Insight:**
- **PKCS#7 Padding Rule:** Padding byte value equals the number of padding bytes added
- Enables unambiguous padding removal during decryption
- If plaintext is exactly block-size multiple, a full block of padding is added

**Security Consideration:**
- Padding oracle attacks exploit error messages during padding validation
- Demonstrates why proper error handling is critical in cryptographic implementations

**Skills Demonstrated:**
- Deep understanding of block cipher mechanics
- Padding scheme analysis (PKCS#7)
- Distinction between block and stream cipher modes
- Binary data analysis using hex tools
- Security implications of implementation details

---

### Task 5: Error Propagation - Cipher Mode Resilience Analysis

**Objective:** Analyze how single-bit corruption propagates through different cipher modes during decryption.

**Experimental Design:**

1. **Test File Creation:**
   ```bash
   head -c 1000 /dev/urandom > longfile.txt  # 1000-byte random data
   ```

2. **Multi-Mode Encryption:**
   ```bash
   openssl enc -aes-128-ecb -e -in longfile.txt -out enc_longecb.txt -K $KEY
   openssl enc -aes-128-cbc -e -in longfile.txt -out enc_longcbc.txt -K $KEY -iv $IV
   openssl enc -aes-128-cfb -e -in longfile.txt -out enc_longcfb.txt -K $KEY -iv $IV
   openssl enc -aes-128-ofb -e -in longfile.txt -out enc_longofb.txt -K $KEY -iv $IV
   ```

3. **Corruption Injection:**
   - Used `bless` hex editor to modify **byte 55** in each encrypted file
   - Changed byte value to simulate transmission error or malicious tampering

4. **Decryption of Corrupted Files:**
   ```bash
   openssl enc -aes-128-ecb -d -in enc_longecb.txt -out dec_longecb.txt -K $KEY
   openssl enc -aes-128-cbc -d -in enc_longcbc.txt -out dec_longcbc.txt -K $KEY -iv $IV
   openssl enc -aes-128-cfb -d -in enc_longcfb.txt -out dec_longcfb.txt -K $KEY -iv $IV
   openssl enc -aes-128-ofb -d -in enc_longofb.txt -out dec_longofb.txt -K $KEY -iv $IV
   ```

5. **Comparative Analysis:**
   - Compared decrypted files with original using hex dumps
   - Measured error propagation scope for each mode

**Error Propagation Results:**

| Cipher Mode | Error Propagation | Affected Data | Block Size Impact |
|-------------|-------------------|---------------|-------------------|
| **ECB** | ❌ Limited | Only the corrupted block (16 bytes) | 1 block affected |
| **CBC** | ⚠️ Moderate | Corrupted block + next block (32 bytes) | 2 blocks affected |
| **CFB** | ✅ Minimal | Only the corrupted byte (1 byte) | 1 byte affected |
| **OFB** | ✅ Minimal | Only the corrupted byte (1 byte) | 1 byte affected |

**Detailed Mode Analysis:**

**ECB (Electronic Codebook):**
- **Propagation:** Confined to single 16-byte block containing corruption
- **Mechanism:** Each block encrypted independently
- **Implication:** Errors don't spread, but pattern leakage remains a security issue

**CBC (Cipher Block Chaining):**
- **Propagation:** Corrupted block + subsequent block (32 bytes total)
- **Mechanism:** Decryption of block N depends on ciphertext of block N-1
- **Implication:** Limited error spread with self-healing property (errors don't propagate beyond 2 blocks)

**CFB (Cipher Feedback):**
- **Propagation:** Only the corrupted byte
- **Mechanism:** Operates as stream cipher; each byte independently encrypted
- **Implication:** Best error resilience for unreliable channels

**OFB (Output Feedback):**
- **Propagation:** Only the corrupted byte
- **Mechanism:** Keystream generated independently of plaintext/ciphertext
- **Implication:** Ideal for streaming data where bit errors are expected

**Real-World Applications:**

| Mode | Best Use Case | Reason |
|------|---------------|--------|
| ECB | ❌ Never recommended | Pattern leakage vulnerability |
| CBC | File encryption, TLS 1.2 | Good security with moderate error resilience |
| CFB | Network streaming | Self-synchronizing with minimal error impact |
| OFB | Satellite communications | Error isolation in noisy channels |

**Skills Demonstrated:**
- Error propagation analysis in cryptographic systems
- Understanding of cipher mode mechanics at byte level
- Hex editing and binary file manipulation
- Comparative security analysis
- Ability to recommend appropriate cipher modes for specific scenarios
- Understanding of trade-offs between security and error resilience

---

### Task 6: IV Reuse Attacks - Cryptographic Oracle Exploitation

This task consists of two sophisticated cryptographic attacks exploiting initialization vector (IV) vulnerabilities.

#### **Part A: Known-Plaintext Attack via IV Manipulation**

**Scenario:**
- **Given:** 
  - P1 = "This is a known message!" (known plaintext)
  - C1 = `a469b1c502c1cab966965e50425438e1bb1b5f9037a4c159` (corresponding ciphertext)
  - C2 = `bf73bcd3509299d566c35b5d450337e1bb175f903fafc159` (target ciphertext)
- **Objective:** Recover unknown plaintext P2 from C2

**Attack Methodology:**

1. **Cryptographic Foundation:**
   - OFB mode encryption: `C = P ⊕ Keystream`
   - In OFB, keystream is independent of plaintext
   - **Key Insight:** Same keystream used if IVs are identical

2. **Keystream Recovery:**
   ```
   K = P1 ⊕ C1
   ```
   Where K represents the keystream used for encryption

3. **Manual XOR Calculation:**
   - Converted P1 to hexadecimal:
   
   | Char | ASCII Decimal | Hex |
   |------|---------------|-----|
   | T | 84 | 54 |
   | h | 104 | 68 |
   | i | 105 | 69 |
   | s | 115 | 73 |
   | (space) | 32 | 20 |
   | ... | ... | ... |
   
   **P1 (hex):** `546869732069732061206b6e6f776e206d65737361676521`

4. **Keystream Extraction (K = P1 ⊕ C1):**
   ```
   54 ⊕ a4 = f0
   68 ⊕ 69 = 01
   69 ⊕ b1 = d8
   73 ⊕ c5 = b6
   ... (byte-by-byte XOR)
   ```
   **Result K:** `f001d8b622a8b99907b6353e2d2356c1d67e2ce356c3a478`

5. **Plaintext Recovery (P2 = C2 ⊕ K):**
   ```
   bf ⊕ f0 = 4f (O)
   73 ⊕ 01 = 72 (r)
   bc ⊕ d8 = 64 (d)
   d3 ⊕ b6 = 65 (e)
   50 ⊕ 22 = 72 (r)
   92 ⊕ a8 = 3a (:)
   99 ⊕ b9 = 20 (space)
   ... (continued XOR operations)
   ```

6. **Python Automation:**
   - Modified `sample_code.py` to automate XOR calculations
   - Validated manual calculations programmatically

**Recovered Plaintext:**
```
P2 = "Order: Launch a missile!"
```

**Attack Success Factors:**
- IV reuse across multiple messages
- Knowledge of one plaintext-ciphertext pair
- OFB mode's keystream independence

---

#### **Part B: Padding Oracle Attack on IV Prediction**

**Scenario:**
- Bob encrypted a secret ("Yes" or "No") and sent ciphertext
- Oracle server provides:
  - Bob's ciphertext
  - IV used by Bob (IV1)
  - Next IV to be used (IV2)
- **Goal:** Determine Bob's secret without decryption key

**Attack Vector:**

1. **Cryptographic Weakness:**
   - Predictable IV sequence
   - Ability to control plaintext encrypted with known future IV
   - Oracle returns ciphertext for our chosen plaintext

2. **Attack Formula:**
   ```
   P_attack = IV1 ⊕ IV2 ⊕ P_guess
   ```
   Where:
   - IV1 = IV used by Bob for his secret
   - IV2 = Next IV (provided by oracle)
   - P_guess = Our guess ("Yes" or "No")

3. **Attack Execution:**

   **Step 1: Connect to Oracle**
   ```bash
   nc 10.9.0.80 3000
   ```

   **Step 2: Receive Oracle Information**
   ```
   Bob's secret ciphertext: bf8f5399fdec01f81a395e34aa9cf86b
   Bob's original IV:       a81b2117244d3c85e766b1836e9c4f94
   Next IV:                 772de66f244d3c85e766b1836e9c4f94
   ```

   **Step 3: Prepare Attack Plaintext**
   - Guess: "Yes"
   - Hex (with PKCS#7 padding): `5965730d0d0d0d0d0d0d0d0d0d0d0d0d`
   
   **Step 4: Calculate Attack Plaintext**
   ```
   Part 1: 5965730d0d0d0d0d0d0d0d0d0d0d0d0d ⊕ 
           a81b2117244d3c85e766b1836e9c4f94
         = f17e521a29413188eafbf25a63919299

   Part 2: f17e521a29413188eafbf25a63919299 ⊕
           772de66f244d3c85e766b1836e9c4f94
         = 8653b4750d0c0d0d0d9dc3dd0d0d0d0d
   ```
   
   **P_attack:** `8653b4750d0c0d0d0d9dc3dd0d0d0d0d`

4. **Oracle Query:**
   - Submitted crafted plaintext to oracle
   - Oracle encrypted it with IV2 and returned ciphertext

5. **Ciphertext Comparison:**
   - **Oracle ciphertext:** Different from Bob's ciphertext
   - **Conclusion:** Guess was incorrect
   - **Bob's secret:** "No"

**Attack Mechanics Explained:**

```
Bob's encryption:    C_bob = E(P_secret ⊕ IV1)
Our encryption:      C_our = E(P_attack ⊕ IV2)

If we set: P_attack = IV1 ⊕ IV2 ⊕ P_guess

Then: C_our = E((IV1 ⊕ IV2 ⊕ P_guess) ⊕ IV2)
            = E(IV1 ⊕ P_guess)
            
If P_guess = P_secret, then:
      C_our = E(IV1 ⊕ P_secret)
            = C_bob  ← Ciphertexts match!
```

**Vulnerability Chain:**
1. ✅ Predictable IV sequence
2. ✅ Oracle access (encryption service)
3. ✅ Known IV values (past and future)
4. ✅ Limited plaintext space (Yes/No)
5. ✅ Ciphertext comparison capability

**Real-World Implications:**
- **TLS vulnerabilities:** BEAST attack exploited similar IV predictability in TLS 1.0
- **API security:** Demonstrates danger of exposing cryptographic operations as services
- **IV generation:** Must use cryptographically secure random IVs (CSPRNG)
- **Defense:** Implement rate limiting, randomness verification, and proper IV handling

**Skills Demonstrated:**
- Advanced cryptographic attack implementation
- XOR cipher manipulation
- Python scripting for cryptanalysis
- Network protocol interaction (netcat)
- Padding oracle exploitation
- Mathematical reasoning in cryptographic contexts
- Understanding of IV security requirements
- Ability to chain multiple vulnerabilities for attack success

---

## 🎓 Key Learning Outcomes

### Security Vulnerabilities Identified:
1. **Pattern Leakage in ECB Mode** - Visual cryptanalysis possible
2. **IV Reuse in OFB Mode** - Keystream recovery attack
3. **Predictable IVs** - Oracle-based plaintext recovery
4. **Padding Implementation** - Understanding of padding oracle potential
5. **Classical Cipher Weaknesses** - Frequency analysis effectiveness

### Defensive Recommendations:
- ✅ **Never use ECB mode** for any production encryption
- ✅ **Generate IVs using CSPRNG** - cryptographically secure random number generators
- ✅ **Never reuse IVs** in stream cipher modes (OFB, CTR)
- ✅ **Implement authenticated encryption** (GCM, CCM) to detect tampering
- ✅ **Use TLS 1.3** which eliminates many IV-related vulnerabilities
- ✅ **Limit oracle access** - implement rate limiting and monitoring
- ✅ **Constant-time operations** - prevent timing side-channels

---

## 💡 Real-World Applications

### Industry Relevance:

**1. Secure Communications:**
- Understanding of why messaging apps use AES-GCM instead of CBC
- Importance of IV management in VPN implementations

**2. Data-at-Rest Encryption:**
- Why disk encryption (BitLocker, LUKS) uses XTS mode
- Implications of mode selection for database encryption

**3. Security Auditing:**
- Ability to identify weak cryptographic implementations
- Methodology for testing encryption systems

**4. Penetration Testing:**
- Practical cryptographic attack techniques
- Oracle exploitation scenarios

---

## 🔧 Technical Skills Demonstrated

### Cryptography:
- Symmetric encryption algorithms (AES, DES, Blowfish)
- Block cipher modes (ECB, CBC, CFB, OFB)
- Frequency analysis and cryptanalysis
- IV management and security
- Padding schemes (PKCS#7)
- XOR cipher operations

### Tools & Technologies:
- OpenSSL command-line operations
- Python scripting for cryptanalysis
- Hex editors (xxd, hexdump, bless)
- Network tools (netcat)
- Linux command-line utilities
- Binary file manipulation

### Analysis & Problem-Solving:
- Vulnerability identification
- Attack vector development
- Comparative security analysis
- Statistical pattern recognition
- Systematic debugging approach

---