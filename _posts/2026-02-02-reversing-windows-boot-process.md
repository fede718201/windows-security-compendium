---
layout: post
slug: reversing_windows_boot_chain
title: Reversing the Windows Boot Chain with Binary Ninja
---

Before getting into the kernel code, here is a compressed version of what happens before `KiSystemStartup` runs. I am not going to spend too much time on the pre-kernel stages since the focus of this post is on `ntoskrnl.exe` itself, but some context is necessary.

Pressing the power button shorts PWRBTN# to GND on the motherboard. That is the entire input. The PCH's Power Management Controller picks up the falling edge, sequences the sleep signals and PS_ON#, waits for PWR_OK from the PSU, and releases the CPU from reset. First instruction fetch lands at `0xFFFFFFF0`. The chipset routes that address to the SPI flash where the UEFI firmware lives.

The firmware side of things is a whole topic on its own, but the short version: SEC runs first and has to set up Cache-As-RAM because DRAM does not exist yet (the CPU cache is literally tricked into acting as writable memory). PEI comes next and its main job is getting real RAM working through the Memory Reference Code. DXE is where the firmware starts resembling an OS, loading drivers and building the UEFI service tables. BDS finds the boot device.

From there it is the Windows bootloader chain. `bootmgfw.efi` reads the BCD store, which is a registry hive sitting on FAT32 if you can believe that, takes TPM measurements, and loads `winload.efi`. This is the component that does the real work. `winload.efi` loads `ntoskrnl.exe`, `hal.dll`, all the BOOT_START drivers, and builds the `LOADER_PARAMETER_BLOCK`. That structure is massive. Physical memory map, every loaded module, initial EPROCESS, initial ETHREAD, the SYSTEM hive, boot flags, ELAM data, TPM entropy. Everything. `winload.efi` also configures the page tables, writes PML4 into CR3, sets up the GDT and IDT, then calls `ExitBootServices()`. After that call the firmware is gone. No going back. The LOADER_PARAMETER_BLOCK pointer goes into RCX and execution jumps to `KiSystemStartup`.
