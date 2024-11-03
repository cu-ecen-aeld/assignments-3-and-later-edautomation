# Analysis of Kernel oops

## Introduction

Upon execution of `echo "Hello, world" > /dev/faulty`, the system crashes and prints out a report.

## What happened?

It seems the `faulty` driver attempts to dereference a NULL pointer:

    Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000

## Where did it happen?

It seems the NULL pointer dereference happened in the `faulty` driver in the `faulty_write` function, eight bytes into the function, which is 16 bytes long.

     pc : faulty_write+0x8/0x10 [faulty]


## Full Output
    
    echo "Hello, world�" > /dev/faulty
    Unable to handle kernel NULL pointer dereference at virtual address 0000000000000000
    Mem abort info:
      ESR = 0x0000000096000045
      EC = 0x25: DABT (current EL), IL = 32 bits
      SET = 0, FnV = 0
      EA = 0, S1PTW = 0
      FSC = 0x05: level 1 translation fault
    Data abort info:
      ISV = 0, ISS = 0x00000045, ISS2 = 0x00000000
      CM = 0, WnR = 1, TnD = 0, TagAccess = 0
      GCS = 0, Overlay = 0, DirtyBit = 0, Xs = 0
    user pgtable: 4k pages, 39-bit VAs, pgdp=0000000041bba000
    [0000000000000000] pgd=0000000000000000, p4d=0000000000000000, pud=0000000000000000
    Internal error: Oops: 0000000096000045 [#1] SMP
    Modules linked in: hello(O) faulty(O) scull(O) [last unloaded: hello(O)]
    CPU: 0 PID: 115 Comm: sh Tainted: G           O       6.6.32 #1
    Hardware name: linux,dummy-virt (DT)
    pstate: 80000005 (Nzcv daif -PAN -UAO -TCO -DIT -SSBS BTYPE=--)
    pc : faulty_write+0x8/0x10 [faulty]
    lr : vfs_write+0xb8/0x384
    sp : ffffffc080dc3d20
    x29: ffffffc080dc3d20 x28: ffffff8001b76a00 x27: 0000000000000000
    x26: 0000000000000000 x25: 0000000000000000 x24: 0000000000000000
    x23: 0000000040001000 x22: 000000000000000e x21: 000000555daa2310
    x20: 000000555daa2310 x19: ffffff8001b89300 x18: 0000000000000000
    x17: 0000000000000000 x16: 0000000000000000 x15: 0000000000000000
    x14: 0000000000000000 x13: 0000000000000000 x12: 0000000000000000
    x11: 0000000000000000 x10: 0000000000000000 x9 : 0000000000000000
    x8 : 0000000000000000 x7 : 0000000000000000 x6 : 0000000000000000
    x5 : 0000000000400100 x4 : ffffffc078ba9000 x3 : ffffffc080dc3df0
    x2 : 000000000000000e x1 : 0000000000000000 x0 : 0000000000000000
    Call trace:
     faulty_write+0x8/0x10 [faulty]
     ksys_write+0x68/0xf4
     __arm64_sys_write+0x1c/0x28
     invoke_syscall+0x54/0x128
     el0_svc_common.constprop.0+0x40/0xe0
     do_el0_svc+0x1c/0x28
     el0_svc+0x40/0xf4
     el0t_64_sync_handler+0xc0/0xc4
     el0t_64_sync+0x190/0x194
    Code: ???????? ???????? d2800001 d2800000 (b900003f) 
    ---[ end trace 0000000000000000 ]---
    

