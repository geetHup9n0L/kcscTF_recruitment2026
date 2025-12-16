## Lược qua:
Challenge đọc shellcode từ input người dùng và thực thi nó, binary sẽ thoát nếu shellcode bao gồm 


___
## Cách giải

### Thông tin:
* Challenge đưa ra các file:
```
Dockerfile
vuln
flag.txt
```
* Kiểm tra thông tin file:
```
└─$ file vuln 
vuln: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=d09e382b902cb23837b58db43648051472523f0d, for GNU/Linux 3.2.0, not stripped
```
* File **64-bit**
```c
└─$ checksec --file=vuln 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX disabled   PIE enabled     No RPATH   No RUNPATH   53 Symbols  No     0               2               vuln
```
* `NX disabled`: có thể thực thị shellcode trên stack

Chạy binary:
<img width="810" height="84" alt="image" src="https://github.com/user-attachments/assets/040b1bf2-f9f1-4463-b046-5214ac760cc1" />

Function đáng chú ý chỉ có main() 

Disassemle trong ghidra:
```c
undefined8 main(void)

{
  long lVar1;
  int mproc;
  ssize_t read;
  long in_FS_OFFSET;
  int index;
  short char;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  setup();
  printf("Your shellcode: ");
  read = ::read(0,shellcode,4096);
  if ((int)read < 1) {
    perror("Read failed !!!");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  mproc = mprotect(shellcode,0x1000,5);
  if (mproc != 0) {
    perror("Mprotect failed !!!");
                    /* WARNING: Subroutine does not return */
    exit(-1);
  }
  close(0);
  index = 0;
  while( true ) {
    if ((int)read + -1 <= index) {
      (*shellcode)();
      if (lVar1 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return 0;
    }
    char = *(short *)(shellcode + index);
    if (((char == 0x50f) || (char == 0x340f)) || (char == -0x7f33)) break;
    index = index + 1;
  }
  puts("Found forbidden bytes !!!");
                    /* WARNING: Subroutine does not return */
  exit(1);
}
```
Từ disassembly code, ta chú ý:
* `read = ::read(0,shellcode,4096);` đọc lượng lớn thông tin từ user (4096 bytes)
* `mproc = mprotect(shellcode,0x1000,5);`: là quyền truy cập RWE cho vị trí shellcode
  * `shellcode`: vị trí trên memory
  * `0x1000`: là kích thước vùng lữu trữ (= 4096)
  * `prot = 5`: (= 1 + 4) = PROT_READ | PROT_EXEC - là tại vùng nhớ shellcode, có thể readale and executable

Trong vòng while loop:
* `(*shellcode)();`: chương trình sẽ thực thi shellcode
* Kiếm tra xem trong payload có sử dụng syscall instructions
  `if (((char == 0x50f) || (char == 0x340f)) || (char == -0x7f33)) break;`:
    | Check     | Hex      | Bytes    | Meaning    |
    | --------- | -------- | ---------- | ---------- |
    | `0x50f`   | `0x050f` | `0f 05`    | `syscall`  |
    | `0x340f`  | `0x340f` | `0f 34`    | `sysenter` |
    | `-0x7f33` | `0x80cd` | `cd 80`    | `int 0x80` |

  
