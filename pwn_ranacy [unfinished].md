## Lược qua:

**Challenge này cho phép ta khai thác lỗ hổng BOF (buffer overflow), leak canary trên stack và thực hiện kỹ thuật Stack pivot (chuyển hướng luồng thực thi) sang shell tự tạo**

Nguồn tham khảo: 

* BOF & Stack pivot:  https://www.youtube.com/watch?v=-dnH913iloY (của JHT)

* Stack pivot & SROP: https://www.youtube.com/watch?v=K4B_qVGJUFw (SloppyJoePirates)

___
## Hướng giải
### Thông tin:
Tên binary là:
```
ranacy
```
Kiểm tra thông tin file:
```python
└─$ file ranacy 
ranacy: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=9e97f9713e799c491a7a9083e39302a13b4a6842, for GNU/Linux 3.2.0, not stripped
```
* binary `64-bit` và `dynamically linked`
```python
└─$ checksec --file=ranacy 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   46 Symbols  No     0               3               ranacy
```
* `NO PIE`: các địa chỉ tĩnh
* Cả `canary` và `NX` được bật

Output binary:

<img width="806" height="113" alt="image" src="https://github.com/user-attachments/assets/ca38e330-3e78-475f-a58d-dc22b7c0f4cb" />

Các functions chính:

<img width="807" height="396" alt="image" src="https://github.com/user-attachments/assets/4a8cb342-de4b-401b-9642-d76427e8eacc" />

Mổ xẻ code trong ghidra:
```c
undefined8 main(void)

{
  vuln();
  return 0;
}
```
```c
void vuln(void)

{
  long in_FS_OFFSET;
  int choice;
  int attempts;
  undefined1 input_buffer [264];    ///////////////
  long canary_check;
  
  canary_check = *(long *)(in_FS_OFFSET + 0x28);
  set_up(input_buffer);
  attempts = 0;
  do {
    if (4 < attempts) {      //////////////
code_r0x004013a4:
      if (canary_check != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return;
    }
    menu();
    FUN_00401100(&DAT_00402043,&choice);
    if (choice == 1) {
      printf("Please enter some data:\n> ");
      read(0,input_buffer,288);    ////////////////
    }
    else if (choice == 2) {
      printf("Starting data observation...\nData: %s\n",input_buffer);  ///////////
    }
    else {
      if (choice == 3) {
        puts("Processing your request...");
        goto code_r0x004013a4;
      }
      puts("Invalid choice, please try again.");
    }
    attempts = attempts + 1;
  } while( true );
}
```
**Chức năng đáng chú ý:**
* Khả năng **BOF**, khi mà `read()` đọc nhiều hơn so với size `input_buffer[]`:
  ```c
  input_buffer [264];
  ...
  read(0,input_buffer,288);
  ```
* Chỉ có `5` lần tương tác binary:
  ```c
  if (4 < attempts) {
      ...
      return;
  }
  ```
* Lựa chọn `2` in ra `input_buffer`: dùng để leak data
  ```c
  else if (choice == 2) {
      printf("Starting data observation...\nData: %s\n",input_buffer);
  }
  ```

___
### Khai thác:

Vậy, có lỗ hổng `BOF`, với NX và Canary đều được bật, và một vùng nhớ khá nhỏ để overflow
```c
overflow = 288 - 264 = 24 bytes
```
Ở đây, có thể hình dung Stack như sau:
```asm
low address
|--------------|
| input_buffer | 264 bytes  <== rsp 
| [0]...[263]  |
| canary       | 8 bytes   }
| saved rbp    | 8 bytes   } => 24 bytes
| return       | 8 bytes   }
| ...          |
high address
```
Phạm vi để BOF là bao gồm cả `canary`, `saved_rbp`, `ret` (24 bytes). Rất hẹp để thực hiện việc tạo shell, nên phải áp dụng **Stack pivot** để chuyển đến nơi có đủ vùng nhớ cho shell trên stack

**Mục tiêu**: Tạo shell trong vùng nhớ `input_buffer[]`, và Stack pivot đến địa chỉ `input_buffer` trên stack 

Và phải khai thác trong 5 lần tương tác binary

1. Leak `canary` và `saved rbp`:
* cái canaray thường có `\x00` (null) ở byte đầu tiên (hay ở LSB), nhằm mục đích chặn `printf()` in ra value trong canary.

  bắng cách BOF và overwrite cái null byte này, printf() sẽ in ra liên tục các giá trị trên stack cho đến khi gặp `\x00`
  ```python
  payload = b'A' * 264 + b'A' # 'A' cuối thay thế '\x00'
  ```
==> Với cách này, có thể leak cả canary và saved rbp

* cần leak `old rbp` của main trong `saved rbp`, vì là địa chỉ đáng tin cậy để gián tiếp tính địa chỉ của `input_buffer` (Vì ASLR)

2. Tạo shell trên input_buffer và Pivot stack đến input_buffer:

**Trước hết, tính địa chỉ input_buffer:**

* debug kiếm tra stack memory, thấy địa chỉ `old rbp` trong `rbp` và địa chỉ của `input_buffer`
<img width="801" height="451" alt="image" src="https://github.com/user-attachments/assets/9fa70cbe-3e70-45b7-b9fd-85c5b2118136" />
* tính offset:
  ```python
  offset = 0x7ffee9330870 - 0x7ffee9330748 = 0x120
  ```
* Có thể thấy địa chỉ thay đổi trong lần chạy khác (vì ASLR), nhưng offset giữ nguyên - đáng tin cậy
<img width="799" height="513" alt="image" src="https://github.com/user-attachments/assets/11e94622-876c-40ec-a2c1-c24366bf54ad" />
* Địa chỉ input_buffer at runtime:
  ```python
  buffer_addr = leaked_rbp - 0x120
  ```
**Để thực hiện Stack Pivot:**

* Hình dung stack:
```asm
[ buffer        ]  ← overflow xuất phát
[ ...           ]
[ saved rbp     ]  ← overwrite 
[ return addr   ]  ← overwrite 
```
* overwrite `saved rbp` với địa chỉ `buffer_address`
* overwrite `return addr` với `leave; ret` gadget
  * `rsp = rbp`: rsp trỏ tới địa chỉ `buffer_address`
  * `pop rbp`: rbp = `buffer_address`
  * `ret`








