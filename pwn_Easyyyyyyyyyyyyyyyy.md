### Lược qua:
Challenge cho phép tận dụng lỗ hổng OOB (Out-of-bound) để write vào memory, cụ thể là vào các chức năng libc từ GOT để thực thi chức năng cụ thể khác.

Nguồn tham khảo chính (của JHT): 

https://www.youtube.com/watch?v=ogTRLJ3kiIk

### Cách giải:
Challenge cho file: 
```
easy.rar
```

Giải nén file với `unrar` và kiểm tra thông tin cơ bản:
```bash
└─$ file vuln
vuln: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=3d38ee665e85336ce7d15bfbb8179ac70377fd82, for GNU/Linux 3.2.0, not stripped
```
* binary chạy 64-bit
* dynamically linked: sử dụng shared libc tại runtime
* not stripped: dễ đọc hơn khi disassemble binary
```bash
└─$ checksec --file=vuln
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   No canary found   NX enabled    No PIE          No RPATH   No RUNPATH   57 Symbols  No     0               5               vuln                                               
```
* NO pie: các địa chỉ cố định
* NO canary: có thể BOF
* Partial RELRO: có thể write vào GOT table

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
Đáng chú ý ở đoạn:
```c
      if (userinput == 1) {
        ret_id = input_player();
        id = (long)ret_id;
        printf("User created! ID: %d\n",id);
      }
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
Đây là nơi có lỗ hổng OOB + overwrite địa chỉ libc' functions 










