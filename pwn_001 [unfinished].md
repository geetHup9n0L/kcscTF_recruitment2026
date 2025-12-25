## Lược qua:
Chall này sẽ chủ yếu khai thác lỗ hổng format string từ leak password, địa chỉ đến write vào RIP

## Hướng giải:
### Thông tin:
Thông tin binary:
```python
└─$ file 001
001: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=c0a5d52dcd7a7abdf69e0ee2302b8d22e2808da4, for GNU/Linux 3.2.0, with debug_info, not stripped
                                                                                                   
└─$ checksec --file=001
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   60 Symbols  No     0               3               001
```
* binary full lớp bảo vệ

Disassembly code:
```c

/* WARNING: Unknown calling convention */

int main(void)

{
  int match;
  size_t len;
  EVP_PKEY_CTX *in_RDI;
  long in_FS_OFFSET;
  char *secret;
  char name [9];
  char passwd [128];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  init(in_RDI);
  gen_passwd(backup_passwd,40);
  printf("Account: ");
  read_line(0,name,9);
  printf("Account: ");
  printf(name);     /////////////////////////
  putchar(10);
  printf("Password: ");
  read_line(0,passwd,128);
  len = strlen(backup_passwd);
  match = strncmp(passwd,backup_passwd,len);  /////////////////
  if (match == 0) {
    write_passwd(passwd);
  }
  else {
    puts("Password is: 123456789");
    puts("You are not an administrator");
    puts("Do you want to be a pwn player???");
    puts("Watch video: https://youtu.be/BSbYN8srw7U?si=q_eH4ZNipi74lLO8");
    puts("Bye bye =)");
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```
* `printf(name); ` có thể format string
* `strncmp(passwd,backup_passwd,len);` kiểm tra pass, với độ dài xác định (len = 16), nó sẽ không xét từ offset 16 trở đi
```c
void gen_passwd(char *backup_pass,size_t len)

{
  uint pid;
  int rand_val;
  size_t length;
  time_t rand;
  size_t len_local;
  char *out_local;
  size_t passlen;
  size_t i;
  char *chars;
  size_t clen;
  
  length = strlen("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
  if (len == 0) {
    len = 1;
  }
  passlen = len - 1;
  if (16 < passlen) {   
    passlen = 16;      // backup_passwd có độ dài = 16
  }
  rand = time((time_t *)0x0);
  pid = getpid();
  srand(pid ^ (uint)rand);
  for (i = 0; i < passlen; i = i + 1) {
    rand_val = ::rand();
    backup_pass[i] =
         "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
         [(ulong)(long)rand_val % length];
  }
  backup_pass[passlen] = '\0';
  return;
}
```
* khởi tạo random password cho `backup_passwd`
```c
ssize_t read_line(int fd,char *name,size_t maxlen)

{
  ssize_t sVar1;
  long in_FS_OFFSET;
  size_t maxlen_local;
  char *buf_local;
  int fd_local;
  char c;
  ssize_t total;
  ssize_t r;
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  total = 0;
  do {
    if ((long)maxlen <= total + 1) {
LAB_001016c1:
      name[total] = '\0';
      sVar1 = total;
LAB_001016d3:
      if (canary == *(long *)(in_FS_OFFSET + 0x28)) {
        return sVar1;
      }
                    /* WARNING: Subroutine does not return */
      __stack_chk_fail();
    }
    r = read(fd,&c,1);
    if (r < 1) {
      if ((r == 0) && (total == 0)) {
        sVar1 = 0;
        goto LAB_001016d3;
      }
      goto LAB_001016c1;
    }
    if (c == '\n') goto LAB_001016c1;
    name[total] = c;
    total = total + 1;
  } while( true );
}
```
```c
int write_passwd(char *passwd)

{
  int file;
  long in_FS_OFFSET;
  char *passwd_local;
  int fd;
  char cmd [128];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  printf("Password: ");
  printf(passwd);    //////////////////////
  putchar(10);
  file = open("admin",577,420);
  if (-1 < file) {
    snprintf(cmd,128,"echo \"%s\" > admin",backup_passwd);
    system(cmd);
  }
  else {
    perror("open");
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return (int)(-1 >= file);
}
```
*  `printf(passwd);`: có thể format string tiếp
```c
/* WARNING: Unknown calling convention -- yet parameter storage is locked */

void win(void)

{
  system("/bin/sh");
  return;
}
```
* hàm win() chạy shell, ta sẽ cần nhảy vào đây

### Khai thác:
dùng format string leak `backup_passwd` trên stack:

<img width="802" height="175" alt="image" src="https://github.com/user-attachments/assets/f2165f02-d544-45f9-a787-b688be964854" />

<img width="801" height="819" alt="image" src="https://github.com/user-attachments/assets/7f573c20-7839-443f-a6fb-9fd7170d4b2d" />

và leak cả libc ở RIP:

* tìm offset của format string:
  * leak ở printf(name) nhưng sai, vì stack frame mới của hàm `write_passwd()`
    
<img width="799" height="426" alt="image" src="https://github.com/user-attachments/assets/6b8ac652-b192-4396-9a20-0591a911a84a" />
```c
%29$p
```
<img width="806" height="144" alt="image" src="https://github.com/user-attachments/assets/ed23eea8-9f40-48b1-9e78-2010413fa74b" />

  * leak ở printf(passwd), nên phải căn lại với rbp cũ
    
<img width="811" height="340" alt="image" src="https://github.com/user-attachments/assets/23bbd6ef-0d23-4345-90fd-37ee6957a0a5" />
<img width="806" height="606" alt="image" src="https://github.com/user-attachments/assets/56f18ccb-15f5-4c63-9e44-2e9fd7f43533" />

```c
%53$p
```

* tìm offset từ leak libc đến base

<img width="803" height="406" alt="image" src="https://github.com/user-attachments/assets/b51647c0-9ac8-47d9-ae33-02913e93410a" />

<img width="805" height="569" alt="image" src="https://github.com/user-attachments/assets/9e9ecd76-62cb-43fb-830a-8da08b51acfe" />

```c
libc.address = leak_libc - 0x29ca8
```

Kiểm tra lại:

<img width="802" height="247" alt="image" src="https://github.com/user-attachments/assets/46011373-6664-495b-9589-f273ab93c888" />
<img width="806" height="359" alt="image" src="https://github.com/user-attachments/assets/13ae89b9-5447-475a-868c-88a3b7e0d61a" />

* dùng format string `%n` overwrite địa chỉ `win()` vào `RIP`:

địa chỉ hàm `win()`:

<img width="806" height="200" alt="image" src="https://github.com/user-attachments/assets/af769bc9-d036-4719-a9f1-30c364486f25" />
```
win = libc.base + 0x1329
```






