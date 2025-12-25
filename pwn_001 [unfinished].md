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
* `strncmp(passwd,backup_passwd,len);` kiểm tra pass, độ dài (len = 16)
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
