## Lược qua:

**Bài này là nâng cao của [`Easyyyyyyyyyyyyyyyy`](https://github.com/geetHup9n0L/kcscTF_recruitment2026/blob/main/pwn_Easyyyyyyyyyyyyyyyy.md), 
vẫn tận dụng lỗ hổng OOB (Out-of-bound) để write vào địa chỉ các chức năng libc trên memory, bên cạnh đó sẽ là lỗ hổng Interger Overflow (tràn số nguyên có dấu).**


___
## Hướng giải:
### Thông tin:
Các files cung cấp vẫn giống bài `Easyyy..`
```c
└─$ file test 
test: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ec52346b8150e97d895157fe88a7b60f078eee72, for GNU/Linux 3.2.0, not stripped
```
```c
└─$ checksec --file=test
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
No RELRO        Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   58 Symbols  No     0               5               test
```
* `NO RELRO`: overwrite được GOT
* `NO PIE`: các địa chỉ là cố định

Output binary:

<img width="811" height="210" alt="image" src="https://github.com/user-attachments/assets/28bd1006-f774-421e-92c4-f1d0fc5ab934" />

Trong disassemly code, hàm main() vẫn thế:
```c

void main(EVP_PKEY_CTX *param_1)

{
  long in_FS_OFFSET;
  int userinput;
  undefined8 local_20;
  undefined8 id;
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  init(param_1);
  puts("Welcome to TTV!");
  puts("First, create a user.");
  create();
  puts("User created! ID: 0");
LAB_00401711:
  menu();
  printf("Input your choice:");
  __isoc99_scanf(&DAT_00402175,&userinput);
  if (userinput == 4) {
    puts("Exiting... Goodbye!");
    FUN_004011e0(0);
  }
  else {
    if (4 < userinput) goto LAB_0040180d;
    if (userinput == 3) {
      make_noise();
      goto LAB_00401711;
    }
    if (userinput < 4) {
      if (userinput == 1) {
        id = input_player();
        printf("User created! ID: %d\n",id);
      }
      else {
        if (userinput != 2) goto LAB_0040180d;
        printf("Input id to view: ");
        __isoc99_scanf(&DAT_00402060,&local_20);
        view(local_20);
      }
      goto LAB_00401711;
    }
  }
LAB_0040180d:
  puts("Invalid choice. Try again.");
  goto LAB_00401711;
}
```
Hàm win(): (target)
```c
void win(void)

{
  system("/bin/sh");
  return;
}
```
___
### Khai thác:
**Thay đổi trong code đáng chú ý nằm ở hàm `input_user()`**:
```c
ulong input_player(void)

{
  int iVar1;
  long in_FS_OFFSET;
  ulong id;            //////////////////
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Input user \'s id:");
  iVar1 = __isoc99_scanf(&DAT_00402060,&id);
  if (iVar1 == 1) {
    if (id < 230584300921369395) {      //////////////////////
      printf("Input user \'s name:");   
      read(0,users + id * 80,80);
    }
    else {
      printf("Error: ID %llu is too large or invalid.\n",id);
      id = 0xffffffffffffffff;
    }
  }
  else {
    id = 0xffffffffffffffff;
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return id;
}
```
**Thay đổi:**
* bây giờ, data type của `id` là kiểu số không âm `ulong` (unsigned long), và có kích thước rất to = `8 byte` (64 bit)

* một cái check mới `if (id < 230584300921369395)` với giá trị rất lớn

==> Đây là nơi diễn ra lổ hổng mới: **Integer Overflow** 

    Lỗ hổng này là khi biến mang giá trị lớn hơn giá trị được định ra bởi kiểu dữ liệu của nó

**Đánh giá:**
* `ulong id` nên id chỉ nhận giá trị **dương**, muốn write OOB phải gián tiếp biến value `id` < 0
  
* `read(0,users + id * 80,80);` chức năng để overwrite vào memory, xuất phát từ global variable: `<users>`, cấp phát vùng nhớ cho mỗi `id` 80 bytes, truy cập vùng nhớ tại `users + id * 80` 

* Vì sao kiểm tra `if (id < 230584300921369395)`?:
  * ta biết `ulong id` nhận giá trị trong khoảng:
    ```
    0 --> 18,446,744,073,709,551,615 ( 2^64-1 ).
    ```
  * giả sử `id` có thể mang giá trị MAX = `230584300921369395`
  * tính `id * 80` = `230584300921369395 * 80` = `18446744073709551600` xấp xỉ gần giá trị MAX của **unsigned long**. Đây là địa chỉ xa nhất có thể cấp phát cho `id`.

* Vậy lỗi nằm ở Integer Overflow trong phép nhân của `id * 80`
  * Biểu diễn qua hex:
    ```
    id * 80
    = 18446744073709551600
    mod 2^64
    = 0xFFFFFFFFFFFFFFF0
    ```
  * `id * 80` nếu là uint long thì mang giá trị rất lơn như trên.
  * Nhưng trong trường hợp trên, `users + id * 80`, nó đóng vai trò là 1 offset, pointer arithmetic, thì nó sẽ được đưa về kiểu dữ liệu `signed 64-bit`, tương đương:
    ```
    (signed 64-bit) 0xFFFFFFFFFFFFFFF0 = -16 
    ```
  ==> OOB write khả thi

**Notes**: Phần giải thích đây khá là lộn xộn, sẽ tối ưu khi hiểu sâu về vấn đề này hơn
___
**TL;DR**
Lấy `id` lớn nhất, và nó sẽ thành số âm, `read()` sẽ truy cập ngược lại các địa chỉ GOT và overwrite với `win()` 

```c
if (id < 230584300921369395) {      
      printf("Input user \'s name:");   
      read(0,users + id * 80,80);
    }
...
```
* `id` = 230584300921369394
* `id * 80` = 









