
___
### Thông tin:
Kiểm tra file binary:
```python
┌──(kali㉿kali)-[~/CTFs/testCTF/node]
└─$ file node_node_node 
node_node_node: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=be8dfb6255380f87d596a9038ccfe2f3e6d37183, for GNU/Linux 3.2.0, not stripped
```
* `64-bit` binary, dynamically linked
* `not stripped`: tên hàm và biến global giữ nguyên
```python
┌──(kali㉿kali)-[~/CTFs/testCTF/node]
└─$ checksec --file=node_node_node 
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols   FORTIFY  Fortified       Fortifiable     FILE
Partial RELRO   Canary found      NX enabled    No PIE          No RPATH   No RUNPATH   55 Symbols  No     0               3               node_node_node
```
* `Partial RELRO`: có thể overwrite got
* `No PIE`: các địa chỉ là tĩnh

Output binary:

<img width="811" height="127" alt="image" src="https://github.com/user-attachments/assets/62029925-6180-446f-85f7-d683ed2936cc" />

Disassembly code:
```c
void main(void)

{
  undefined8 node;
  long in_FS_OFFSET;
  ulong choice;
  ulong ID;
  ulong ID2;
  undefined8 canary;
  ulong tempID;
  
  canary = *(undefined8 *)(in_FS_OFFSET + 0x28);
  setup();
  memset(nodes,0,128);
LAB_00401800:
  menu();
  scanf(&DAT_00402080,&choice);
  if (choice == 4) {
    exit(0);
  }
  else {
    if (4 < choice) goto LAB_00401a14;
    if (choice == 3) {
      puts("Read from: ");
      scanf(&DAT_00402080,&ID);
      Read_Graph(ID);        ////////////////
      goto LAB_00401800;
    }
    if (choice < 4) {
      if (choice == 1) {
        puts("Id: ");
        scanf(&DAT_00402080,&ID);
        tempID = ID;
        if ((ID < 16) && (*(long *)(nodes + ID * 8) != 0)) {
          puts("Node exists");
        }
        else if (ID < 16) {
          node = Create_Node(ID);
          *(undefined8 *)(nodes + tempID * 8) = node;
          (**(code **)(*(long *)(nodes + ID * 8) + 32))("Created");
        }
        else {
          puts("Invalid id");
        }
      }
      else {
        if (choice != 2) goto LAB_00401a14;
        puts("Node 1: ");
        scanf(&DAT_00402080,&ID);
        puts("Node 2:");
        scanf(&DAT_00402080,&ID2);
        if (((ID < 16) && (ID2 < 16)) && (ID != ID2)) {
          Link_Node(ID,ID2);
        }
        else {
          puts("Invalid");
        }
      }
      goto LAB_00401800;
    }
  }
LAB_00401a14:
  puts("Invalid choice");
  goto LAB_00401800;
}
```
```c

void Read_Graph(long ID)

{
  size_t len;
  long i;
  long *curr_node;
  long in_FS_OFFSET;
  int k;
  int m;
  ulong j;
  long visited [16];
  long *queue [17];
  long canary;
  
  canary = *(long *)(in_FS_OFFSET + 0x28);
  curr_node = visited;
  for (i = 16; i != 0; i = i + -1) {
    *curr_node = 0;
    curr_node = curr_node + 1;
  }
  if (*(long *)(nodes + ID * 8) == 0) {
    puts("Not created node");
  }
  else {
    queue[0] = *(long **)(nodes + ID * 8);
    for (j = 1; curr_node = queue[0], j != 0; j = j - 1) {
      printf("Node: %llu\n",*queue[0]);
      visited[*curr_node] = 1;
      (*(code *)curr_node[4])("Data: ");
      len = strlen((char *)(curr_node + 2));               //////////////////
      read(0,(void *)((long)curr_node + len + 16),16);     //////////////////  shell
      (*(code *)curr_node[4])("Done!");                    //////////////////
      for (k = 0; (ulong)(long)k < (ulong)curr_node[1]; k = k + 1) {
        if (visited[curr_node[(long)k + 5]] == 0) {
          queue[j] = *(long **)(nodes + curr_node[(long)k + 5] * 8);  /////////////////  leak
          j = j + 1;
        }
      }
      for (m = 0; (ulong)(long)m < j; m = m + 1) {
        queue[m] = queue[m + 1];
      }
    }
    puts("Data saved");
  }
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```
* Hàm `Read_Graph()` sử dụng thuật toán BFS (Breadth-first Search) để duyệt qua các node
* Với:
  * `curr_node` trỏ đến node hiện tại
  * `queue[]` là hàng chờ cho các node khác
  * `visited` để đánh dấu xem node được đi qua chưa
* Hàm này là nơi khai thác lỗ hổng OOB 
```c
undefined8 * Create_Node(undefined8 ID)

{
  undefined8 *buff;
  
  buff = (undefined8 *)malloc(168);
  if (buff == (undefined8 *)0x0) {
    buff = (undefined8 *)0x0;
  }
  else {
    *buff = ID;
    buff[1] = 0;
    buff[4] = node_method;
    memset(buff + 2,0,16);
    memset(buff + 5,-1,128);
  }
  return buff;
}
```
* Ta thấy cấu trúc của 1 node trên heap:
  ```c
  heap: node(168 bytes)
  | id | counter | buffer | *(func) | links |
  -------------------------------------------
  | 8  |    8    |   16   |    8    |  128  | (bytes)
  -------------------------------------------
  |                       |         |
  nodes                  +32       +40
  ```
| Offset | Field            | Size       | Notes                                      |
|--------|------------------|------------|--------------------------------------------|
| +0     | ID               | 8 bytes    | Node ID                                    |
| +8     | Counter          | 8 bytes    | Number of links                            |
| +16    | Data Buffer      | 16 bytes   | index + 2                                  |
| +32    | Function Pointer | 8 bytes    | index[4] (node_method)                     |
| +40    | Links Array      | 128 bytes  | Stores IDs of connected nodes              |

```c
void Link_Node(long ID1,long ID2)

{
  int i;
  long node1;
  long node2;
  long val;
  
  if ((*(long *)(nodes + ID1 * 8) == 0) || (*(long *)(nodes + ID2 * 8) == 0)) {
    puts("Invalid");
  }
  else {
    for (i = 0; (ulong)(long)i < *(ulong *)(*(long *)(nodes + ID1 * 8) + 8); i = i + 1) {
      if (ID2 == *(long *)(*(long *)(nodes + ID1 * 8) + 8 + ((long)i + 4) * 8)) {
        exit(0xffffffff);
      }
    }
    node1 = *(long *)(nodes + ID1 * 8);
    node2 = *(long *)(nodes + ID2 * 8);
    val = *(long *)(node1 + 8);
    *(long *)(node1 + 8) = val + 1;
    *(long *)(node1 + 8 + (val + 4) * 8) = ID2;
    val = *(long *)(node2 + 8);
    *(long *)(node2 + 8) = val + 1;
    *(long *)(node2 + 8 + (val + 4) * 8) = ID1;
    (**(code **)(node1 + 32))("Done!");
  }
  return;
}
```
Hàm này không đóng vai trò gì nhiều

___
### Khai thác:
Trong hàm `Read_Graph()`, có đoạn:
```c
len = strlen((char *)(curr_node + 2));               
read(0,(void *)((long)curr_node + len + 16),16);     
(*(code *)curr_node[4])("Done!"); 
```
* `len` kiểm tra độ dài trong buffer tại `curr_node+2` (buffer = 16 bytes)
* `read()` đọc 16 bytes vào vị trí `curr_node + len + 16`,
  
  với `len = 16` ==> `read()` viết vào vị trí `curr_node + 32` (`*(func)`)
  ```c
  heap:
  | id | counter | buffer | *(func) | links |
  -------------------------------------------
  | 8  |    8    |   16   |    8    |  128  | (bytes)
  -------------------------------------------
  |                  /    |    |    |
  |                 /    +32   |   +40
  |                /           |
  curr_node   curr_node+2    curr_node[4]
  ```
* `(*(code *)curr_node[4])` call và chạy `*(func)`.
  
==> nghĩa là `read()` cho phép ta write vào địa chỉ function pointer `*(func)`, và `*(func)` sẽ thực thi nó (với điều kiện len=16). Có thể đẩy shell lên đây.

tiếp trong hàm `Read_Graph()`:
```c
      printf("Node: %llu\n",*queue[0]);    
      visited[*curr_node] = 1;
      ...
      for (k = 0; (ulong)(long)k < (ulong)curr_node[1]; k = k + 1) {
        if (visited[curr_node[(long)k + 5]] == 0) {
          queue[j] = *(long **)(nodes + curr_node[(long)k + 5] * 8);  
          j = j + 1;
        }
      }
```
* đoạn `for loops` là để duyệt các `node` lân cận chưa được thăm, rồi cho vào hàng chờ `queue[]`
* `printf("Node: %llu\n",*queue[0]);` khả năng dùng để leak địa chỉ

Để leak libc, ta sẽ theo các bước:
* Tạo node A, cho data đầy vào buffer (16 bytes)
* Sử dụng OOB, giữ nguyên giá trị `node_method` trong function pointer
* overwrite vào vùng `links` với giá trị âm (đặt ID trong mục node lân cận thành số âm)
* với BFS, duyệt đến node có ID âm với vùng memory: `(nodes + curr_node[(long)k + 5] * 8)` (k < 0)
===> truy nhập đến bảng GOT nằm trước biến global `nodes`
* trong vòng `for` tiếp, `printf()` sẽ in ra địa chỉ GOT 

* Tìm địa chỉ các biến global:

<img width="809" height="128" alt="image" src="https://github.com/user-attachments/assets/54342016-2658-4ee1-996a-2420714b79c4" />
```c
# function pointer <node_method>
└─$ nm node_node_node| grep node_method               
0000000000401276 T node_method
# global variable <nodes>
└─$ nm node_node_node| grep nodes      
00000000004040c0 B nodes
```

Tìm offset cho `id`:

<img width="803" height="382" alt="image" src="https://github.com/user-attachments/assets/654164dd-f282-4459-b7b1-d99004c2055b" />
<img width="807" height="419" alt="image" src="https://github.com/user-attachments/assets/c7189d86-0d1f-4e8f-a610-4e8726918aa3" />

```c
id = -21
```

















