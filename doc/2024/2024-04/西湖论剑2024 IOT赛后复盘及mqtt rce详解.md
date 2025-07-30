#  西湖论剑2024 IOT赛后复盘及mqtt rce详解   
Nameless_a  看雪学苑   2024-04-19 18:02  
  
```
```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMy3Dreuib0sBBjoicgI0VENYpL3ibqjc2WVTy2TVqib1olXrc2GGlJdEo5Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
今年的西湖论剑IOT部分提供了一块搭载了openwrt的开发板，选手需要对开发板以及提供的Firmware.zip进行分析，回答主办方提出的问题。  
  
  
  
```
```  
  
  
  
由于没有对题目进行截图保留，所以凭借个人以及队友仅存的记忆对赛题进行了整理：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gM7iclZa5ojWR34FZqcyNBOm6MD6zWzK5PaP5OeqZFib5xuDFPaXHLGyIA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
比赛过程中也提供了几个公告：  
  
（1）比赛提供的Firmware.bin为不完整固件请选手不要尝试将其烧录进开发板  
  
（2）mqtt服务存在rce  
  
（3）mqtt的用户名为xhlj2024  
  
（ps：公告（1）是笔者当时修改root密码重打包尝试烧录后放出的XD）  
  
  
  
```
```  
  
###   
### （1）分析复位按钮  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMxdzpSia5icDdknfn4xkUUgNTjSWQmbfUiafPNoKndV49jc1y12Oz3TQ9g/640?wx_fmt=jpeg&from=appmsg "")  
  
  
板子上有个相对比较明显的丝印"PORST"，用万用表测试一下它的常态为高电平：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMLZIXYF8icthRpnZwu8HNQb3e0nWsxibTUNw40RUCib2IQ1UicQsDgDmRNg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
用公对公的杜邦线将它接地后观察开发板成功重置。  
  
### （2）分析flash型号  
  
  
可以从两个地方两个地方获取flash的型号。  
  
  
首先从miscro usb的串口输出中得知flash型号为W25Q256FV：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMz2vQtfPEaRMHsO7ribaquribSN6dU1FW7EDgmaumUibktf0nreZ87pN3A/640?wx_fmt=png&from=appmsg "")  
  
  
然后通过读板子上的丝印也能获取flash型号为w25q256jveq：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMlJC0L7nlh5ANXU1Td89M5EBx5YKvVwZmYibmg3eicHDuawxTWdp7Xusw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
发现这俩居然还不一样，询问主办方说以丝印为准。  
  
  
查阅官方手册可以获取flash的信息，包括flash容量大小：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMwAuAgDJgqDqlyG4VTiaHfJKjcMiac3mFDXzpDjmwcQxPM2ib5cp31lWDw/640?wx_fmt=png&from=appmsg "")  
  
### （3）分析波特率  
  
  
在板子重启的时候按4进入uboot shell，并进行printenv查看boot时候的一些参数。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMrV9IgDh0TOOmE3D0yqZr8Hm5tqibMVv5VGS5lx6esoQXtY13Xibialzxg/640?wx_fmt=png&from=appmsg "")  
  
  
其中就有波特率的信息，为57600。  
  
### (4)8888端口服务分析  
  
  
everthing查找一下"8888"发现在nginx.conf里存在：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMfUKhdv6pIv3Iw7boYdibByP9MPHbCibGKHSchX6BEV2h1u9TWTzE45yw/640?wx_fmt=png&from=appmsg "")  
  
  
发现是对1883也就是mqtt服务的端口转发。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gM4EYzGD1ZsBKRDcIL8bdx6Z7RwSt3fA1m1DHq3dibsWTmJGmX0v0Unqw/640?wx_fmt=png&from=appmsg "")  
###   
### (5)xxx端口密码爆破  
  
  
（4）中查找到了mqtt服务，首先默认这个xxx端口为mqtt的8888，寻找一下mqtt有没有密码。  
  
  
在/etc/mosquitto.conf文件中找到的mqtt的密码文件/etc/pwfile。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMwWNdic9ACwdibykpQPBMdjSSld02g4pkcicLsJicicsSxDdnL5cxZuWWc6Q/640?wx_fmt=png&from=appmsg "")  
  
  
其中的内容为：  
  
```
```  
  
  
(ps:这里的内容是赛后对板子上运行的固件dump下来的内容，并非主办方一开始提供的firmware.bin里的内容)  
  
  
询问misc佬ymnh得知这个是经过sha-512然后base64加盐编码后的内容，密码是7位数字的话写过个爆破脚本就很轻易的能得出答案了。  
  
  
爆破脚本：  
  
  
```
```  
  
  
  
输出：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMjne7gII2qjhztq8s4nK11f3egDhyZicUTwnq5pqvCOIRf242QoIHrVg/640?wx_fmt=png&from=appmsg "")  
  
  
所以mqtt的登陆密码为2758934。  
  
  
到了这里我们再通过给出的固件进行静态分析是很难找到题目6~8的答案的，包括（5）倘若没有主办方的提示，我们也需要对板子进行固件提取获取真实完整的固件才能爆破出答案。  
  
  
总而言之，如果想进一步的解题目前我们还是需要getshell，有两种思路：  
  
（1）通过硬件手段对板子进行固件的dump，修改固件的root密码然后通过uboot的tftp烧写上去从而获得root的shell。  
  
（2）通过一些服务的漏洞来RCE。  
  
  
  
```
```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMlJC0L7nlh5ANXU1Td89M5EBx5YKvVwZmYibmg3eicHDuawxTWdp7Xusw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
通过放大镜可以看出这是wson8的flash，可以通过wson8的芯片夹和ch341编程器进行固件提取。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMlia4p5ep3ibiaOHyo7HlkCOr0CapELTG31UMgiaj0XCeicp10g5RDicRKy9Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
板子上也有和flash有关的引脚以及3v3的测试点，也可以飞八根线出来连到ch341编程器或者树莓派上进行固件提取：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMzibgeFfGR1zlgFlWHhG17n0djLZ8gbPrP1QZf8LeoKO0bVks9DoSicoA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
但无论哪种方式提出来的固件用binwalk解压貌似不太完整。赛后和天枢的badmonkey师傅交流也说提出的固件不太完整，很疑惑不知道为什么，用我的树莓派4b甚至只能读到芯片型号但提不出固件。  
  
  
同时板子上也有jtag口：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gM6QfJib3ccp2OicQ3oyVTSXRRdLBibj1MgFoo1JWIxbiaFeRTFaEadzdSTg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
猜测是连接mcu内部flash的，但是它是一个6pin的非标准jtag，没有jtagulator去读一下的话很难看出哪个是哪个，（但笔者没有jtagulatorQAQ）于是就很难通过jlink进行读取测试。  
  
  
所以就暂时放弃dump固件这一条道路，转去研究RCE。  
  
  
  
```
```  
  
  
  
比赛过程中主办方给出了mqtt存在rce的提示，但当时把八根线飞出来还没提出固件比赛已经濒临结束了。于是只能赛后进行一波研究。  
  
  
赛后比赛方提供了root用户的ssh密码，于是能够连上去查找和mqtt相关的进程：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMoJ43Yu8U78cfqS6McaRYw4QOk3JgrbkA0hk2BPk3maoxQ0YBcRAKnA/640?wx_fmt=png&from=appmsg "")  
  
  
通过和github上的源码进行比对，发现mosquitto的逆向代码和源码差不大多，但mosquitto_sub不太一样，而且它指定了"block"和"logs"这两个topic，感觉就是出题人自己实现的一个进程。  
  
  
通过ida逆向可以找到和这两个topic相关的伪代码：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMq0jVxAYoJjXy6FbgibJujGTv3OQ0LewiaHnrmA0ZeUyuiaLICsk3NtuRw/640?wx_fmt=png&from=appmsg "")  
  
  
可以看出发送消息的JSON格式为：  
  
  
```
```  
  
  
  
而且如果往"logs"这个topic进行publish操作，就会调用system在"/var/log"目录生成和给定的时间戳相关的文件，看上去可以通过构造特殊的时间戳进行命令注入。  
  
  
但"sub_4100dc"这个函数对时间戳进行了格式的校验：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMIMTQBeQqqrhmLeemfDYsmHqoibKJ29a7T7lYDff0juuWiatPKdzO8zYA/640?wx_fmt=png&from=appmsg "")  
  
  
具体的时间戳应该是这样的格式：  
  
  
```
```  
  
  
  
也就是说很难通过时间戳进行注入。  
  
  
再看后面和info相关的处理：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMj7dJWZNZxQNbyC3wdr8KDUGwDz2QApIJFjRwmsPujuj31P08uP0p5Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
可以发现info被进行了两轮操作变成info2，然后对info2有一个检验，通过后info2就被当作参数传入snprintf并最终被命令执行。如果最终的info2是'"\n/bin/sh\n'这种类型的字符串的话，就能实现命令注入。  
  
  
要确定是否能注入，我们需要逆向出info变成info1和info1变成info2进行了什么操作。  
  
  
在逆向大爹void的帮助下，成功恢复了几个关键函数的符号表：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMWXsKlg0t0fj7Xn6ibnZVkj1Rv5W2l4LGLppC8Y6UWEgfk3AnWTQRLyw/640?wx_fmt=jpeg&from=appmsg "")  
  
（ps：其中的SM4Crypt经尝试为SM4的解密过程）  
  
  
filter的过滤：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMStjxluibqyURicM88eq9IsbWquYj6WNP0HZFNhBh7G51UsvmgfTHL8Jw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
但没有过滤"\n"，还是有被注入的可能。  
  
  
倒推一下，输入的info应该是如'"\n/bin/sh\n'这样的字符串先进行sm4加密然后进行base64编码后的过程。  
  
  
值得注意的是，info1也就是输入info的base64解码结果的第一个byte位是控制位ctrl，为了使得ctrl满足要求且后面的memcpy能复制尽可能长的内容，ctrl应该为0xBF。  
  
  
所以构造的info应该是注入字符串进行sm4加密，然后头部加上0xbf再做base64编码后的内容。  
  
  
这里我选择的是通过wget获取msf生成的反弹到宿主6666端口的可执行文件，然后chmod +x后执行的RCE方法，实际测试注入的字符串长度上限为0x20，所以选择了下面三个命令:  
  
  
```
```  
  
  
  
RCE脚本：  
  
  
```
```  
  
  
  
RCE效果：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMkkInnqUweU6B1qsePQCDXly1riaCibO0T6HQb8wxpkgZqUaS6XNQDU9A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
```
```  
  
###   
### （7）5679端口号服务  
  
  
rce后可以登陆上去执行"netstat -pantu"查看端口和对应的进程：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMsBRbWNSIC7JdCvgfhgaSJjdTH3giaiaouShCia5efTrLaKG1V6yHjgYiag/640?wx_fmt=jpeg&from=appmsg "")  
  
  
可以看出5679是network这两个进程。  
  
  
对于（6）和（8）这两个题目，感觉是偏流量分析的题目，就可能传一个tcpdump上去捕获一下流量进行取证，不是笔者太擅长的内容，就浅尝辄止了。  
  
  
  
```
```  
  
  
  
从复盘整个过程下来，今年IOT的题目对硬件和固件的层面分析都有涉及，但短时间能RCE感觉还是很有难度，而且容易陷入提不出固件又RCE不了的尴尬局面（这也是笔者当时遇到的情况），但总而言之整个复盘下来还是收获颇丰。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EgYVUmkuuWqVcU7uXia92gMzNySNrnicYUrZoGxmu0R8l4cjSZEyZJFMXiazcmWKA1icDWbrzVyx39og/640?wx_fmt=png&from=appmsg "")  
  
  
**看雪ID：Nameless_a**  
  
https://bbs.kanxue.com/user-home-943085.htm  
  
*本文为看雪论坛精华文章，由 Nameless_a 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458549820&idx=2&sn=35ccdc46cbcdd18cf16676b17b2ac1f1&chksm=b18d4eb686fac7a03879f4a7f71e67b1c07c45f75436a55eb8c1071bbc96ce3e4700479a4562&scene=21#wechat_redirect)  
  
  
  
**#****往期推荐**  
  
1、[Hypervisor From Scratch：设置我们的第一个虚拟机](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458550630&idx=1&sn=d9cfc18b474ac2d8dea9da4fc77733d3&chksm=b18db1ec86fa38fa45db71b362e082ea6db3fa75bc7602313a1e9d54038fe6b14ea39815306e&scene=21#wechat_redirect)  
  
  
2、[自定义Linker实现分析之路](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458550539&idx=2&sn=e3a883e6de9929783e4920b1ae75802d&chksm=b18db18186fa38971cf9a67439421e62a1c3e1dbeb2cdc974c70ab52186fe92738ed759cf003&scene=21#wechat_redirect)  
  
  
3、[逆向分析VT加持的无畏契约纯内核挂](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458550427&idx=1&sn=399ad869e9f33b368de123b079ca1ff2&chksm=b18db01186fa390707f03c65e957277ed4eb7d250bbce02130ab2d6324c0c4cd9ab837e01802&scene=21#wechat_redirect)  
  
  
4、[阿里云CTF2024-暴力ENOTYOURWORLD题解](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458550386&idx=1&sn=ef197d9dc41313d624d8e297d6cc5f9a&chksm=b18db0f886fa39eedca81d2ebee9e73e689d9db0bfdcb9831d8ebe4a759a5c55f98aff2a771b&scene=21#wechat_redirect)  
  
  
5、[Hypervisor From Scratch - 基本概念和配置测试环境、进入 VMX 操作](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458550275&idx=1&sn=c1b54dc12abbcb627796db92d4f9c2fc&chksm=b18db08986fa399ff036a52bbbe579808ba65111151b31af848628a464efe064e4fbd7c6c1d9&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GJubmq65v9uBFmEJuoJD78321RiaLpp3FAylJv0nbibloCFmXdVe4wvW4ibgnCc6srNI8sGBkX14MpQ/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GJubmq65v9uBFmEJuoJD78321RiaLpp3FAylJv0nbibloCFmXdVe4wvW4ibgnCc6srNI8sGBkX14MpQ/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GJubmq65v9uBFmEJuoJD78321RiaLpp3FAylJv0nbibloCFmXdVe4wvW4ibgnCc6srNI8sGBkX14MpQ/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8GJubmq65v9uBFmEJuoJD78txPhfvI9WpuGSCawCN8NJCgzD16Y0IwdUkaI33Qr3DpwRRuvibgRQOg/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  
