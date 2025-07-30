#  Spring漏洞利用工具 -- Scan-Spring-GO（3月7日）   
sspsec  网络安全者   2024-03-10 00:00  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。  
0x01 工具介绍  
在日常渗透工作中，我遇到很多Spring框架搭建的服务，很多都是Whitelabel Error Page页面，对于Spring的扫描工具github中也有很多项目 python的 java的，但使用go的就很少。因为自身电脑的缘故 使用go编译的工具 加入环境变量中 能让我很方便的使用命令行来使用这些命令行工具，做到打开命令行就能进行 "随手一测"。而像python，java写的类似图形化的工具，我需要进入到相关目录中运行或者双击才能进行使用，对于我这种非常不喜欢找文件的人来说，使用go编译的可执行文件加入环境变量中使用，对我来说是极大的方便。加上最近在学习go语言就想着写一个玩玩，顺便联系一下自己的代码能力。  
0x02 安装与使用  
一、  
对单个目标进行端点探测  
```
ssp -u http://example.com
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccy7AC0zmrq7dkn3F0hiauiaSZKuQyTeonS9q8lpFC4ODyxcDyyCfvw9gGvhVYSOAqJ1dhhc5xhGVOwg/640?wx_fmt=png&from=appmsg "")  
  
二、  
批量目标敏感端点  
```
ssp -uf filename.txt
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccy7AC0zmrq7dkn3F0hiauiaSZqxs6FEibWLs36YMkwYgialAZwf3XO8N0WXMu85Vnz2P36h84XraojbCA/640?wx_fmt=png&from=appmsg "")  
  
三、  
对单个目标进行漏洞探测  
  
如若探测出漏洞 会进入漏洞利用模块  
```
ssp -v http://example.com
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccy7AC0zmrq7dkn3F0hiauiaSZMOR9uJvlVTBvlqQCvpIichzicyAu5la53yn9ASdw7CkBpYe3sZvzyrkw/640?wx_fmt=png&from=appmsg "")  
  
如若探测出漏洞 会进入漏洞利用模块 进行漏洞利用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0JJXjA8siccy7AC0zmrq7dkn3F0hiauiaSZPJgZgP0tj9hwyCWvUdtjYV5j7iaOn5d4cbsPL9VC0jibhR3RDvD3bxzA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 项目链接下载**  
  
1、通过阅读原文，到项目地址下载  
  
2、  
网盘  
链接：https://pan.quark.cn/s/3fe9b9124c21  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/F162Y11BDvR2bmk98tD4YCc4ymabvAWkt7l6LicYt8wOHEmYA0v3VNMc5RM6rUeqsNXiaYGMABM1HJBezia8IWzKg/640?wx_fmt=png&from=appmsg "")  
  
