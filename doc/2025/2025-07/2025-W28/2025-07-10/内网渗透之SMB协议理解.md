> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwODc1NTgyMg==&mid=2247487311&idx=1&sn=371601a97ee123ba3316d98eca40ea48

#  内网渗透之SMB协议理解  
hangchuanin  蓝云Sec   2025-07-10 16:02  
  

```
原文链接：
https://xz.aliyun.com/news/11417
```

## 0x00  
  
在内网利用PTH进行横向移动时常使用的atexec/smbexec/psexec等都有smb协议的身影，而笔者对smb协议理解的也比较粗浅，所以对smb协议进行一个系统的学习，并作个记录。  
## 0x01 SMBv1  
  
CIFS协议是SMB协议的一个特定版本的特定叫法，本质还是SMB协议。其它的SMB协议版本对应有其它的叫法，这个叫法也可以说是方言。  
> 服务器消息块 (SMB) 协议是网络文件共享协议，如 Microsoft Windows中实现的称为 Microsoft SMB 协议。 定义特定版本的协议的消息数据包集称为方言。 常见的 Internet 文件系统 (CIFS) 协议是 SMB 的方言。  
  
  
CIFS协议可以进行客户端和服务器之间传输文件，也可以用于访问集中式打印队列，以及使用命名管道进行进程间通信。  
### 0x010 SMBv1 消息结构  
  
SMBv1消息由三部分构成  
- 固定长度的SMB标头（SMB_Header）  
  
- 可变长度的参数块（SMB_Parameters）  
  
- 可变长度的数据块（SMB_Data）  
  
#### 0x0100 SMB_Header  
  
SMB_Header结构如下  

```
SMB_Header{UCHARProtocol[4];UCHARCommand;SMB_ERRORStatus;UCHARFlags;USHORTFlags2;USHORTPIDHigh;UCHARSecurityFeatures[8];USHORTReserved;USHORTTID;USHORTPIDLow;USHORTUID;USHORTMID;}
```

  
Command位用于表示发送的是什么命令，用命令对应的命令代码表示，比如我要发送SMB_COM_CREATE_DIRECTORY命令，则填充Command位为0x00，SMB_COM_CREATE_DIRECTORY命令的意思是创建一个新目录。其它命令可查看文档  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK4qanadx6YN6xVvm8EDpl4Ox1jnI7UYiaib5mHqriaVBmMgc0ELyU9PmZGBqF1nQwQHF3oyZpPicS5Cdw/640?wx_fmt=png&from=appmsg "")  
  
SMB_Header结构的其它位的含义可以查看文档  
#### 0x0101 SMB_Parameters  
  
SMB_Parameters结构如下  

```
SMB_Parameters{UCHARWordCount;USHORTWords[WordCount](variable);}
```

  
WordCount作为Words数组的宽度决定SMB_Parameters的大小，当WordCount为0时SMB_Parameters大小为1字节。  
#### 0x0102 SMB_Data  
  
SMB_Data结构如下  

```
SMB_Data{
    USHORT ByteCount;
    UCHAR  Bytes[ByteCount] (variable);
}
```

  
WordCount作为Bytes数组的宽度决定SMB_Data的大小，当ByteCount为0时SMB_Data大小为2字节。  
### 0x011 消息概例  
  
SMBv1消息结构可以表示为如下  

```
SMB_Header{UCHARProtocol[4];UCHARCommand;SMB_ERRORStatus;UCHARFlags;USHORTFlags2;USHORTPIDHigh;UCHARSecurityFeatures[8];USHORTReserved;USHORTTID;USHORTPIDLow;USHORTUID;USHORTMID;}SMB_Parameters{UCHARWordCount;USHORTWords[WordCount](variable);}SMB_Data{USHORTByteCount;UCHARBytes[ByteCount](variable);}
```

  
SMB_Header结构中字段都是固定的，而SMB_Parameters和SMB_Data也是遵循其基本结构的，只是不同的消息Words数组和Bytes数组存储的东西不一样而已。  
  
使用如下powershell命令禁用SMBv2/SMBv3，使服务器使用SMBv1协议  

```
Set-ItemProperty-Path&#34;HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters&#34;SMB2-TypeDWORD-Value0-Force
```

  
大概分析一下以下两条cmd命令的SMBv1消息，重点看Command字段值  

```
net use \\10.1.1.1\ipc$ &#34;administrator&#34; /user:&#34;administrator&#34;
dir \\10.1.1.1\c$
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK4qanadx6YN6xVvm8EDpl4OdZCkEIOGCec9VFFdP7mEl4jHoB15cQwaSXmGze2Pf9nPAElZxUgzHA/640?wx_fmt=png&from=appmsg "")  
  
Command字段值按顺序汇总为如下  

```
SMB_COM_NEGOTIATE
SMB_COM_SESSION_SETUP_ANDX
SMB_COM_SESSION_SETUP_ANDX
SMB_COM_TREE_CONNECT_ANDX
SMB_COM_TREE_CONNECT_ANDX
SMB_COM_TRANSACTION2
SMB_COM_TRANSACTION2
SMB_COM_TRANSACTION2
SMB_COM_TRANSACTION2
SMB_COM_TRANSACTION2
SMB_COM_TRANSACTION2
```

  
SMB_COM_NEGOTIATE命令用于协商协议方言。  
  
SMB_COM_SESSION_SETUP_ANDX命令用于配置SMB 会话。如果服务器在用户级访问控制模式下运行，则必须发送至少一个 SMB_COM_SESSION_SETUP_ANDX以执行用户登录到服务器并建立有效的 UID。通过抓包我们也可以看到SMB_COM_SESSION_SETUP_ANDX命令用来进行NTLM身份认证。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK4qanadx6YN6xVvm8EDpl4OIbiaqicunTyOuwETGR58ToHibzUC6ibk1zqYUvFYyPEfZO9ZQVKiaD4ic2QQ/640?wx_fmt=png&from=appmsg "")  
  
SMB_COM_TREE_CONNECT_ANDX命令用于建立到服务器共享的客户端连接。这里是先建立到
```
\\10.1.1.1\ipc$
```

  
共享的客户端连接，然后在dir的时候建立到
```
c$
```

  
的共享  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK4qanadx6YN6xVvm8EDpl4OJV6gCj3BpqibE75yicy9Mo3k82PJrKZibFzuO14EyKvP6Hhlhwq5zjmMw/640?wx_fmt=png&from=appmsg "")  
  
SMB_COM_TRANSACTION2命令请求消息结构如下  

```
SMB_Parameters{UCHARWordCount;Words{USHORTTotalParameterCount;USHORTTotalDataCount;USHORTMaxParameterCount;USHORTMaxDataCount;UCHARMaxSetupCount;UCHARReserved1;USHORTFlags;ULONGTimeout;USHORTReserved2;USHORTParameterCount;USHORTParameterOffset;USHORTDataCount;USHORTDataOffset;UCHARSetupCount;UCHARReserved3;USHORTSetup[SetupCount];}}SMB_Data{USHORTByteCount;Bytes{UCHARName;UCHARPad1[];UCHARTrans2_Parameters[ParameterCount];UCHARPad2[];UCHARTrans2_Data[DataCount];}}
```

  
SMB_COM_TRANSACTION2消息结构中的Setup[SetupCount]表示子命令，SMB_COM_TRANSACTION2命令具体的作用还需要看子命令，也就是看Setup[SetupCount]的值  
  
把SMB_COM_TRANSACTION2命令中的子命令按顺序汇总为如下  

```
TRANS2_QUERY_PATH_INFORMATION
TRANS2_QUERY_PATH_INFORMATION
TRANS2_QUERY_FS_INFORMATION
TRANS2_QUERY_FS_INFORMATION
TRANS2_FIND_FIRST2
TRANS2_QUERY_FS_INFORMATION
```

  
TRANS2_QUERY_PATH_INFORMATION子命令用于获取文件或目录的信息。TRANS2_QUERY_PATH_INFORMATION请求消息中的Trans2_Parameters.InformationLevel的值为
```
QUERY Information Level Codes
```

  
，
```
QUERY Information Level Codes
```

  
决定了响应消息中包含的哪些信息，
```
QUERY Information Level Codes
```

  
有如下值  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK4qanadx6YN6xVvm8EDpl4OHBVS6gSuRGWqj29j9R18163lk8ia0CT51e9onGic6XOScLxNoYaePPcg/640?wx_fmt=png&from=appmsg "")  
  
TRANS2_QUERY_FS_INFORMATION子命令用于请求有关作为服务器上共享基础的对象存储的信息。TRANS2_QUERY_FS_INFORMATION子命令请求消息也有Trans2_Parameters.InformationLevel字段，该字段值为
```
QUERY_FS Information Level Codes
```

  
，
```
QUERY_FS Information Level Codes
```

  
不同返回的内容不同，有如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK4qanadx6YN6xVvm8EDpl4Op9vw3t8SicReRtnANOozIxKywvk7bZiciaI4rpJaZBjv19uVeibTb6OtibA/640?wx_fmt=png&from=appmsg "")  
  
TRANS2_FIND_FIRST2子命令用于搜索目录中的文件或目录。Trans2_Parameters.InformationLevel字段值为
```
FIND Information Level Codes
```

  
，
```
FIND Information Level Codes
```

  
不同返回的内容不同，有如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK4qanadx6YN6xVvm8EDpl4OPscU40l3qn6TYiaz79Prj6Y2YpWPZubzPN3aJHvP8diczeuHabu9mr2w/640?wx_fmt=png&from=appmsg "")  
  
其它SMB_COM_TRANSACTION2命令的子命令可以查看文档  
  
每条命令的细节可以去查文档，文档里面的有命令的作用和对应的消息结构。  
## 0x02 SMBv2  
  
SMBv2是对SMBv1的一个扩展，当SMBv2标头设置了Flags中的SMB2_FLAGS_ASYNC_COMMAND位时，SMBv2标头结构为ASYNC，当SMBv2标头没有设置Flags中的SMB2_FLAGS_ASYNC_COMMAND位时，SMBv2标头结构为SYNC  
  
SMBv2标头结构在SMBv2的所有消息中是固定的，而消息剩余部分的内容随命令不同而不同，SMBv2命令填充到SMBv2标头的Command字段中，SMBv2命令有如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK4qanadx6YN6xVvm8EDpl4OuymH4NwBdVGpic8aSMXbFft19LP3siaBPnEibolbMQ761PyaLgjdu1ibJw/640?wx_fmt=png&from=appmsg "")  
  
使用如下powershell命令开启SMBv2/SMBv3，命令执行完之后需要重启计算机  

```
Set-ItemProperty-Path&#34;HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters&#34;SMB2-TypeDWORD-Value1-Force
```

  
大概分析一下以下两条命令的SMBv2消息  

```
net use \\10.1.1.1\ipc$ &#34;123.com&#34; /user:&#34;administrator&#34;
dir \\10.1.1.1\c$
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK4qanadx6YN6xVvm8EDpl4OyJYMoBUf82PoSlqfLARWkb6ekvxhTl7uESwmUTBAT2SwGYcJRj7S5A/640?wx_fmt=png&from=appmsg "")  
  
Command字段值按顺序汇总为如下  

```
SMB_COM_NEGOTIATE
SMB2 NEGOTIATE
SMB2 SESSION_SETUP
SMB2 SESSION_SETUP
SMB2 TREE_CONNECT
SMB2 IOCTL
SMB2 IOCTL
SMB2 TREE_CONNECT
SMB2 IOCTL
SMB2 CREATE
SMB2 QUERY_INFO
SMB2 CREATE
SMB2 CLOSE
SMB2 CREATE
SMB2 CLOSE
SMB2 QUERY_INFO
```

  
SMB_COM_NEGOTIATE是SMBv1中的命令，是用来协商方言的。  
  
SMB2 NEGOTIATE是SMBv2中的命令，也是用来协商方言的。这里可以看下返回包，服务器选择了SMB2.1方言  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK4qanadx6YN6xVvm8EDpl4OvicUjqjeCRwn998v3QqALgcvUgKWIyiaxdr0DW0ZWN4tULfj98h44nxQ/640?wx_fmt=png&from=appmsg "")  
  
SMB2 SESSION_SETUP命令用以请求新的经过身份验证的会话到服务器。这里就是使用NTLM协议进行身份认证。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK4qanadx6YN6xVvm8EDpl4OjYLNIQxSfvnGia6ukES7Goewx7wGHFMprFa8an2RiaiatTibRwUHqVMKEQ/640?wx_fmt=png&from=appmsg "")  
  
SMB2 TREE_CONNECT命令用来请求服务器上的特定共享。这里连接的是ipc$  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK4qanadx6YN6xVvm8EDpl4OKXRmp7YxGBqDzfUJxPUAK74Lib812ZeJR53ID73NpEXZYd2GfiaQw7gQ/640?wx_fmt=png&from=appmsg "")  
  
SMB2 IOCTL用来发送文件系统控制命令或设备控制命令。  
  
SMB2 CREATE用以请求创建或访问文件。  
  
SMB2 QUERY_INFO用来查询文件、命名管道或基础卷的信息。  
  
SMB2 CLOSE用于关闭SMB2 CREATE命令打开的文件实例。  
## 0x03 SMBv3  
  
SMBv2/SMBv3在官方文档里面是作为SMB 2协议的一个方言存在的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK4qanadx6YN6xVvm8EDpl4OYEKRv861H0Tnqm8efZ7Ipg35cdKZvicSV1wezDk8d2ZQE1tq0AR4azA/640?wx_fmt=png&from=appmsg "")  
  
所以SMBv2的消息结构也是SMBv3的消息结构，当然SMBv3有很多自己的特性，比如SMBv3可以使用SMB2 TRANSFORM_HEADER标头来发送加密消息，也可以使用SMB2 COMPRESSION_TRANSFORM_HEADER标头来发送压缩消息。  
  
我这里连接Windows Server 2012的SMB服务，这时候协商使用的是SMB3.0.2方言  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK4qanadx6YN6xVvm8EDpl4OVo66L6Fl0nTVibeLovJDSYbmZpITE8NyedXOmfeVearj6HXMR5ibwtXQ/640?wx_fmt=png&from=appmsg "")  
  
而对比其它的数据包，结构也基本一致。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IS2RlFMDPK4qanadx6YN6xVvm8EDpl4Oq3RQzF4EoQ8rN7ElIVWBqAsothsbpIf4GhkPekVFChdE9fcut7kkUA/640?wx_fmt=png&from=appmsg "")  
  
文章用到的数据包可以在这里找到。  
## 0x04 参考  
  
Common Internet File System (CIFS) Protocol  
  
Server Message Block (SMB) Protocol Versions 2 and 3  
  
Microsoft SMB 协议和 CIFS 协议概述  
  
在 Windows服务器中启用/禁用SMBv1、SMBv2和SMBv3的方法  
  
0x05最后  
  
蓝云Sec公众号公开交流群，欢迎大家加入！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/IS2RlFMDPK6iciawLkcuSr6qjSL5c4SwDUiabibM5h0HVNcY9e2uGvrnadTYhRric9usiaoBIFRbmHZR2mrpgOIS6SEA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
