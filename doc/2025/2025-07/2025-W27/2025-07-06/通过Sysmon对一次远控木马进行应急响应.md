> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxNzY5MTg1Ng==&mid=2247489900&idx=1&sn=f27b1d8f58576c2dfde3a222087ad08b

#  通过Sysmon对一次远控木马进行应急响应  
 富贵安全   2025-07-05 07:47  
  
東雪蓮  
  
读完需要  
  
5  
  
分钟  
  
速读仅需 2 分钟  
  
日常做**应急响应**  
的时候，很多情况下都会出现**主机无恶意流量**  
的时候，要求上机排查，这种情况下，有安全设备还好，最起码可以看到以前的连接流量，没有安全设备就只能手搓了。  
  
**1、排查思路**  
##      
  
一般遇到这种，我是存在两种思路的，一是通过**翻找主机侧的日志**  
，可以看一下在上次反连的时候，主机存在什么**异常行为**  
，比如创建服务，开启计划任务等等，当然这种排查方式要求你对业务以及微软相关服务比较熟悉，算是比较麻烦的一种解决办法（但是甲方爸爸喜欢）  
  
其次的话，就是今天这种，搞一个**监控脚本**  
，去大批量的记录日志，等待反连流量再次出现。  
  
**2、Sysmon**  
##      
  
搞过应急的 XDM 应该都了解，其实 Windows 默认情况下记录的日志是很片面的，很多的系统事件是默认不记录的，比如程序的启动，DNS 解析等，这时候就需要用到 Sysmon 了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ItX7ia6TFkJl8cm5Otbm98AlpwQRYXdwSvW581IAria9lL9YCVxG6oA3vQ3mHUNOM0hxkc9Bibx72tic7icFRibdCAicQ/640?wx_fmt=png&from=appmsg "")  
  
首先介绍一下 Sysmon，这是微软官方出的一款监控器，引用一下官方解释  
  
系统监视器 (Sysmon) 是一项 Windows 系统服务，也是一个设备驱动程序，一旦安装在系统上，就会在系统重新启动后一直驻留，以监视系统活动并将其记录到 Windows 事件日志中。 它提供有关进程创建、网络连接和文件创建时间更改的详细信息。  
  
再引用一下官方的功能介绍（原谅我的懒 X）  

```
  -记录当前进程和父进程中使用完整命令行创建的进程。


  -记录使用 SHA1（默认）、MD5、SHA256 或 IMPHASH 的进程映像文件的哈希。


  -在进程内创建事件之中包含一个进程 GUID，当 Windows 重新使用进程 ID 时，允许事件的相关性。


  -在每个事件中包含会话 GUID，允许同一登录会话上事件的相关性。


  -记录驱动程序或 DLL 的加载及其签名与哈希。


  -记录磁盘和卷的原始读取访问打开次数。


  -（可选）记录网络连接，包括每个连接的源进程、IP 地址、端口数量、主机名和端口名称。


  -检测文件创建时间的更改，以了解文件真正创建的时间。 修改文件创建时间戳是恶意软件惯用的伎俩来掩盖其轨道。


  -在启动进程之初生成事件，以捕获相当复杂的内核模式恶意软件进行的活动。


```

  
**2.1、使用方法**  
###      
  
一般在你下载之后，里面至少会存在三个文件  
> sysmon64.exeSysmon.exesysmonconfig-export.xml  
  
  
配置方法也很简单，**管理员**  
打开 CMD，运行一下下面两条命令即可  

```
 sysmon64.exe -i   #安装Sysmon
 sysmon64.exe -c sysmonconfig-export.xml   #更新配置


```

  
![](https://mmbiz.qpic.cn/mmbiz_png/ItX7ia6TFkJl8cm5Otbm98AlpwQRYXdwSwn1LNA3PQthY1AVx41HibnPskK428pDZdVvMEWK27qtf1iasSrdHfepg/640?wx_fmt=png&from=appmsg "")  
  
搞好之后，他会在**事件查看器-应用程序和服务日志-Microsoft-Windows**  
下面生成一个**sysmon 文件夹**  
，可以在里面查看我们的 sysmon 日志  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ItX7ia6TFkJl8cm5Otbm98AlpwQRYXdwSYa9dcY9RqQ5vLjVPrRjiaiaBANziaVSgX2jQROKnbBMuu7oHIKkPsQeyw/640?wx_fmt=png&from=appmsg "")  
  
**2.2、实例**  
###      
  
这里举一个实例，这是几个月之前的一次应急，当时情况是**知道 IOC**  
，但是因为当时没有流量反连，所以很难去定位文件，所以就图方便直接上了 sysmon  
  
经过一晚上的等待，再次上机，发现了残留的日志，此处我筛选的事件 ID 是**22**  
 ，去寻找**DNS 解析记录**  
，筛选完之后，直接查找 IOC，就定位到这样一条日志  

```
来源: Microsoft-Windows-Sysmon 
日期: 2025/x/xx 12:56:05 
事件 ID: 22 
任务类别: Dns query (rule: DnsQuery) 
级别: 信息 关键字: 用户: SYSTEM 计算机: XiaoDi 
描述: Dns 
UtcTime: 2025-x-xx 04:56:03.922 
ProcessGuid: {77bc24b4-a4f1-681e-2702-000000008300} 
ProcessId: 23468 
QueryName: de.xxxxxxx.com 
QueryStatus: 0 
Image: C:\Windows\explorer.exe 
User: XiaoDi \26224 
```

  
此时我们就确定到了这个事件的时间以及源程序，但是我们发现源程序是**explorer.exe**  
，那就有可能是有其他驻留项启动的某个木马，往前翻了一两个日志，就看到了**task scheduler**  
字样  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ItX7ia6TFkJl8cm5Otbm98AlpwQRYXdwSpeUFuJGugfKtX3xSzU0gHOUBXVpVPrvhAO1WHaLvKMYAnibbhvqibxwQ/640?wx_fmt=png&from=appmsg "")  
  
熟悉的朋友应该就能看出来，这是 Windows 的**计划任务**  
，此时直接去计划任务里看一下，找一下当时那个时间段执行过的计划任务，最后也是成功定位到计划任务**OneNote 45756**  
  
从而找到源文件**C:\Users\xxxx\AppData\Roaming\str.cmd**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ItX7ia6TFkJl8cm5Otbm98AlpwQRYXdwSxSnPuAMtVYRI27BicJcGHrPJzOfxOPK0pmbXJEImPOZrfeo2tgWJFhQ/640?wx_fmt=png&from=appmsg "")  
  
简单看了一眼这个 cmd 文件，发现还是挺复杂的，不过主要功能如下   

```
混淆启动：通过批处理脚本调用 PowerShell，隐藏执行窗口。
内存解密：使用 AES-256-CBC 解密加密的恶意负载。
反射注入：直接在内存中加载解密的程序集（DLL/EXE），规避文件扫描。
持久化与通信：
创建计划任务或注册表启动项。
连接矿池域名 de.xxxxxxx.com进行加密货币挖矿
```

  
**3、下载地址**  
##      
  
可以直接去**微软官方**  
下载  
  
