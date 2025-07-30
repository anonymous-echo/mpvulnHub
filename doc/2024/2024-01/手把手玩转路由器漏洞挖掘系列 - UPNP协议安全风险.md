#  手把手玩转路由器漏洞挖掘系列 - UPNP协议安全风险   
原创 nil  山石网科安全技术研究院   2024-01-03 17:47  
  
## 1. 基本介绍  
### 1.1 概要  
  
通用即插即用（英语：Universal Plug and Play，简称UPnP）是由“通用即插即用论坛”（UPnP™ Forum）推广的一套网络协议。该协议的目标是使家庭网络（数据共享、通信和娱乐）和公司网络中的各种设备能够相互无缝连接，并简化相关网络的实现。UPnP通过定义和发布基于开放、因特网通讯网协议标准的UPnP设备控制协议来实现这一目标。  
### 1.2 结构组成  
- 设备 - UPNP规范中的最基本单元。代表一个物理设备或包含多个物理设备的逻辑设备。  
  
- 服务 - UPNP规范中的最小控制单元。代表设备提供的服务及调用API接口。  
  
- 控制点 - UPNP所在网络的其他网络中UPNP设备。  
  
### 1.3 协议过程  
- 发现 - 简单发现服务  
  
- 描述 - 通过远程访问URL，XML文件格式显示服务相关信息  
  
- 控制 - 控制信息使用SOAP协议，XML文件格式显示。  
  
## 2. 安全风险  
  
UPnP由于设计上的缺陷而产生的漏洞，这些其中大多数漏洞是由于服务配置错误或实施不当造成的。  
- 路由器设备作为代理，对内网进行渗透测试  
  
- 开启端口映射，访问内部计算机  
  
## 3. 威胁分析  
### 3.1 获得服务控制协议文档(SCPD)  
##### (1) 部分开启服务 - 1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnQLOWYUmE1hHURRhq3n8m4OLBRuPLcbSgJTBWWBX5ZpEw389GjuTkQZjnnicLgWS4GetUHVfGzaXRg/640?wx_fmt=png&from=appmsg "")  
##### (2) 部分开启服务 - 2  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnQLOWYUmE1hHURRhq3n8m4O1pjvtkCMHdc4uWecEY5ZVvWhGC7r9CpuzVKibl3icQiaZiacaMLJLx9sSA/640?wx_fmt=png&from=appmsg "")  
  
开启服务汇总  
```
<serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType>
<serviceId>urn:upnp-org:serviceId:L3Forwarding1</serviceId>
<SCPDURL>/L3F.xml</SCPDURL>
<controlURL>/ctl/L3F</controlURL>
<eventSubURL>/evt/L3F</eventSubURL>

<serviceType>urn:schemas-upnp-org:service:DeviceProtection:1</serviceType>
<serviceId>urn:upnp-org:serviceId:DeviceProtection1</serviceId>
<SCPDURL>/DP.xml</SCPDURL>
<controlURL>/ctl/DP</controlURL>
<eventSubURL>/evt/DP</eventSubURL>

<serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType>
<serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId>
<SCPDURL>/WANCfg.xml</SCPDURL>
<controlURL>/ctl/CmnIfCfg</controlURL>
<eventSubURL>/evt/CmnIfCfg</eventSubURL>

<serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType>
<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
<SCPDURL>/WANIPCn.xml</SCPDURL>
<controlURL>/ctl/IPConn</controlURL>
<eventSubURL>/evt/IPConn</eventSubURL>

<serviceType>urn:schemas-upnp-org:service:WANIPv6FirewallControl:1</serviceType>
<serviceId>urn:upnp-org:serviceId:WANIPv6Firewall1</serviceId>
<SCPDURL>/WANIP6FC.xml</SCPDURL>
<controlURL>/ctl/IP6FCtl</controlURL>
<eventSubURL>/evt/IP6FCtl</eventSubURL
```  
  
ControlURL是与特定服务进行通信的SOAP端点（实质上，该URL的GET / POST将触发操作）。  
### 3.2 服务操作(SOAP)  
  
假若路由器设备SOAP API暴露，我们就可以对设备进行操作，从而绕过防护。  
##### (1) 直接访问控制  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnQLOWYUmE1hHURRhq3n8m4OA05bZgnfclMhctWG8e9YSAiboqialmDoZbEbJLc0ZReSW5CVHCZxB09Q/640?wx_fmt=png&from=appmsg "")  
  
查看具体服务参数及对应接口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnQLOWYUmE1hHURRhq3n8m4OF4eiaLKwcSxgCdRltRCLibjsKC90jxDqYXaiadfF2ukl7j4TGaSnFRS2w/640?wx_fmt=png&from=appmsg "")  
##### (2) 端口映射操作  
  
Miranda是Kali提供的一款基于Python语言的UPNP客户端工具。它可以用来发现、查询和操作UPNP设备，尤其是网关设置。当路由器开启UPNP功能，存在相应的漏洞，就可以通过Miranda进行渗透和控制。  
  
https://github.com/kimocoder/miranda  
  
优势 - 无需认证  
- 将路由器80端口映射在外网端口8443  
  
```
$ upnp> host send 0 WANConnectionDevice WANIPConnection AddPortMapping
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnQLOWYUmE1hHURRhq3n8m4OaicoEYWvRFbuPhEFPlRVfEt9LINrd7sAmbnGXV36hqXSgyIFduVicErw/640?wx_fmt=png&from=appmsg "")  
- 获取设备端口映射列表  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnQLOWYUmE1hHURRhq3n8m4OoH4VItrkQU8PHX0TCQZowqAEjAFlgdf6v9Rh1Xlx1jzUAiboaia6jbHA/640?wx_fmt=png&from=appmsg "")  
- 查看后端端口映射是否添加成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnQLOWYUmE1hHURRhq3n8m4OlKR9d7Mvs6iadcorRaMQedibcuW8gdzwDZxAaXfeZo3EE20puAKlo8Pg/640?wx_fmt=png&from=appmsg "")  
- 查看映射是否成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnQLOWYUmE1hHURRhq3n8m4OHvjKlFtHVEhrMBa0plh0HicDAicHh5sRKica2nNQia5zuOotTouXCRA0BA/640?wx_fmt=png&from=appmsg "")  
## 4. 安全风险  
  
①代理跳板：黑客可以利用路由器的某些服务接管路由器的设备权限。  
  
②内网渗透：边界设备开启UPNP没有做好鉴权处理，会导致攻击者通过该服务队内部网络进行内部渗透。  
## 5. UPNP攻击面  
- 通过SCPD获取服务控制协议文档，查看可利用服务。  
  
- 通过SOAP进行可利用服务操作，获取设备相关敏感信息及相应权限。  
  
## 总结  
  
UPNP协议通过端口转发和映射等功能，简化网络设备的安全配置，提供更方便的用户体验的同时，也带来不小的安全威胁。这就需要管理者花时间去研究如何调整UPnP的设置，而不是通过部署或优化其他安全组件，来提高其所处网络的整体安全态势。  
  
  
