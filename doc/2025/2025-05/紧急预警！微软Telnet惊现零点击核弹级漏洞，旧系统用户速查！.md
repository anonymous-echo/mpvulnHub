#  紧急预警！微软Telnet惊现"零点击"核弹级漏洞，旧系统用户速查！   
原创 赵小龙  红岸基地网络安全   2025-05-07 07:14  
  
### 一、漏洞直击：30秒看懂致命威胁  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/2FibdfL4fGpRm80pQQg4fiay5EUHwnV1YayDtKeLU5EjFhTUoeXKvDZIEothoC9QhBGmDibG9BvaGQnwuRibZVWjWA/640?wx_fmt=png&from=appmsg "")  
  
****  
**漏洞代号**  
：MS-TNAP身份验证倒置  
  
**杀伤力**  
：💣 0Click攻击（无需用户交互）  
  
**攻击效果**  
：黑客可完全绕过密码验证，直取系统管理员权限，如同用万能钥匙打开所有保险库！  
  
**技术深剖**  
：  
  
漏洞根源在于NTLM认证过程的"颠倒乾坤"——服务器竟反向向客户端自证身份！攻击者通过构造特殊数据包（工具telnetbypass.exe已暗流涌动），利用  
SECPKG_CRED_BOTH  
标志与  
ASC_REQ_DELEGATE  
的组合漏洞，让系统上演现实版"指鹿为马"。  
  
### 二、高危红区：这些系统正在"滴血"  
  
✅   
**受影响系统**  
：  
  
▸ Windows 2000  
  
▸ Windows Server 2003/2008/R2  
  
▸ 所有启用Telnet Server的旧版系统  
  
🚨   
**残酷现实**  
：  
  
尽管微软已停止对这些"古董系统"的技术支持，但全球仍有  
**23%**  
的企业因老旧设备依赖被迫使用（数据来源：Cybersecurity Ventures）。工业控制系统、科研设备、银行ATM机成重灾区！  
### 三、生死时速：4步紧急止血方案  
  
1️⃣   
**立即断网**  
  
Win+R  
输入  
services.msc  
→停止并禁用"Telnet Server"服务，操作如同按下核弹发射器的紧急制动钮。  
  
2️⃣   
**协议革命**  
  
连夜部署SSH协议替代Telnet，推荐使用免费开源的OpenSSH，为远程管理套上防弹衣。  
  
3️⃣   
**网络隔离**  
  
在企业防火墙设置"白名单封锁线"：仅允许特定IP通过5870端口访问，非授权流量一律格杀勿论！  
  
4️⃣   
**行为监控**  
  
启用EDR系统设置"三重复核机制"：  
- 实时监测异常NTLM认证请求  
  
- 捕获  
AcceptSecurityContext()  
函数调用  
  
- 拦截含  
ASC_REQ_DELEGATE  
标志流量  
  
## 四、Microsoft Telnet 客户端 MS-TNAP 服务端身份验证令牌漏洞利用（PoC）  
### 概述  
  
该 PoC 演示了 Microsoft Telnet 客户端在 MS-TNAP 身份验证协议中的一个安全漏洞。当客户端通过   
telnet.exe  
 或   
telnet://  
 URI 超链接连接到一个恶意的 Telnet 服务器，并检测到 MS-TNAP 扩展时，服务器可以从客户端提取 NTLM 身份验证数据。  
  
如果攻击者主机位于受信任的网络区域（如内网或信任站点），客户端将  
**自动**  
发送凭证而  
**无需提示**  
，使其非常适合红队场景下用于：  
- NTLM 中继攻击  
  
- 离线密码破解（NetNTLMv1/v2 哈希）  
  
### 漏洞细节  
  
Microsoft Telnet 客户端在连接到不信任区域（如互联网区域）的服务器时，会提示用户确认：  
> “您即将向 Internet 区域中的远程计算机发送密码信息，这可能不安全。是否仍要发送？(y/n)”  
  
  
但如果目标服务器位于受信任区域（如 Intranet 或信任站点）中，或者系统策略被配置为静默身份验证，那么  
**将不会显示此提示**  
，凭据会被直接发送给远程服务器。  
  
攻击者可通过伪造的   
telnet://  
 超链接诱骗受害者点击，从而在没有用户察觉的情况下窃取其凭据。  
### 安全区域行为  
  
Windows 通过 URL 安全区域机制判断 Telnet 连接是否应当自动发送凭据：  
  
<table><thead><tr style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><th style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span cid="n254" mdtype="table_cell" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span md-inline="plain" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span leaf="">安全区域</span></span></span></th><th style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span cid="n255" mdtype="table_cell" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span md-inline="plain" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span leaf="">行为</span></span></span></th></tr></thead><tbody><tr style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><td style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span cid="n257" mdtype="table_cell" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span md-inline="plain" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span leaf="">Internet 区域</span></span></span></td><td style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span cid="n258" mdtype="table_cell" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span md-inline="plain" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span leaf="">提示用户是否发送凭据</span></span></span></td></tr><tr style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><td style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span cid="n260" mdtype="table_cell" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span md-inline="plain" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span leaf="">Intranet 区域</span></span></span></td><td style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span cid="n261" mdtype="table_cell" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span md-inline="plain" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span leaf="">默认</span></span><span md-inline="strong" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><strong style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span md-inline="plain" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span leaf="">静默发送</span></span></strong></span><span md-inline="plain" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span leaf="">凭据</span></span></span></td></tr><tr style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><td style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span cid="n263" mdtype="table_cell" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span md-inline="plain" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span leaf="">信任的站点</span></span></span></td><td style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span cid="n264" mdtype="table_cell" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span md-inline="plain" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span leaf="">默认</span></span><span md-inline="strong" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><strong style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span md-inline="plain" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span leaf="">静默发送</span></span></strong></span><span md-inline="plain" style=" box-sizing: border-box; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; ; "><span leaf="">凭据</span></span></span></td></tr></tbody></table>> ⚠️   
**安全隐患：**  
 许多企业在添加受信任站点时不加协议前缀（如直接添加   
192.168.1.1  
 而非   
http://192.168.1.1  
），会导致该地址所有协议（HTTP/HTTPS/Telnet 等）都被视为可信，间接暴露在攻击面前。  
  
### 受影响系统  
  
几乎  
**所有安装了 Microsoft Telnet 客户端的 Windows 系统**  
均受到影响：  
- Windows NT 4.0 ~ Windows 11  
  
- Windows Server 2003 ~ Server 2025  
  
### 使用方法  
#### 编译  
  
在 Visual Studio 的开发者命令提示符中运行：  
```
```  
  
或使用   
nmake  
：  
```
```  
#### 命令行参数  
```
```  
- -d  
: 设置域名（默认：WIN2K3）  
  
- -s  
: 设置服务器名称（默认：WIN2K3）  
  
- -c  
: 设置自定义 NTLM challenge（8 字节十六进制字符串）  
  
- -o  
: 指定日志文件路径（默认：telnetclientpoc.log）  
  
### 实际效果示例  
  
运行 PoC 后：  
- 程序监听端口 23（Telnet 默认端口）  
  
- 捕获并记录详细的 NTLM Type1/2/3 握手数据  
  
- 自动提取 NetNTLMv2 和 NTLMv1 哈希值，保存至文件   
netntlmv2.hash  
 和   
ntlmv1.hash  
  
### 哈希格式示例（用于 Hashcat）  
```
```  
### 安全建议  
1. **禁止使用 Telnet 客户端**  
（已过时且不安全）  
  
1. **在“受信任站点”中指定完整协议前缀**  
，如   
http://192.168.1.1  
，避免默认信任所有协议  
  
1. **使用防火墙或 IDS/IPS 系统监控 telnet:// URI 使用情况**  
  
1. **加强用户培训**  
，避免点击未知来源的 telnet 链接  
  
###   
### 五、曙光初现：安全界的黑科技驰援  
  
多家顶级安全厂商已放出"临时疫苗"：  
- **Palo Alto Networks**  
：更新IDPS特征库（特征码TELNET-0DAY-2024）  
  
- **CrowdStrike**  
：发布专用检测规则（Falcon规则集v9.81）  
  
- **深信服**  
：紧急上线虚拟补丁防护模块  
  
当你在博物馆看到Windows 2000的展柜时，不该在机房发现它的心跳！此次漏洞犹如一记惊雷，警示所有企业：数字时代的生存法则，从来都是"不进化，即灭亡"。立即行动，莫让企业成为黑客的自动提款机！  
  
  
  
你的企业还存在"古董系统"吗？欢迎留言说出你的迁移难题，网络安全专家在线支招！  
  
（本文部分技术细节已做简化处理，如需完整技术通报请后台留言"漏洞详情"获取PDF文档）+POC检测github路径  
  
  
