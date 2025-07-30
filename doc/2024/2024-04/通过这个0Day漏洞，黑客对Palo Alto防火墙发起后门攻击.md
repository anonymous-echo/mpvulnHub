#  通过这个0Day漏洞，黑客对Palo Alto防火墙发起后门攻击   
Zicheng  FreeBuf   2024-04-15 19:11  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38G7UBnfnJe16XngYuoojbSNk1acjWibZiacqEaBAGWAwIqQGYNgqBjD6X0Bkb68ibkkGKKdhrxFXoaQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38G7UBnfnJe16XngYuoojbSSvjAjxqzFuI8vxPNGiaVq11rQscyfCSvX6BGXuZkwibXWKibRIRGV6WtQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9Jc7s5hDG54azmucicCwYCYFmoPUUHXvJZdVMDreRFB7mQr1icpm2MKicyXKwo4dUZJKKRwyh1Dofu1L/640?wx_fmt=svg&from=appmsg "")  
  
左右滑动查看更多  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9Jc7s5hDG54azmucicCwYCYFmoPUUHXvJZdVMDreRFB7mQr1icpm2MKicyXKwo4dUZJKKRwyh1Dofu1L/640?wx_fmt=svg&from=appmsg "")  
  
  
  
  
据BleepingComputer消息，自 3 月 26 日以来，疑似受国家支持的黑客一直在利用 Palo Alto Networks 防火墙中的零日漏洞入侵企业或组织内部网络以窃取数据和凭证。该漏洞被追踪为 CVE-2024-3400。  
  
  
由于该漏洞正被用于攻击，Palo Alto Networks 决定披露该漏洞并发布缓解措施，以便客户在补丁完成之前保护自己的设备。据悉，补丁已于 4 月 14 日发布。  
  
  
发现该零日漏洞的 Volexity 公司在公布的报告中提供了更多细节，该公司以 UTA0218 为代号跟踪这一恶意活动，并根据开发和利用这种性质的漏洞所需的资源、该行为者所针对的受害者类型，以及安装 Python 后门和进一步访问受害者网络所显示的能力，评估认为 UTA0218 极有可能是受国家支持的攻击者在实施攻击。  
  
  
Volexity 称，它于 2024 年 4 月 10 日首次在 Palo Alto Networks PAN-OS 的 GlobalProtect 功能中检测到零日漏洞利用，并向供应商通报了这一活动。第二天，Volexity 观察到另一起对同一零日漏洞进行了「相同的利用」，创建了一个反向Shell，回到攻击者的基础架构，并将更多有效载荷下载到设备上。  
  
  
该公司的进一步调查表明，攻击者至少从 3 月 26 日开始利用 CVE-2024-3400 零日漏洞，但直到 4 月 10 日才部署有效载荷。  
  
  
其中一个已安装的有效载荷是一个名为「Upstyle」的定制植入程序，专为 PAN-OS 设计，可作为后门在被入侵设备上执行命令。该后门通过一个 Python 脚本安装，该脚本会在"/usr/lib/python3.6/site-packages/system.pth "中创建一个路径配置文件。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38G7UBnfnJe16XngYuoojbS6g8PK5XG23NiciaX3paUpWjlgSJtwPrnbdrxibR5V6Qxq59x4x0vh99qQ/640?wx_fmt=jpeg&from=appmsg "")  
  
用于安装后门的初始 Python 有效负载  
  
  
根据 Python 文档，Python 使用路径配置文件为 sys.path 变量添加额外的目录，该变量用于搜索要加载的模块。但如果 .pth 文件以 Import 开头，后面跟着空格或制表符，那么每次 Python 启动时都会执行以下代码。  
  
system.pth 文件就是 Upstyle 后门，Volexity 称它会监控网络服务器的访问日志，以提取要执行的 base64 命令。下图说明了 Upstyle 后门的运行方式。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38G7UBnfnJe16XngYuoojbSYQ3SVjxNCKBr3eFItOlt8XPMbju4Tppa7jxticiajywFia14OMh3iciciamQ/640?wx_fmt=jpeg&from=appmsg "")  
  
pstyle后门运作方式  
  
  
除后门外，Volexity 还观察到攻击者部署了其他有效载荷，以启动反向Shell、渗出 PAN-OS 配置数据、删除日志文件、部署名为 GOST 的 Golang 隧道工具。  
  
  
Volexity还观察到攻击者转向内部网络以窃取敏感的 Windows 文件，如「活动目录数据库 (ntds.dit)、密钥数据 (DPAPI) 和 Windows 事件日志 (Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx)」。  
  
  
此外，攻击者还窃取了特定目标设备上的 Google Chrome 和 Microsoft Edge 文件，包括登录数据、Cookie 和本地状态。这些文件包含保存的凭据和身份验证 cookie，可能允许攻击者破坏其他设备。  
  
  
Volexity 称有两种方法可用于检测 Palo Alto Networks 防火墙是否被入侵。其中一种方法目前仍在与 Palo Alto Networks 合作研究，因此还没有可共享的信息。  
  
  
另一种方法则是：  
  
- 生成技术支持文件，该文件可用于生成包含取证工件的日志，通过分析这些工件可检测到入侵行为。  
  
- 监控Direct-to-IP HTTP 的网络活动、源于 GlobalProtect 设备的 SMB/RDP 连接、包含浏览器数据的 SMB 文件传输，以及从设备向 worldtimeapi[.]org/api/timezone/etc/utc 发送的 HTTP 请求。  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复“加群”，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://www.bleepingcomputer.com/news/security/palo-alto-networks-zero-day-exploited-since-march-to-backdoor-firewalls/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493318&idx=1&sn=02dc5120e00a3d6759be8fcf1b49ec0a&chksm=ce1f1c59f968954fd868b2f8cefa0e8bc5dd703c36dd6db4fc03923be36783a7d4cc791c18b6&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493279&idx=1&sn=d083763c48a2eabb4b9ef4f1e9e71b1a&chksm=ce1f1c00f9689516be84268ea61e623a44cdd020131078b455b68ef05b8582370e25690f2bf1&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
