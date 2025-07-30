#  Palo Alto Networks零日防火墙漏洞是由开发人员的基本错误导致的   
原创 Lucian Constanti  信息安全D1net   2024-11-20 08:52  
  
点击上方“**蓝色字体**”，选择 “**设为星标**”  
  
关键讯息，D1时间送达！  
  
Palo Alto Networks防火墙近期被发现存在两个严重漏洞，攻击者可利用这两个漏洞组合，通过PAN-OS管理Web界面绕过身份验证并提升权限，最终获得root权限，完全控制设备。第一个漏洞（CVE-2024-0012）允许攻击者绕过身份验证，第二个漏洞（CVE-2024-9474）则是一个命令注入漏洞，可提升权限至root。目前，Palo Alto已发布修复程序，并建议管理员更新防火墙版本，同时限制管理界面访问权限。安全公司watchTowr的研究人员指出，这些漏洞源于开发过程中的基本错误，并提醒将PAN-OS管理界面暴露在互联网上极为危险。  
  
  
攻击者正在利用两个漏洞的组合，通过PAN-OS管理Web界面绕过身份验证并提升权限，从而在Palo Alto Networks防火墙上获得root权限。  
  
Palo Alto Networks已为其防火墙和虚拟安全设备发布了两个正在被积极利用的漏洞的修复程序。当这两个漏洞同时存在时，攻击者可以在底层的PAN-OS操作系统上以最高权限执行恶意代码，从而完全控制设备。  
  
Palo Alto本月早些时候发布了一份咨询报告，警告客户其正在调查有关PAN-OS基于Web的管理界面中存在潜在远程代码执行(RCE)漏洞的报告，并建议客户遵循推荐的步骤来确保对该界面的安全访问。  
  
在调查过程中，该公司发现这次RCE攻击并非由单一漏洞导致，而是由两个漏洞共同造成。这两个漏洞都已在针对管理界面暴露在互联网上的设备的有限攻击中被利用。  
  
**身份验证绕过和权限提升**  
  
第一个漏洞(CVE-2024-0012)被评为严重级别，评分为10分中的9.3分。通过利用此漏洞，攻击者可以绕过身份验证并获得管理界面的管理权限，从而执行管理操作并更改配置。  
  
尽管这已经很糟糕，但它并不会直接导致整个系统被攻陷，除非这一功能能被用来在底层操作系统上执行恶意代码。  
  
事实证明，攻击者通过第二个漏洞(CVE-2024-9474)找到了这样一种方法，该漏洞允许任何拥有Web界面管理权限的人以root身份(即最高权限)在基于Linux的操作系统上执行代码。  
  
这两个漏洞均影响PAN-OS 10.2、PAN-OS 11.0、PAN-OS 11.1和PAN-OS 11.2版本，目前这些版本都已获得补丁。  
  
**漏洞源于疏忽**  
  
来自安全公司watchTowr的研究人员对Palo Alto的补丁进行了逆向工程，以分析这两个漏洞，并得出结论认为，这些漏洞是开发过程中基本错误的结果。  
  
为了验证用户访问页面是否需要身份验证，PAN OS管理界面会检查请求的X-Pan-Authcheck标头是否设置为on或off。将请求转发到托管Web应用的Apache服务器的Nginx代理服务器会根据请求的路由自动将X-Pan-Authcheck设置为on。在某些情况下，由于位置(例如/unauth/目录)应无需身份验证即可访问，因此X-Pan-Authcheck被设置为off，但除了/unauth/之外，几乎所有其他位置都应将该标头设置为on，这应导致用户被重定向到登录页面。  
  
然而，watchTowr研究人员发现，一个名为uiEnvSetup.php的重定向脚本期望HTTP_X_PAN_AUTHCHECK的值被设置为off，如果请求中提供了这个值，服务器就会接受它。  
  
“我们只需……在X-PAN-AUTHCHECK HTTP请求标头中提供off值，服务器就会贴心地关闭身份验证?!”研究人员在报告中写道，“到了这一步，还有谁会感到惊讶呢?”  
  
第二个漏洞同样源于疏忽，它是一个命令注入漏洞，允许将shell命令作为用户名传递给名为AuditLog.write()的函数，然后该函数将注入的命令传递给pexecute()。但根据研究人员的说法，传递给这个日志函数的负载实际上是另一个功能的结果，而这个功能本身也相当可怕。  
  
该功能允许Palo Alto Panorama设备指定其希望模拟的用户和用户角色，然后无需提供密码或通过双因素身份验证即可为其获得完全认证的PHP会话ID。  
  
综上所述，由于这种软件设计，攻击者可以将shell负载作为用户名字段的一部分来模拟特定用户和角色，然后该负载将被传递给AuditLog.write()，接着传递给pexecute()，最终在底层操作系统上执行。  
  
“令人惊讶的是，这两个漏洞竟然出现在生产设备中，更令人惊讶的是，它们竟然通过Palo Alto设备底层潜伏的大量shell脚本调用而被允许存在，”研究人员在分析中写道。  
  
**缓解措施**  
  
除了将受影响的防火墙更新到最新发布的版本外，管理员还应将管理界面的访问权限限制为仅受信任的内部IP地址。管理界面也可以被隔离在专用的管理VLAN上，或者可以配置为通过所谓的跳转服务器访问，这些服务器需要先进行单独的身份验证。  
  
将PAN-OS管理界面暴露在互联网上是非常危险的，因为这不是在此类设备中发现的第一个，也不太可能是最后一个RCE漏洞。今年早些时候，Palo Alto Networks修补了PAN-OS中的一个零日RCE漏洞(CVE-2024-3400)，该漏洞被国家支持的黑客组织利用过。  
  
Palo Alto Networks的威胁追踪团队正在追踪CVE-2024-0012和CVE-2024-9474的利用活动，并将其命名为Operation Lunar Peak，同时发布了与之相关的入侵指标。  
  
“这次活动主要源自已知为匿名VPN服务代理/隧道流量的IP地址，”该团队表示，“观察到的后利用活动包括交互式命令执行和在防火墙上投放恶意软件，如Webshell。”  
  
版权声明：本文为企业网D1Net编译，转载需在文章开头注明出处为：企业网D1Net，如果不注明出处，企业网D1Net将保留追究其法律责任的权利。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/tkEdnxs9SCm4omlQHkJibq3BQ31wdl2LzWkk2OtH0W7KKy9NeMGnKOa4wiabH53URyyFcsibKw0YFC5NankuuMcOg/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
**2024全国甲方IT选型大会 将于11月29-30日在南京盛大召开，欢迎您扫描下方二维码报名↓↓↓。**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_jpg/01wTAnj9dLfp8QeodicQHA40MuBz8OpZZ7beuE15HFoWGkclGvFicXOBoo0Cfx6fWvVOd5npj5NaE9fNBVnU2YKw/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
（来源：企业网D1Net）  
  
**关于企业网D1net(www.d1net.com)**  
  
  
  
  
国内主流的to B IT门户，同时在运营国内最大的甲方CIO专家库和智力输出及社交平台-信众智(www.cioall.com)。旗下运营19个IT行业公众号(  
微信搜索D1net即可关注)  
  
  
  
如果您在企业IT、网络、通信行业的某一领域工作，并希望分享观点，欢迎给企业网D1Net投稿。  
封面图片来源于摄图网  
  
**投稿邮箱：**  
  
editor@d1net.com  
  
**合作电话：**  
  
010-58221588（北京公司）  
  
021-51701588（上海公司）   
  
**合作邮箱：**  
  
Sales@d1net.com  
  
企业网D1net旗下信众智是CIO（首席信息官）的专家库和智力输出及资源分享平台，有五万多CIO专家，也是目前最大的CIO社交平台。  
  
  
信众智对接CIO为CIO服务，提供数字化升级转型方面的咨询、培训、需求对接等落地实战的服务。也是国内最早的toB共享经济平台。同时提供猎头，选型点评，IT部门业绩宣传等服务。  
  
**扫描 “**  
**二维码**  
**” 可以查看更多详情**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OuQdh6iaViaXaIOY0mjrTgicElErUqymD4icjEneq6YYVpiadU3pDLRHwqFrW9Y2Ht0uKeuIEjO3hDxfiatbI5KcibHIA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
