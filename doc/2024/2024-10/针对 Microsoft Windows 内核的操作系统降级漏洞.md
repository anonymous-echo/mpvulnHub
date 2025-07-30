#  针对 Microsoft Windows 内核的操作系统降级漏洞   
 信息安全大事件   2024-10-28 19:45  
  
一种新的攻击技术可用于绕过   
Microsoft   
在完全修补的   
Windows   
系统上的驱动程序签名强制 （  
DSE  
），从而导致操作系统 （  
OS  
） 降级攻击。  
  
“这种绕过允许加载未签名的内核驱动程序，使攻击者能够部署自定义   
Rootkit  
，这些   
Rootkit   
可以中和安全控制、隐藏进程和网络活动、保持隐身等等，”  
SafeBreach   
研究员   
Alon Leviev   
在与   
The Hacker News   
分享的一份报告中说。  
  
最新发现建立在早期分析的基础上，该分析揭示了   
Windows   
更新过程中的两个权限提升缺陷（  
CVE-2024-21302   
和   
CVE-2024-38202  
），这些缺陷可能被武器化，用于将最新的   
Windows   
软件回滚到包含未修补安全漏洞的旧版本。  
  
该漏洞以名为   
Windows Downdate   
的工具的形式实现，根据   
Leviev   
的说法，该工具可用于劫持   
Windows   
更新进程，以在关键操作系统组件上制作完全无法检测、持续且不可逆的降级。  
  
这可能会产生严重的后果，因为它为攻击者提供了比自带易受攻击的驱动程序   
（  
BYOVD  
） 攻击更好的替代方案，允许他们降级第一方模块，包括操作系统内核本身。  
  
Microsoft   
随后分别于   
2024   
年   
8   
月   
13   
日和   
10   
月   
8   
日解决了   
CVE-2024-21302   
和   
CVE-2024-38202  
，作为周二补丁日更新的一部分。  
  
Leviev   
设计的最新方法利用降级工具在完全更新的   
Windows 11   
系统上降级“  
ItsNotASecurityBoundary  
”  
DSE   
绕过补丁。  
  
2024   
年   
7   
月，  
Elastic   
安全实验室研究员   
Gabriel Landau   
首次与   
PPLFault   
一起记录了   
ItsNotASecurityBoundary  
，并将其描述为代号为“错误文件不可变性”的新错误类。  
Microsoft   
在今年   
5   
月早些时候对其进行了修复。  
  
简而言之，它利用争用条件将已验证的安全目录文件替换为包含未签名内核驱动程序的验证码签名的恶意版本，然后攻击者提示内核加载驱动程序。  
  
Microsoft   
的代码完整性机制用于使用内核模式库  
ci.dll  
对文件进行身份验证，然后解析流氓安全目录以验证驱动程序的签名并加载它，从而有效地授予攻击者在内核中执行任意代码的能力。  
  
DSE   
旁路是通过使用降级工具将“  
ci.dll  
”库替换为旧版本 （  
10.0.22621.1376.  
） 来实现的，以撤消   
Microsoft   
实施的补丁。  
  
话虽如此，有一个安全屏障可以防止这种绕过成功。如果基于虚拟化的安全性   
（  
VBS  
） 在目标主机上运行，则目录扫描由安全内核代码完整性   
DLL   
（  
skci.dll  
） 执行，而不是由   
ci.dll   
执行。  
  
但是，值得注意的是，默认配置为不带统一可扩展固件接口   
（  
UEFI  
） 锁的   
VBS  
。因此，攻击者可以通过篡改   
EnableVirtualizationBasedSecurity   
和   
RequirePlatformSecurityFeatures   
注册表项来关闭它。  
  
即使在启用了   
UEFI   
锁定的情况下，攻击者也可以通过将其中一个核心文件替换为无效的对应文件来禁用   
VBS  
。最终，攻击者需要遵循的利用步骤如下：  
- 在   
Windows   
注册表中关闭   
VBS  
，或使   
SecureKernel.exe   
无效  
  
- 将   
ci.dll   
降级到未修补的版本  
  
- 重新启动本机  
  
- 利用   
ItsNotASecurityBoundary DSE   
旁路实现内核级代码执行  
  
唯一失败的情况是当   
VBS   
使用   
UEFI   
锁和“强制”标志打开时，最后一个标志在   
VBS   
文件损坏时会导致启动失败。强制模式是通过注册表更改手动启用的。  
  
“强制设置可防止操作系统加载程序在   
Hypervisor  
、  
Secure Kernel   
或其依赖模块之一无法加载的情况下继续启动，”  
Microsoft   
在其文档中指出。“在启用此模式之前应特别小心，因为如果虚拟化模块出现故障，系统将拒绝启动。”  
  
因此，为了完全缓解攻击，必须使用   
UEFI   
锁启用   
VBS   
并设置强制标志。在任何其他模式下，它使对手可以关闭安全功能、执行   
DDL   
降级并实现   
DSE   
旁路。  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__0" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="-webkit-tap-highlight-color: transparent;outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="-webkit-tap-highlight-color: transparent; outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__1" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;visibility: visible;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);">                   </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100006251" data-ratio="1" data-s="300,640" data-type="png" data-w="1000" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;text-indent: 0em;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: normal;"><br style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
