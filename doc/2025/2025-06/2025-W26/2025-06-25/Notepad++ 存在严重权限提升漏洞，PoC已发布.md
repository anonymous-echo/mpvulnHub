> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650611176&idx=2&sn=d245aba5b4fef5f22ba543ba93694efb

#  Notepad++ 存在严重权限提升漏洞，PoC已发布  
 黑白之道   2025-06-25 01:55  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
Notepad++ 8.8.1版本中发现一个严重的权限提升漏洞，可能导致全球数百万用户面临系统完全被控制的风险。该漏洞编号为CVE-2025-49144，攻击者可通过二进制植入技术获取SYSTEM级权限，目前已有公开的概念验证演示。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38LEqIgxpLGJtu8bNZDFVwZicoV0ibgHPxWTOibyRus4K8Qvhde1j3D9mzJiceRtKP01UibYdJibE8QkQzA/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
**Part01**  
### 漏洞详情  
  
  
该漏洞影响2025年5月5日发布的Notepad++ v8.8.1安装程序，利用未受控的可执行文件搜索路径实现本地权限提升攻击。安全研究人员发现，安装程序会在当前工作目录中搜索可执行依赖项而未经适当验证，这为恶意代码注入创造了可乘之机。  
  
  
由于利用该漏洞所需的用户交互极少，安全风险尤为突出。攻击向量利用了Windows标准DLL搜索顺序机制，使攻击者能够在安装过程中自动加载具有提升权限的恶意可执行文件。  
  
  
**Part02**  
### 攻击方法与概念验证  
###   
  
攻击过程非常简单，充分展示了二进制植入攻击的危险性。攻击者可在Notepad++安装程序所在目录放置恶意可执行文件（如被篡改的regsvr32.exe）。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38LEqIgxpLGJtu8bNZDFVwZibjf8ZiccZZE9nPwia5FmJiaI2FF23EnYnkE24icj3D2Q1Bbf3VrEDaTtrw/640?wx_fmt=jpeg&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
当用户运行安装程序时，系统会自动以SYSTEM权限加载恶意文件，使攻击者获得目标机器的完全控制权。概念验证材料中的Process Monitor日志清晰展示了安装程序在当前目录搜索可执行文件的漏洞行为。  
  
  
**Part03**  
### 影响范围与风险  
  
  
Notepad++在全球拥有大量用户，截至2025年6月，其官网月访问量超过160万次。在IDE和文本编辑器类别中，Notepad++约占1.33%的市场份额，意味着全球可能有数十万安装存在漏洞。  
  
  
考虑到Notepad++在开发者、IT专业人员和各行业普通用户中的普及程度，该漏洞带来的风险尤为严重。企业环境中广泛使用该软件进一步放大了潜在攻击影响，可能导致数据泄露、网络横向移动和系统完全被控制。  
  
  
**Part04**  
### 缓解措施与响应  
###   
  
Notepad++开发团队迅速做出响应，发布8.8.2版本修复该关键漏洞。补丁遵循微软安全加载指南，实现了安全的库加载实践和对可执行依赖项的绝对路径验证。强烈建议用户立即更新至修复版本以消除安全风险。  
  
  
安全专家建议采取额外防护措施，包括从安全隔离目录运行安装程序，以及部署能够检测二进制植入攻击的终端安全解决方案。企业还应考虑实施应用程序白名单和加强对安装过程的监控。  
  
  
该事件凸显了安全软件开发实践的重要性，特别是在可信应用程序的安装程序设计和依赖项加载机制方面。随着网络威胁不断演变，安全社区强调需要对影响广泛使用软件平台的新威胁采取主动漏洞管理和快速响应措施。  
  
  
> **文章来源：freebuf**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
