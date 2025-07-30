#  WinZip 存在远程攻击者执行任意代码漏洞   
 网安百色   2025-02-14 11:29  
  
 ![图片](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vK9ZGS15PBzhF8gRBMk6V7TXMVsSxyqn3vpLuXTg82nHzLRYicg7QtVJQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们吧~  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5Jjch2wQj7HFiaWvjHSr59wraKPZphtCOs5TuoGocFqluj74IxAaictWmKYzB7RxZfeN9r63DCcyBA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
WinZip 新披露的一个严重漏洞（编号为 CVE-2025-1240）使远程攻击者能够通过利用  
格式错误的 7Z 压缩文件在受影响的系统上执行任意代码。  
  
该漏洞在通用漏洞评分系统（CVSS）中的评分为 7.8 分，影响 WinZip 28.0（版本号 16022）及更早版本，用户需更新至 WinZip 29.0 以降低风险。  
## WinZip 漏洞 - CVE-2025-1240  
  
该漏洞是由于在解析过程中对7Z文件数据的验证不充分，使得攻击者可以创建恶意存档，从而导致越界写入内存。  
  
这种破坏可以被用来在WinZip进程的上下文中执行代码，如果与其他漏洞攻击程序搭配使用，可能会对整个系统造成危害。  
#### 关键利用要求：  
- 用户交互（打开恶意的 7Z 文件或访问被篡改的网页）。  
  
- 利用目标WinZip的7Z文件处理组件，压缩数据的一种常见格式。  
  
安全公司Zero Day Initiative （ZDI）详细描述了这一漏洞，称其为ZDI- can -24986，并指出鉴于WinZip的全球用户基数，它可能被广泛滥用。  
#### 影响和风险  
  
  
成功的漏洞攻击会授予攻击者与登录用户相同的权限。这可能会导致：  
- 安装恶意软件或勒索软件。  
  
- 窃取敏感数据。  
  
- 网络内的横向移动。  
  
虽然这种攻击需要用户交互，但 7Z 文件在软件分发和数据共享中的普遍使用增加了网络钓鱼活动成功的可能性。  
#### 缓解措施与补丁  
  
  
WinZip计算在2024年12月发布的29.0版本（Build 16250）中解决了这个缺陷。此次更新还加强了安全措施，包括：  
- 更新了7Z和RAR库，以改进文件验证。  
  
- 简化补丁部署，确保用户及时收到关键补丁。  
  
#### 给用户的建议：  
1. 立即升级到WinZip 29.0通过官方网站或内置更新程序。  
  
1. 避免从不可信的来源打开7Z文件。  
  
1. 启用自动更新以防范未来的漏洞。  
  
该漏洞出现在大量文件解析漏洞攻击之后，包括最近的一个Windows OLE零点击漏洞（CVE-2025-21298），它允许通过恶意电子邮件进行RCE。这些事件强调了主动补丁管理的重要性，特别是对于像WinZip这样广泛使用的实用程序，它每年处理超过10亿个压缩文件。  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
