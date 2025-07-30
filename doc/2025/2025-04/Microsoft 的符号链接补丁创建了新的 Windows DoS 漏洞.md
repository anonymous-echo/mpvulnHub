#  Microsoft 的符号链接补丁创建了新的 Windows DoS 漏洞   
 网安百色   2025-04-28 11:30  
  
最近的 Microsoft 安全更新旨在修补关键权限提升漏洞，但无意中引入了一个新的重大缺陷。  
  
此修复程序现在使非管理用户能够有效地阻止所有未来的 Windows 安全更新，从而创建拒绝服务条件。  
  
补丁的这一意外后果凸显了软件安全的复杂性以及防止不可预见的漏洞的持续挑战。  
## 符号链接漏洞和 Microsoft 的修复  
  
2025 年 4 月，Microsoft 发布了安全更新以解决 CVE-2025-21204，该漏洞被评为“重要”，CVSS 3.1 评分为 7.8。  
  
该漏洞涉及 Windows 更新堆栈中文件访问（“链接跟踪”）之前不正确的链接解析，这允许授权攻击者在本地提升权限。  
  
为了缓解此漏洞，Microsoft 实施了一项修复程序，该修复程序会在所有 Windows 系统的系统驱动器上自动创建名为“inetpub”的文件夹，而不管是否安装了 Internet Information Services （IIS）。  
  
Microsoft 明确警告用户不要删除此文件夹，因为它是安全增强功能不可或缺的一部分。  
## 新的 DoS 漏洞  
  
安全研究人员 Kevin Beaumont 发现，此修复引入了拒绝服务漏洞，允许非管理员用户永久阻止 Windows 安全更新。  
  
Beaumont 发现，通过一个简单的命令行作，用户可以创建一个打破更新机制的交汇点（Windows 中的一种文件系统重定向）。  
  
“非管理员（和管理员）用户可以在 c 中创建交界点：”Beaumont 在他的研究中解释道。利用方法只需要标准用户权限和基本的命令行访问权限。  
  
可以通过一个简单的命令来利用该漏洞，该命令在受保护的 inetpub 文件夹和系统文件之间创建一个符号链接：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo4DcyjCs7axg2jicW4YSq8jYCCYibmJNoW8gQdE6FI7T7eTId9eLMfVHcpZgPkRW7Qj00BgtgEfMa0Q/640?wx_fmt=png&from=appmsg "")  
  
此命令将创建一个将 c：\inetpub 重定向到 Windows 记事本的交接点。建立此交接点后，Windows 更新在尝试与文件夹交互时遇到错误，从而导致更新失败或回滚。  
  
“在那之后，2025 年 4 月的 Windows作系统更新（以及未来的更新，除非 Microsoft 修复它）无法安装——它们会出错和/或回滚。所以你就没有安全更新，”Beaumont 指出。  
  
此漏洞最令人担忧的方面是它不需要管理权限即可利用。  
  
Standard 用户可以在许多默认配置的系统上创建这些连接点，从而可能阻止在系统范围内安装关键安全更新。  
  
这不仅仅是暂时的拒绝服务，而是一个持续存在的问题，直到有人手动解决交汇点或重新安装系统为止。  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
