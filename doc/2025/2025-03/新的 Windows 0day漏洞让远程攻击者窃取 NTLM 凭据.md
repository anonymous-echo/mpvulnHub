#  新的 Windows 0day漏洞让远程攻击者窃取 NTLM 凭据   
 网安百色   2025-03-27 19:29  
  
   
   
![图片](https://mmbiz.qpic.cn/mmbiz_png/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vK9ZGS15PBzhF8gRBMk6V7TXMVsSxyqn3vpLuXTg82nHzLRYicg7QtVJQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们吧~  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5LRO0sicappf5yDPBrdDmaw8pdrQ8snqt2fdf0rR8RgG7YxQZ359HaSnIIuK9BT3T33l9rQJialgOQ/640?wx_fmt=jpeg&from=appmsg "")  
  
一个严重漏洞影响从 Windows 7 和 Server 2008 R2 到最新的 Windows 11 v24H2 和 Server 2025 的所有 Windows作系统。  
  
此0day漏洞使攻击者只需让用户在 Windows 资源管理器中查看恶意文件，即可捕获用户的 NTLM 身份验证凭据。  
  
打开共享文件夹、插入包含恶意文件的 USB 驱动器，甚至查看之前从攻击者网站下载此类文件的 Downloads 文件夹时，都可能触发此漏洞。  
  
攻击中利用的 NTLM 漏洞  
  
新发现的漏洞与之前修补的 URL 文件漏洞 （CVE-2025-21377） 具有相似的攻击场景，尽管潜在的技术问题有所不同，并且之前尚未公开记录。  
  
虽然安全研究人员在 Microsoft 发布官方补丁之前隐瞒了具体的漏洞利用细节，但他们确认该漏洞允许通过恶意文件交互窃取凭据。  
  
虽然未归类为严重漏洞，但此 NTLM 凭据盗窃漏洞仍然很危险，尤其是在攻击者已经获得网络访问权限或可以以面向公众的服务器（如 Exchange）为目标来中继被盗凭据的环境中。  
  
安全情报证实，这些类型的漏洞已在实际攻击中被积极利用。  
  
微补丁可用性  
  
安全团队已根据负责任的披露做法向 Microsoft 报告了此漏洞。  
  
在等待官方修复的同时，他们已经开发并发布了通过 0patch 提供的微补丁，这些补丁将暂时缓解该问题。在 Microsoft 实施永久解决方案之前，这些微补丁将保持免费状态。  
  
这是同一研究团队最近发现的第四个零日漏洞，如下所示：  
  
Windows 主题文件问题（已修补为 CVE-2025-21308）  
  
Server 2012 上的 Web 问题标记（仍未修补）  
  
URL 文件 NTLM 哈希泄漏漏洞（修补为 CVE-2025-21377）  
  
此外，2024 年 1 月报告的“EventLogCrasher”漏洞允许攻击者跨域计算机禁用 Windows 事件日志记录，Microsoft 仍未修补该漏洞。  
  
临时安全补丁支持全面的 Windows 版本，包括：  
  
旧版 Windows 版本：  
  
Windows 11 v21H2 和更早的 Windows 10 版本（v21H2、v21H1、v20H2 等）。  
  
具有各种扩展安全更新 （ESU） 状态的 Windows 7。  
  
具有不同 ESU 配置的 Windows Server 2012/2012 R2/2008 R2。  
  
当前支持的 Windows 版本：  
  
Windows 11（v24H2、v23H2、v22H2）  
  
窗户 10 v22H2  
  
Windows Server 2025、2022、2019 和 2016  
  
Windows Server 2012/2012 R2 带 ESU 2  
  
微补丁已自动分发到受影响的系统，并在 PRO 或 Enterprise 账户下安装了 0patch Agent。  
  
要实施这些保护措施，新用户应在 0patch Central 中创建一个免费账户，开始可用的试用版，然后安装并注册 0patch 代理。  
  
该过程不需要重新启动系统，并且补丁部署会自动进行，在等待 Microsoft 的官方修复时提供针对此零日漏洞的即时保护。  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
