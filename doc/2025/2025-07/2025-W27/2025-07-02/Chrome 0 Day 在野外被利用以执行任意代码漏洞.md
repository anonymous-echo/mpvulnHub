> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI0NzE4ODk1Mw==&mid=2652096366&idx=1&sn=1f824c99f63b3324ed70f4623df29c43

#  Chrome 0 Day 在野外被利用以执行任意代码漏洞  
 网安百色   2025-07-01 11:24  
  
Google 为其 Chrome 浏览器发布了紧急安全更新，解决了攻击者正在积极利用的关键零日漏洞。  
  
该漏洞被跟踪为 CVE-2025-6554，是 Chrome 的 V8 JavaScript 引擎中的一个类型混淆  
漏洞，该引擎支持浏览器跨 Windows、macOS 和 Linux 平台处理 Web 内容的能力。  
  
该漏洞是由谷歌威胁分析小组 （TAG） 的 Clément Lecigne 于 2025 年 6 月 25 日发现的。据谷歌称，攻击者已经在野外开发并部署了针对此漏洞的漏洞，促使公司迅速采取行动。  
  
<table><thead><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf=""><br/></span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf=""><br/></span></section></td></tr></thead><tbody><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="13520026" msthash="37" style="box-sizing: border-box;font-weight: bold;"><span leaf="">CVE 标识符</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">CVE-2025-6554漏洞</span></section></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="12134226" msthash="39" style="box-sizing: border-box;font-weight: bold;"><span leaf="">漏洞类型</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">类型混淆</span></section></td></tr><tr style="box-sizing: border-box;background-color: rgb(240, 240, 240);"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="18772338" msthash="41" style="box-sizing: border-box;font-weight: bold;"><span leaf="">受影响的组件</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">V8 JavaScript 引擎（Chrome 浏览器）</span></section></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><strong msttexthash="15805205" msthash="43" style="box-sizing: border-box;font-weight: bold;"><span leaf="">严重性级别</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid rgba(0, 0, 0, 0);word-break: break-word;"><section><span leaf="">高</span></section></td></tr></tbody></table>  
该漏洞允许远程攻击者通过引诱用户访问恶意构建的网页，在浏览器内存中执行任意读写作。成功利用此漏洞可让攻击者执行任意代码，从而可能导致整个系统受损。  
  
“谷歌知道 CVE-2025-6554 的漏洞在野外存在，”该公司在其安全公告中表示。  
  
国家资助的行为者和网络犯罪分子都高度重视浏览器中的零日漏洞，因为它们可用于间谍活动、数据盗窃和恶意软件的传递。  
  
V8 中的类型混淆缺陷以前与路过式下载攻击、沙盒逃逸以及通过看似良性的网站安装恶意负载有关。  
  
为了减轻威胁，谷歌在 Windows 的 Chrome 版本 138.0.7204.96 和 138.0.7204.97、Mac 的 138.0.7204.92 和 138.0.7204.93 以及 Linux 的 138.0.7204.96 下发布了安全补丁。  
  
此更新将在未来几天和几周内向用户推出。  
  
Google 已限制访问有关该错误的详细技术信息，直到大多数用户应用了修复程序，这是一种旨在防止进一步利用的标准做法。  
  
该公司敦促所有 Chrome 用户立即将他们的浏览器更新到最新版本。  
  
用户可以通过导航到 Chrome 菜单，选择“帮助”，然后选择“关于 Google Chrome”来检查更新。浏览器将自动检查并安装可用的更新。  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
