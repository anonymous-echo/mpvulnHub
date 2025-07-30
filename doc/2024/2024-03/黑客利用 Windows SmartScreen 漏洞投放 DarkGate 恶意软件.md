#  黑客利用 Windows SmartScreen 漏洞投放 DarkGate 恶意软件   
 安全客   2024-03-14 14:53  
  
DarkGate 恶意软件操作发起的新一波攻击利用现已修复的 Windows Defender SmartScreen 漏洞来绕过安全检查并自动安装虚假软件安装程序。SmartScreen 是一项 Windows 安全功能，当用户尝试运行从 Internet 下载的无法识别或可疑文件时，它会显示警告。被追踪为 CVE-2024-21412 的缺陷是 Windows Defender SmartScreen 缺陷，允许特制的下载文件绕过这些安全警告。  
  
攻击者可以通过创建指向远程 SMB 共享上托管的另一个 .url 文件的 Windows Internet 快捷方式（.url 文件）来利用该缺陷，这将导致最终位置的文件自动执行。  
  
微软于 2 月中旬修复了该漏洞，趋势科技透露，出于经济动机的 Water Hydra 黑客组织此前曾利用该漏洞作为零日漏洞，将其 DarkMe 恶意软件植入交易者的系统中。趋势科技分析师报告称，DarkGate 操作者正在利用相同的缺陷来提高他们在目标系统上成功（感染）的机会。这是该恶意软件的一项重大发展，它与 Pikabot 一起填补了去年夏天 QBot 破坏造成的空白，并被多个网络犯罪分子用于分发恶意软件。  
  
DarkGate 攻击细节  
  
该攻击从一封恶意电子邮件开始，其中包含一个 PDF 附件，其中的链接利用 Google DoubleClick 数字营销 (DDM) 服务的开放重定向来绕过电子邮件安全检查。当受害者点击该链接时，他们会被重定向到托管互联网快捷方式文件的受感染 Web 服务器。此快捷方式文件 (.url) 链接到托管在攻击者控制的 WebDAV 服务器上的第二个快捷方式文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb7n4MV9fPSibwTR7pRfcBTiaZibtrkqVeaD8tFjdpCaTwh6sC5jfmhameKicuspWcZQrRWhgyfXCGvviag/640?wx_fmt=png&from=appmsg "")  
  
“JANUARY-25-2024-FLD765.url”的内容  
  
使用一个 Windows 快捷方式在远程服务器上打开第二个快捷方式可有效利用 CVE-2024-21412 缺陷，导致恶意 MSI 文件在设备上自动执行。  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb7n4MV9fPSibwTR7pRfcBTiaZuCrW6YPBJeVIHJLC93PgoW3zp7WZkibhtX0ymGWl3BoQjyWWCgE1HXw/640?wx_fmt=png&from=appmsg "")  
  
   
“  
gamma.url”的内容  
  
这些 MSI 文件伪装成来自 NVIDIA、Apple iTunes 应用或 Notion 的合法软件。  
  
执行 MSI 安装程序后，涉及“libcef.dll”文件和名为“sqlite3.dll”的加载程序的另一个 DLL 侧载缺陷将解密并在系统上执行 DarkGate 恶意软件负载。  
  
一旦初始化，恶意软件就可以窃取数据，获取额外的有效负载并将其注入正在运行的进程中，执行按键日志记录，并为攻击者提供实时远程访问。  
  
自 2024 年 1 月中旬以来，DarkGate 运营商采用的复杂且多步骤的感染链总结如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb7n4MV9fPSibwTR7pRfcBTiaZvat7WtibjDH2MjGMXZ9xOKYBnHnJGXt0mKtzSeoKOSvfqCYDtKNj1GA/640?wx_fmt=png&from=appmsg "")  
  
攻击链架构  
  
趋势科技表示，该活动采用了 DarkGate 6.1.7 版本，与旧版本 5 相比，该版本具有 XOR 加密配置、新配置选项以及命令和控制 (C2) 值的更新。  
  
DarkGate 6 中提供的配置参数使其操作员能够确定各种操作策略和规避技术，例如启用启动持久性或指定最小磁盘存储和 RAM 大小以规避分析环境。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb7n4MV9fPSibwTR7pRfcBTiaZt2VOWOmiblCxfnMEHJ0OkgGpmkS3kDYR7hBJaqsLyOtLYmX17NDal4A/640?wx_fmt=png&from=appmsg "")  
  
 DarkGate 版本 6 的关键配置设置  
  
减轻这些攻击风险的第一步是应用 Microsoft 的 2024 年 2 月补丁星期二更新，该更新修复了 CVE-2024-21412。  
  
  
**来**  
  
**领**  
  
**资**  
  
**料**  
  
**【免费领】**  
**网络安全专业入门与进阶学习资料，轻松掌握网络安全技能！**  
  
****![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb59ibIezbic1Dob2DsGBgT7WkA3sJgtXriaUGWIocjCgU8JQth19dEFvC8lSOwlp1ALOVnZltOicA1RkA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
