#  微软在 Perforce Helix 核心服务器中发现4个安全漏洞   
 信息安全大事件   2023-12-19 22:13  
  
微软分析师在对Perforce Helix的游戏开发工作室产品进行安全审查时，发现为游戏、政府、军事和技术等部门广泛使用的源代码管理平台 Perforce Helix Core Server 存在四大漏洞，并于今年 8 月底向 Perforce 报告了这些漏洞，其中一个漏洞被评为严重漏洞。  
  
尽管目前微软表示尚未发现上述四个漏洞被黑客利用的迹象，但还是建议用户尽快升级到   
11 月 7 日发布的 2023.1/2513900 版本，以降低风险。  
  
**Perforce Helix 核心漏洞**  
  
微软发现的四个漏洞主要涉及拒绝服务（DoS）问题，其中最严重的漏洞允许未经认证的攻击者以本地系统（LocalSystem）身份执行任意远程代码。  
  
漏洞概述如下：  
- CVE-2023-5759（CVSS 得分 7.5）：通过 RPC 标头滥用进行未验证（DoS）。  
  
- CVE-2023-45849（CVSS 得分为 9.8）：以 LocalSystem 身份执行未经验证的远程代码。  
  
- CVE-2023-35767 (CVSS 得分为 7.5)：通过远程命令执行未经验证的 DoS。  
  
- CVE-2023-45319 (CVSS 得分 7.5)：通过远程命令执行未验证的 DoS：通过远程命令实施未经验证的 DoS。  
  
其中，CVE-2023-45849 是这组漏洞中最危险的漏洞，它允许未经身份验证的黑客通过 "LocalSystem "执行代码，"LocalSystem "是一个为系统功能保留的高权限 Windows 操作系统账户，通过该账户可以访问本地资源和系统文件、修改注册表设置等。  
  
根据调查，该漏洞的源头是由于服务器对   
user-bgtask RPC 命令的错误处理。在默认配置下，Perforce 服务器允许未经身份验证的黑客以 LocalSystem 身份远程执行任意命令，包括 PowerShell 脚本。  
  
黑客一旦成功利用   
CVE-2023-45849漏洞，就能安装后门、访问敏感信息、创建或修改系统设置，并有可能完全控制运行有漏洞的 Perforce Server 版本的系统。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5RUI2MXsohZxga8jjIx9BMRmoUTCKeW3uelaYOPzSeO1rQtmWwRhEk26gTnWAqmw8cm1FQ4kic5Lw/640?wx_fmt=png&from=appmsg "")  
  
导致命令执行的函数调用链，来源：微软  
  
其余三个漏洞的严重程度较低，但仍应该引起重视。这些漏洞允许DDos攻击，可能造成运行中断，一旦有黑客利用漏洞发起大规模攻击可能会出现重大经济损失。  
  
**保护建议**  
  
除了从供应商的下载门户下载最新版本的   
Helix Core 外，微软还建议采取以下措施：  
- 定期更新第三方软件  
  
- 使用   
VPN 或 IP 允许列表限制访问  
  
- 使用带有代理的   
TLS 证书进行用户验证  
  
- 记录对   
Perforce 服务器的所有访问  
  
- 为   
IT 和安全团队设置崩溃警报  
  
- 使用网络分段遏制漏洞  
  
建议广大用户遵循上述的官方安全指南提示内容。  
  
  
来源：  
FreeBuf.COM  
  
  
<table><tbody style="outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__2" data-style="outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__3" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="outline: 0px;line-height: normal;visibility: visible;"><span style="outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br style="outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="outline: 0px;line-height: normal;"><br style="outline: 0px;"/></section><section style="outline: 0px;line-height: normal;text-indent: 0em;"><span style="outline: 0px;color: rgb(0, 0, 0);">                       </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100005570" data-ratio="1" data-s="300,640" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=png&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1" data-type="png" data-w="1000" style="outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="outline: 0px;line-height: normal;text-indent: 0em;"><span style="outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="outline: 0px;line-height: normal;"><br style="outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
  
