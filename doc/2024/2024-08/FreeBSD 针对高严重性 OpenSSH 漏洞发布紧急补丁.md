#  FreeBSD 针对高严重性 OpenSSH 漏洞发布紧急补丁   
 信息安全大事件   2024-08-12 22:14  
  
FreeBSD 项目的维护者发布了安全更新，以解决 OpenSSH 中的一个高严重性缺陷，攻击者可能会利用该漏洞以提升的权限远程执行任意代码。  
  
该漏洞被跟踪为 CVE-2024-7589，CVSS 评分为 7.4（满分 10.0），表明严重性很高。  
  
“sshd（8） 中的信号处理器可能会调用一个不是异步信号安全的日志函数，”根据上周发布的一份公告。  
  
“当客户端未在 LoginGraceTime 秒数（默认为 120 秒）内进行身份验证时，将调用信号处理程序。这个信号处理程序是在 sshd（8） 的特权代码的上下文中执行的，该代码没有被沙箱化，并且以完全的 root 权限运行。  
  
OpenSSH 是安全 shell （SSH） 协议套件的实现，为各种服务（包括远程 shell 访问）提供加密和身份验证的传输。  
  
CVE-2024-7589 被描述为被称为 regreSSHion （CVE-2024-6387） 的问题的“另一个实例”，该问题于上月初曝光。  
  
“在这种情况下，错误的代码来自于FreeBSD中OpenSSH的黑名单集成，”项目维护者说。  
  
“由于在特权 sshd（8） 上下文中调用了非异步信号安全的函数，因此存在一个竞争条件，被确定的攻击者可能能够利用该条件来允许以 root 身份执行未经身份验证的远程代码。”  
  
强烈建议 FreeBSD 用户更新到受支持的版本并重新启动 sshd 以减轻潜在威胁。  
  
在无法更新 sshd（8） 的情况下，可以通过在 /etc/ssh/sshd_config 中将 LoginGraceTime 设置为 0 并重新启动 sshd（8） 来解决竞争条件问题。虽然此更改使守护程序容易受到拒绝服务的攻击，但它可以保护守护程序免受远程代码执行的影响。  
  
<table><tbody style="outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__0" data-style="outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__1" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="outline: 0px;line-height: normal;visibility: visible;"><span style="outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br style="outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="outline: 0px;line-height: normal;visibility: visible;"><br style="outline: 0px;visibility: visible;"/></section><section style="outline: 0px;line-height: normal;text-indent: 0em;visibility: visible;"><span style="outline: 0px;color: rgb(0, 0, 0);">                       </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100005963" data-ratio="1" data-s="300,640" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" data-type="png" data-w="1000" style="outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="outline: 0px;line-height: normal;text-indent: 0em;"><span style="outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="outline: 0px;line-height: normal;"><br style="outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
