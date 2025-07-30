#  RADIUS 协议漏洞使网络暴露于 MitM 攻击   
 信息安全大事件   2024-07-09 21:43  
  
网络安全研究人员在   
RADIUS   
网络身份验证协议中发现了一个名为   
BlastRADIUS   
的安全漏洞，攻击者可能会利用该漏洞在某些情况下进行中间   
Mallory-in-the-middle   
（  
MitM  
） 攻击并绕过完整性检查。  
  
“  
RADIUS  
协议允许某些访问请求消息没有完整性或身份验证检查，”  
InkBridge Networks  
首席执行官  
Alan DeKok  
是  
FreeRADIUS  
项目的创建者，他在一份声明中说。  
  
“因此，攻击者可以在不被发现的情况下修改这些数据包。攻击者将能够强制任何用户进行身份验证，并向该用户授予任何授权（  
VLAN  
等）。  
  
RADIUS   
是远程身份验证拨入用户服务的缩写，是一种客户端  
/  
服务器协议，可为连接和使用网络服务的用户提供集中式身份验证、授权和记帐 （  
AAA  
） 管理。  
  
RADIUS   
的安全性依赖于使用   
MD5   
算法派生的哈希值，由于存在碰撞攻击的风险，该算法在   
2008   
年   
12   
月被视为加密破坏。  
  
这意味着访问请求数据包可能会受到所谓的选定前缀攻击，从而可以修改响应数据包，使其通过原始响应的所有完整性检查。  
  
但是，要使攻击成功，攻击者必须能够修改在   
RADIUS   
客户端和服务器之间传输的   
RADIUS   
数据包。这也意味着通过   
Internet   
发送数据包的组织存在该缺陷的风险。  
  
阻止攻击生效的其他缓解因素源于使用   
TLS   
通过   
Internet   
传输   
RADIUS   
流量，以及通过   
Message-Authenticator   
属性提高数据包安全性。  
  
BlastRADIUS  
是一个基本设计缺陷的结果，据说会影响所有符合标准的  
RADIUS  
客户端和服务器，因此使用该协议的互联网服务提供商（  
ISP  
）和组织必须更新到最新版本。  
  
“具体来说，  
PAP  
、  
CHAP  
和  
MS-CHAPv2  
身份验证方法是最脆弱的，”  
DeKok  
说。“  
ISP  
将不得不升级他们的  
RADIUS  
服务器和网络设备。  
  
“任何使用  
MAC  
地址身份验证或  
RADIUS  
进行管理员登录交换机的人都容易受到攻击。使用   
TLS   
或   
IPSec   
可以防止攻击，并且   
802.1X   
（  
EAP  
） 不容易受到攻击。  
  
对于企业，攻击者已经需要访问管理虚拟局域网   
（  
VLAN  
）。此外，如果   
ISP   
通过中间网络（例如第三方外包商）或更广泛的互联网发送   
RADIUS   
流量，则它们可能会受到攻击。  
  
值得注意的是，该漏洞的  
CVSS  
评分为  
9.0  
，特别影响通过互联网发送  
RADIUS / UDP  
流量的网络，因为“大多数  
RADIUS  
流量都是  
'  
明文  
'  
发送的。没有证据表明它在野外被利用。  
  
“这次攻击是  
RADIUS  
协议的安全性长期被忽视的结果，”  
DeKok  
说。  
  
“虽然这些标准长期以来一直建议采取保护措施来防止攻击，但这些保护措施并不是强制性的。此外，许多供应商甚至没有实施建议的保护措施。  
  
<table><tbody style="outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__0" data-style="outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__1" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="outline: 0px;line-height: normal;visibility: visible;"><span style="outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br style="outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="outline: 0px;line-height: normal;visibility: visible;"><br style="outline: 0px;visibility: visible;"/></section><section style="outline: 0px;line-height: normal;text-indent: 0em;visibility: visible;"><span style="outline: 0px;color: rgb(0, 0, 0);">                       </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100005845" data-ratio="1" data-s="300,640" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" data-type="png" data-w="1000" style="outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="outline: 0px;line-height: normal;text-indent: 0em;"><span style="outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="outline: 0px;line-height: normal;"><br style="outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
