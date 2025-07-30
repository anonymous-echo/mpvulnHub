#  TP-Link 游戏路由器漏洞使用户面临远程代码攻击   
 信息安全大事件   2024-05-29 20:03  
  
TP-Link Archer C5400X 游戏路由器  
中披露了一个严重性最高的安全漏洞，该漏洞可能通过发送特制请求在易受攻击的设备上导致远程代码执行。  
  
该漏洞被跟踪为  
CVE-2024-5035，CVSS  
   
分数为   
10.0  
。它会影响路由器固件的所有版本，包括   
1_1.1.6   
及之前版本。它已在   
2024   
年   
5   
月   
24   
日发布的版本  
   
1_1.1.7  
   
中进行了修补。  
  
“  
通过成功利用此漏洞，未经身份验证的远程攻击者可以在具有提升权限的设备上获得任意命令执行，  
”  
德国网络安全公司  
ONEKEY  
在周一发布的一份报告中表示。  
  
该问题的根源在于与射频测试“rftest”  
相关的二进制文件，该二进制文件在启动时启动，并在 TCP   
端口 8888  
、8889   
和 8890   
上公开网络侦听器，从而允许未经身份验证的远程攻击者执行代码。  
  
虽然网络服务被设计为只接受以  
“  
wl  
”  
或  
“  
nvram get  
”  
开头的命令，但  
ONEKEY  
发现，通过在  
shell  
元字符之后注入命令，可以轻而易举地绕过这一限制，如  
;  
、   
&   
、 或   
|  
（例如，  
“wl;  
同上  
;“  
）。  
  
TP-Link   
在版本 1_1.1.7 Build 20240510   
中实施的修复通过丢弃包含这些特殊字符的任何命令来解决漏洞。  
  
“  
似乎在TP-Link  
上提供无线设备配置API  
的需求必须得到快速或廉价的回答，这最终导致他们在网络上暴露了一个所谓的有限外壳，路由器内的客户端可以使用该外壳作为配置无线设备的一种方式，”ONEKEY  
说。  
  
几周前，Delta Electronics DVW W02W2   
工业以太网路由器 （  
CVE-2024-3871  
）   
和 Ligowave   
网络设备 （  
CVE-2024-4999  
）   
也发现了安全漏洞，这些漏洞可能允许远程攻击者以提升的权限获得远程命令执行。  
  
值得注意的是，由于设备不再积极维护，这些缺陷仍未修补，因此用户必须采取适当的措施来限制管理界面的暴露，以减少被利用的可能性。  
  
  
<table><tbody style="outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__0" data-style="outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__1" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="outline: 0px;line-height: normal;visibility: visible;"><span style="outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br style="outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="outline: 0px;line-height: normal;"><br style="outline: 0px;"/></section><section style="outline: 0px;line-height: normal;text-indent: 0em;"><span style="outline: 0px;color: rgb(0, 0, 0);">                       </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100005635" data-ratio="1" data-s="300,640" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" data-type="png" data-w="1000" style="outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="outline: 0px;line-height: normal;text-indent: 0em;"><span style="outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="outline: 0px;line-height: normal;"><br style="outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
  
