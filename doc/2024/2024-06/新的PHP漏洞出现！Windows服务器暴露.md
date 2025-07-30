#  新的PHP漏洞出现！Windows服务器暴露   
 信息安全大事件   2024-06-11 21:52  
  
关于影响PHP的一个新的关键安全漏洞的详细信息已经浮出水面，该漏洞可能在某些情况下被用来实现远程代码执行。  
  
该漏洞被追踪为CVE-2024-4577，被描述为CGI参数注入漏洞，影响Windows操作系统上安装的所有版本的PHP。  
  
根据安全研究人员的说法，该缺陷使其有可能绕过对另一个安全缺陷CVE-2012-1823的保护。  
  
安全研究员说：“在实现PHP时，团队没有注意到Windows操作系统中编码转换的最佳匹配功能。”  
  
“这种疏忽允许未经身份验证的攻击者通过特定的字符序列绕过CVE-2012-1823之前的保护。通过参数注入攻击，可以在远程PHP服务器上执行任意代码。”  
  
在2024年5月7日负责任地披露之后，PHP版本8.3.8、8.2.20和8.1.29中提供了该漏洞的修复程序。  
  
DEVCORE警告称，默认情况下，当配置为使用繁体中文、简体中文或日语的区域设置时，Windows上的所有XAMPP安装都会受到攻击。  
  
安全研究员还建议管理员完全放弃过时的PHP CGI，选择更安全的解决方案，如Mod PHP、FastCGI或PHP-FPM。  
  
此外，他也提到：“这个漏洞非常简单，但这也是它有趣的地方。谁能想到，一个在过去12年中经过审查并证明安全的补丁，会因为Windows的一个小功能而被绕过？”  
  
影子服务器基金会在X上分享的一篇帖子中表示，在公开披露后的24小时内，它已经检测到有人试图利用该漏洞攻击其蜜罐服务器。  
  
watchTowr实验室表示，它能够为CVE-2024-4577设计一个漏洞，并实现远程代码执行，这使得用户必须迅速应用最新的补丁。  
  
安全研究员说：“这是一个非常简单的漏洞。”。  
  
“我们敦促那些在受影响的配置中运行的用户——中文（简体或繁体）或日语——尽可能快地执行此操作，因为由于漏洞利用的复杂性较低，因此该漏洞被大规模利用的几率很高。”  
  
  
<table><tbody style="outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__0" data-style="outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__1" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="outline: 0px;line-height: normal;visibility: visible;"><span style="outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br style="outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="outline: 0px;line-height: normal;visibility: visible;"><br style="outline: 0px;visibility: visible;"/></section><section style="outline: 0px;line-height: normal;text-indent: 0em;visibility: visible;"><span style="outline: 0px;color: rgb(0, 0, 0);">                       </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100005691" data-ratio="1" data-s="300,640" data-type="png" data-w="1000" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" style="outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="outline: 0px;line-height: normal;text-indent: 0em;"><span style="outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="outline: 0px;line-height: normal;"><br style="outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
