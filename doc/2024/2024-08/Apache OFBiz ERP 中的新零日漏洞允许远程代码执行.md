#  Apache OFBiz ERP 中的新零日漏洞允许远程代码执行   
 信息安全大事件   2024-08-06 20:58  
  
Apache OFBiz 开源企业资源规划 （ERP） 系统中披露了一个新的零日预认证远程代码执行漏洞，该漏洞可能允许威胁行为者在受影响的实例上实现远程代码执行。  
  
该漏洞被跟踪为   
CVE-2024-38856，CVSS 评分为 9.8 分（满分 10.0 分）。它会影响 18.12.15 之前的 Apache OFBiz 版本。  
  
“漏洞的根本原因在于身份验证机制中的缺陷，”发现并报告该缺陷的SonicWall在一份声明中表示。  
  
“此漏洞允许未经身份验证的用户访问通常需要用户登录的功能，为远程代码执行铺平了道路。”  
  
CVE-2024-38856 也是 CVE-2024-36104 的补丁绕过，CVE-2024-36104 是一个路径遍历漏洞，已于 6 月初发布 18.12.14 时得到解决。  
  
SonicWall 将该漏洞描述为存在于覆盖视图功能中，该功能将关键端点暴露给未经身份验证的威胁参与者，他们可以利用它通过特别构建的请求实现远程代码执行。  
  
安全研究员Hasib Vhora说：“通过将ProgramExport端点与滥用覆盖视图功能的任何其他不需要身份验证的端点链接在一起，允许对ProgramExport端点进行未经身份验证的访问。  
  
这一发展是在   
OFBiz 中另一个可能导致远程代码执行的关键路径遍历漏洞 （CVE-2024-32113） 之后被积极利用以部署 Mirai 僵尸网络。它于 2024 年 5 月修补。  
  
2023 年 12 月，SonicWall 还披露了同一软件中的一个当时的零日漏洞 （CVE-2023-51467），该漏洞使绕过身份验证保护成为可能。随后，它遭到了大量的开发尝试。  
  
<table><tbody style="outline: 0px;visibility: visible;"><tr class="ue-table-interlace-color-single js_darkmode__0" data-style="outline: 0px; background-color: rgb(28, 28, 28); visibility: visible; color: rgb(205, 205, 205) !important;" style="outline: 0px;background-color: rgb(28, 28, 28);visibility: visible;color: rgb(205, 205, 205) !important;"><td width="557" valign="top" data-style="outline: 0px; word-break: break-all; hyphens: auto; border-color: rgb(76, 76, 76); background-color: rgb(255, 218, 169); visibility: visible; color: rgb(25, 25, 25) !important;" class="js_darkmode__1" style="outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(76, 76, 76);background-color: rgb(255, 218, 169);visibility: visible;color: rgb(25, 25, 25) !important;"><section style="outline: 0px;line-height: normal;visibility: visible;"><span style="outline: 0px;font-size: 12px;visibility: visible;color: rgb(0, 0, 0);">尊敬的读者：<br style="outline: 0px;visibility: visible;"/>感谢您花时间阅读我们提供的这篇文章。我们非常重视您的时间和精力，并深知信息对您的重要性。<br style="outline: 0px;visibility: visible;"/>我们希望了解您对这篇文章的看法和感受。我们真诚地想知道您是否认为这篇文章为您带来了有价值的资讯和启示，是否有助于您的个人或职业发展。<br style="outline: 0px;visibility: visible;"/>如果您认为这篇文章对您非常有价值，并且希望获得更多的相关资讯和服务，我们愿意为您提供进一步的定制化服务。请通过填写我们提供的在线表单，与我们联系并提供您的邮箱地址或其他联系方式。我们将定期向您发送相关资讯和更新，以帮助您更好地了解我们的服务和文章内容。</span></section><section style="outline: 0px;line-height: normal;visibility: visible;"><br style="outline: 0px;visibility: visible;"/></section><section style="outline: 0px;line-height: normal;text-indent: 0em;visibility: visible;"><span style="outline: 0px;color: rgb(0, 0, 0);">                       </span><img class="rich_pages wxw-img" data-backh="106" data-backw="106" data-cropselx1="0" data-cropselx2="119" data-cropsely1="0" data-cropsely2="119" data-galleryid="" data-imgfileid="100005947" data-ratio="1" data-s="300,640" data-type="png" data-w="1000" data-src="https://mmbiz.qpic.cn/sz_mmbiz_png/JqliagemfTA5N8G6ZVujodYTTD7NSaxFG5suXlkibicfoGRzCk6vHhCUBx7ST8b4AxdsFVNNAH4ltePBWX4AxKY0A/640?wx_fmt=other&amp;wxfrom=5&amp;wx_lazy=1&amp;wx_co=1&amp;tp=webp" style="outline: 0px;font-family: 宋体;font-size: 14px;letter-spacing: 0.578px;text-align: center;visibility: visible !important;width: 119px !important;"/></section><section style="outline: 0px;line-height: normal;text-indent: 0em;"><span style="outline: 0px;font-family: 宋体;font-size: 12px;letter-spacing: 0.578px;text-align: center;color: rgb(0, 0, 0);">                               扫描二维码，参与调查</span></section><section style="outline: 0px;line-height: normal;"><br style="outline: 0px;letter-spacing: 0.544px;"/></section></td></tr></tbody></table>  
  
**END**  
  
  
  
点击下方，关注公众号  
  
获取免费咨询和安全服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JqliagemfTA5OxIlGh6IbpxrTJHkcY5DZ4O80nevX4Ev7IHvjZfPZDDMxibSVWk4IdYfaYpuhBgz2iaWS5tzXZLJw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
安全咨询/安全集成/安全运营  
  
专业可信的信息安全应用服务商！  
  
http://www.jsgjxx.com  
  
