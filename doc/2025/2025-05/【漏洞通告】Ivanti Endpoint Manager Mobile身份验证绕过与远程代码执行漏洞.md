#  【漏洞通告】Ivanti Endpoint Manager Mobile身份验证绕过与远程代码执行漏洞   
原创 NS-CERT  绿盟科技CERT   2025-05-16 10:44  
  
**通告编号:NS-2025-0029**  
  
2025-05-16  
  
<table><tbody><tr style="margin: 0px;padding: 0px;"><td data-colwidth="107" valign="top" style="margin: 5px 10px;border: 1px solid #d8d8d8;word-break: break-all;padding:5px 10px;"><strong style="margin: 0px;padding: 0px;"><span style="margin: 0px;padding: 0px;font-size: 14px;"><span leaf="">TA</span></span></strong><strong style="margin: 0px;padding: 0px;"><span style="margin: 0px;padding: 0px;font-size: 14px;"><span leaf="">G：</span></span></strong></td><td valign="top" style="margin: 5px 10px;border: 1px solid #d8d8d8;word-break: break-all;padding:5px 10px;"><p style="vertical-align: initial;line-height: 1.75em;font-size: 14px;color: #000000;padding-top: 0px;padding-bottom: 0px;font-family:微软雅黑;"><strong style="font-size: 17px;caret-color: red;font-family:微软雅黑, sans-serif;"><span style="font-size: 14px;caret-color: red;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;"><span leaf="">Ivanti Endpoint Manager Mobile、CVE-2025-4427、CVE-2025-4428</span></span></strong></p></td></tr><tr style="margin: 0px;padding: 0px;"><td data-colwidth="107" valign="top" style="margin: 5px 10px;border: 1px solid #d8d8d8;word-break: break-all;padding:5px 10px;"><span style="margin: 0px;padding: 0px;color: #000000;"><strong style="margin: 0px;padding: 0px;"><span style="margin: 0px;padding: 0px;font-size: 14px;"><span leaf="">漏洞危害：</span></span></strong></span><span style="margin: 0px;padding: 0px;color: #ff0000;"><strong style="margin: 0px;padding: 0px;"><span style="margin: 0px;padding: 0px;font-size: 14px;"></span></strong></span></td><td valign="top" style="margin: 5px 10px;border: 1px solid #d8d8d8;word-break: break-all;padding:5px 10px;"><p style="vertical-align: initial;"><span style="font-family:微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="caret-color: red;"><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;"><span leaf="">攻击者利用上述漏洞，可实现未授权远程代码执行。 </span></span></strong></span></p></td></tr><tr style="margin: 0px;padding: 0px;"><td data-colwidth="107" valign="top" style="margin: 5px 10px;border: 1px solid #d8d8d8;word-break: break-all;padding:5px 10px;"><strong style="margin: 0px;padding: 0px;"><span style="margin: 0px;padding: 0px;font-size: 14px;"><span leaf="">版本：</span></span></strong></td><td valign="top" style="margin: 5px 10px;border: 1px solid #d8d8d8;word-break: break-all;padding:5px 10px;"><strong style="margin: 0px;padding: 0px;"><span style="margin: 0px;padding: 0px;font-size: 14px;"><span leaf="">1.0</span><span leaf=""><br/></span></span></strong></td></tr></tbody></table>  
  
**1**  
  
  
**漏洞概述**  
  
  
近日，绿盟科技CERT监测到Ivanti发布安全公告，修复了Ivanti Endpoint Manager Mobile（EPMM）中的身份验证绕过与远程代码执行漏洞(CVE-2025-4427/CVE-2025-4428)。目前漏洞细节与PoC已公开，且发现在野利用，请相关用户尽快采取措施进行防护。  
  
CVE-2025-4427 ：Ivanti Endpoint Manager Mobile（EPMM）中存在身份验证绕过漏洞，由于Ivanti Endpoint Manager Mobile（EPMM）中的API组件缺少关键功能的身份验证，未经身份验证的攻击者无需有效凭证即可访问受保护的资源。CVSS评分5.3。  
  
CVE-2025-4428 ：Ivanti Endpoint Manager Mobile（EPMM）中存在远程代码执行漏洞，由于Ivanti Endpoint Manager Mobile（EPMM）中的API组件对代码生成的控制不当，经过身份验证的攻击者可通过向目标服务器发送特制的请求，从而实现远程代码执行。CVSS评分7.2。  
  
Ivanti Endpoint Manager Mobile（前身为MobileIron）是Ivanti Endpoint Manager解决方案的移动设备管理（MDM）组件。它提供了专门针对移动设备的管理和安全性控制，使企业能够安全地管理和保护iOS和Android设备。  
  
  
参考链接：  
  
https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Endpoint-Manager-Mobile-EPMM  
  
  
**SEE MORE →******  
  
**2****影响范围**  
  
**受影响版本**  
  
- Ivanti Endpoint Manager Mobile <= 11.12.0.4   
  
- Ivanti Endpoint Manager Mobile <= 12.3.0.1   
  
- Ivanti Endpoint Manager Mobile <= 12.4.0.1   
  
- Ivanti Endpoint Manager Mobile <= 12.5.0.0   
  
  
  
  
**不受影响版本**  
  
- Ivanti Endpoint Manager Mobile = 11.12.0.5   
  
- Ivanti Endpoint Manager Mobile = 12.3.0.2  
  
- Ivanti Endpoint Manager Mobile = 12.4.0.2   
  
- Ivanti Endpoint Manager Mobile = 12.5.0.1   
  
  
  
  
**3**暴露面风险排查  
  
绿盟科技自动化渗透测试工具（EZ）即将支持EPMM的指纹识别排查与CVE-2025-4427/CVE-2025-4428漏洞检测（企业版请联系绿盟销售人员获取）  
  
工具下载链接：https://github.com/m-sec-org/EZ/releases  
  
新用户请注册M-SEC社区（https://msec.nsfocus.com）申请证书进行使用：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/VvfsuOanecr7YjJ7DicsyBibicz8UNkNt7szPOdgr7FVmroSzOI4Ctojias80H5wE5qJ0sG5IhOUjpvrzjxz0hicQlg/640?wx_fmt=png&from=appmsg "")  
  
  
**4****漏洞防护**  
  
**4.1 官方升级**  
  
目前官方已发  
布新版本修复上述漏洞，请受影响的用户尽快升级版本进行防护，下载链接：https://forums.ivanti.com/s/product-downloads。  
  
  
**4.2 临时防护措施**  
  
若相关用户暂时无法进行升级操作，可以使用内置的Portal ACLs功能或WAF等安全设备限制对API的访问，参考官方指南：  
  
http://help.ivanti.com/mi/help/en_us/core/12.x/sys/CoreSystemManager/Access_Control_Lists__Po.htm  
  
  
  
**END**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qR4ORTNELImFwJM2rh6GKbnrurdFA28jJ8chUPyC1U6aW3jhenqEiaXkmeGVmfOnvAJy8j3My901JQ7emHaicYzA/640?wx_fmt=png "")  
           
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qR4ORTNELImFwJM2rh6GKbnrurdFA28jib7icfic0lJJHh3eLRpIXiaia08KqOSEibBsz64vlOH9aqicu3lmjccEeAFWQ/640?wx_fmt=jpeg "")  
          
  
**声明**  
  
本安全公告仅用来描述可能存在的安全问题，绿盟科技不为此安全公告提供任何保证或承诺。由于传播、利用此安全公告所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，绿盟科技以及安全公告作者不为此承担任何责任。              
  
绿盟科技拥有对此安全公告的修改和解释权。如欲转载或传播此安全公告，必须保证此安全公告的完整性，包括版权声明等全部内容。未经绿盟科技允许，不得任意修改或者增减此安全公告内容，不得以任何方式将其用于商业目的。              
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qR4ORTNELImFwJM2rh6GKbnrurdFA28jib7icfic0lJJHh3eLRpIXiaia08KqOSEibBsz64vlOH9aqicu3lmjccEeAFWQ/640?wx_fmt=jpeg "")  
  
  
**绿盟科技CERT**  
  
∣  
微信公众号  
  
![绿盟科技CERT公众号.jpg](https://mmbiz.qpic.cn/mmbiz_jpg/VvfsuOanecp7nvZWFiccw7GFTMIYeG2qRovvvoakj5dzFyEULW2MyQicYvqiaBbJGAWtYcRtpdQD9RY1ZtRauNib9A/640?wx_fmt=jpeg&from=appmsg "绿盟科技CERT公众号.jpg")  
  
![](https://mmbiz.qpic.cn/mmbiz/Hu8hctxHqSW0nSJn8p8OHVEQwHicSwTibFJMBE650AxdzfISoeY8woe2QsgCINIBrccBOOUft2HuU0GsNQWibSG7g/640 "")  
  
长按识别二维码，关注网络安全威胁信息  
  
  
