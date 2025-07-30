#  【漏洞通告】微软Telnet Server(MS-TNAP)身份验证绕过漏洞   
原创 NS-CERT  绿盟科技CERT   2025-04-30 09:12  
  
**通告编号:NS-2025-0025**  
  
2025-04-30  
  
<table><tbody><tr style="margin: 0px;padding: 0px;"><td data-colwidth="107" valign="top" style="margin: 5px 10px;border: 1px solid #d8d8d8;word-break: break-all;padding:5px 10px;"><strong style="margin: 0px;padding: 0px;"><span style="margin: 0px;padding: 0px;font-size: 14px;"><span leaf="">TA</span></span></strong><strong style="margin: 0px;padding: 0px;"><span style="margin: 0px;padding: 0px;font-size: 14px;"><span leaf="">G：</span></span></strong></td><td valign="top" style="margin: 5px 10px;border: 1px solid #d8d8d8;word-break: break-all;padding:5px 10px;"><p style="vertical-align: initial;line-height: 1.75em;font-size: 14px;color: #000000;padding-top: 0px;padding-bottom: 0px;font-family:微软雅黑;"><strong style="font-size: 17px;caret-color: red;font-family:微软雅黑, sans-serif;"><span style="font-size: 14px;caret-color: red;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;"><span leaf="">微软、Telnet Server、0day</span></span></strong></p></td></tr><tr style="margin: 0px;padding: 0px;"><td data-colwidth="107" valign="top" style="margin: 5px 10px;border: 1px solid #d8d8d8;word-break: break-all;padding:5px 10px;"><span style="margin: 0px;padding: 0px;color: #000000;"><strong style="margin: 0px;padding: 0px;"><span style="margin: 0px;padding: 0px;font-size: 14px;"><span leaf="">漏洞危害：</span></span></strong></span><span style="margin: 0px;padding: 0px;color: #ff0000;"><strong style="margin: 0px;padding: 0px;"><span style="margin: 0px;padding: 0px;font-size: 14px;"></span></strong></span></td><td valign="top" style="margin: 5px 10px;border: 1px solid #d8d8d8;word-break: break-all;padding:5px 10px;"><p style="vertical-align: initial;"><span style="font-family:微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="caret-color: red;"><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;"><span leaf="">攻击者利用此漏洞，可实现身份验证绕过。</span></span></strong></span></p></td></tr><tr style="margin: 0px;padding: 0px;"><td data-colwidth="107" valign="top" style="margin: 5px 10px;border: 1px solid #d8d8d8;word-break: break-all;padding:5px 10px;"><strong style="margin: 0px;padding: 0px;"><span style="margin: 0px;padding: 0px;font-size: 14px;"><span leaf="">版本：</span></span></strong></td><td valign="top" style="margin: 5px 10px;border: 1px solid #d8d8d8;word-break: break-all;padding:5px 10px;"><strong style="margin: 0px;padding: 0px;"><span style="margin: 0px;padding: 0px;font-size: 14px;"><span leaf="">1.0</span><span leaf=""><br/></span></span></strong></td></tr></tbody></table>  
  
**1**  
  
  
**漏洞概述**  
  
  
近日，绿盟科技CERT监测到网上披露了微软Telnet Server(MS-TNAP)身份验证绕过漏洞，由于Telnet Server在处理NTLM（NT LAN Manager）认证流程时配置错误，在认证握手阶段设置了存在缺陷的SSPI（安全支持提供程序接口）标志；未经身份验证的攻击者可利用Guest账户绕过登录限制，获取包括管理员在内的任意用户访问权限。目前漏洞PoC已公开，请相关用户尽快采取措施进行防护。  
  
漏洞利用：  
  
1、使用特定标志请求双向认证  
  
2、在客户端使用管理员账户的NULL空密码  
  
3、设置特定SSPI标志触发服务器NTLM认证逻辑缺陷  
  
4、发送经过篡改的NTLM Type 3类型消息欺骗服务器  
  
5、绕过身份验证，开启具有管理员权限的Telnet会话  
  
  
**SEE MORE →******  
  
**2****影响范围**  
  
**受影响版本**  
  
- Windows 2000  
  
- Windows XP  
  
- Windows Vista  
  
- Windows 7  
  
- Windows Server 2003  
  
- Windows Server 2008  
  
- Windows Server 2008 R2  
  
  
  
  
**3****暴露面风险排查**  
  
绿盟科技自动化渗透测试工具（EZ）即将支持Telnet Server(MS-TNAP)的识别检测（注：企业版请联系绿盟销售人员获取）。  
  
工具下载链接：https://github.com/m-sec-org/EZ/releases  
  
 新用户请注册M-SEC社区（https://msec.nsfocus.com）申请证书进行使用：  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/VvfsuOanecroToLtWicVj2JldJu7NGUUuYiba8g5iaaibPttwWeqnGwkERibU7OsUl1oytT6Y2fThCKJ4GnHicDXrRHQ/640?wx_fmt=png&from=appmsg "")  
  
  
**4****漏洞防护**  
  
**4.1 临时防护措施**  
  
目前微软官方暂未发布修复措施与补丁，建议相关用户尽快采取下列措施进行临时防护：  
  
1、禁用Telnet服务器系统上的Guest账户；  
  
2、在Telnet服务器上禁用NTLM认证协议；  
  
3、禁用受影响系统上的Telnet Server服务，用SSH等替代；  
  
4、实施网络层过滤，仅允许可信IP和网络访问Telnet服务；  
  
5、应用控制策略阻止未经授权的Telnet客户端连接。  
  
  
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
  
  
