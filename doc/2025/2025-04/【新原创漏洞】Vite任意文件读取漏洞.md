#  【新原创漏洞】Vite任意文件读取漏洞   
原创 NS-CERT  绿盟科技CERT   2025-04-10 20:11  
  
**通告编号:NS-2025-0023**  
  
2025-04-10  
  
<table><tbody><tr style="margin: 0px;padding: 0px;"><td data-colwidth="107" valign="top" style="margin: 5px 10px;border: 1px solid #d8d8d8;word-break: break-all;padding:5px 10px;"><strong style="margin: 0px;padding: 0px;"><span style="margin: 0px;padding: 0px;font-size: 14px;"><span leaf="">TA</span></span></strong><strong style="margin: 0px;padding: 0px;"><span style="margin: 0px;padding: 0px;font-size: 14px;"><span leaf="">G：</span></span></strong></td><td valign="top" style="margin: 5px 10px;border: 1px solid #d8d8d8;word-break: break-all;padding:5px 10px;"><p style="vertical-align: initial;line-height: 1.75em;font-size: 14px;color: #000000;padding-top: 0px;padding-bottom: 0px;font-family:微软雅黑;"><strong style="font-size: 17px;caret-color: red;font-family:微软雅黑, sans-serif;"><span style="font-size: 14px;caret-color: red;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;"><span leaf="">Vite、任意文件读取</span></span></strong></p></td></tr><tr style="margin: 0px;padding: 0px;"><td data-colwidth="107" valign="top" style="margin: 5px 10px;border: 1px solid #d8d8d8;word-break: break-all;padding:5px 10px;"><span style="margin: 0px;padding: 0px;color: #000000;"><strong style="margin: 0px;padding: 0px;"><span style="margin: 0px;padding: 0px;font-size: 14px;"><span leaf="">漏洞危害：</span></span></strong></span><span style="margin: 0px;padding: 0px;color: #ff0000;"><strong style="margin: 0px;padding: 0px;"><span style="margin: 0px;padding: 0px;font-size: 14px;"></span></strong></span></td><td valign="top" style="margin: 5px 10px;border: 1px solid #d8d8d8;word-break: break-all;padding:5px 10px;"><p style="vertical-align: initial;"><span style="font-family:微软雅黑, &#34;Microsoft YaHei&#34;;"><strong style="caret-color: red;"><span style="font-size: 14px;font-family:微软雅黑, &#34;Microsoft YaHei&#34;;"><span leaf="">攻击者利用此漏洞，可实现任意文件读取。 </span></span></strong></span></p></td></tr><tr style="margin: 0px;padding: 0px;"><td data-colwidth="107" valign="top" style="margin: 5px 10px;border: 1px solid #d8d8d8;word-break: break-all;padding:5px 10px;"><strong style="margin: 0px;padding: 0px;"><span style="margin: 0px;padding: 0px;font-size: 14px;"><span leaf="">版本：</span></span></strong></td><td valign="top" style="margin: 5px 10px;border: 1px solid #d8d8d8;word-break: break-all;padding:5px 10px;"><strong style="margin: 0px;padding: 0px;"><span style="margin: 0px;padding: 0px;font-size: 14px;"><span leaf="">1.0</span><span leaf=""><br/></span></span></strong></td></tr></tbody></table>  
  
**1**  
  
  
**漏洞概述**  
  
  
近日，绿盟科技CERT监测到Vite发布安全公告，修复了Vite任意文件读取漏洞(CVE-2025-32395)；由于Vite开发服务器在处理URL请求时未对路径进行严格校验，未经身份验证的攻击者可以通过构造特殊的URL绕过路径访问限制，从而读取目标服务器上的任意文件。目前漏洞细节与PoC已公开，请相关用户尽快采取措施进行防护。  
  
Vite是一个现代化的前端开发与构建工具，提供极速的开发服务器启动速度和高效的热更新机制，支持多框架开发，如Vue、React等。因其出色的性能和丰富的插件生态，成为前端开发领域的热门选择。  
  
绿盟科技发现并向官方提交了此漏洞：  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/VvfsuOanecrRnIoQzG2CQAEK1BuM1dcJ6sooY7tRdf6DtPj6ObG5Uw7bAotDE82zTdU0PL8Hwe1c8kIiaFFaN3w/640?wx_fmt=png&from=appmsg "")  
  
  
参考链接：  
  
https://github.com/vitejs/vite/security/advisories/GHSA-356w-63v5-8wf4  
  
  
**SEE MORE →******  
  
**2****影响范围**  
  
**受影响版本**  
  
- 6.2.0 <= Vite <= 6.2.5  
  
- 6.1.0 <= Vite <= 6.1.4  
  
  
  
- 6.0.0 <= Vite <= 6.0.14  
  
- 5.0.0 <= Vite <= 5.4.17  
  
- Vite <= 4.5.12  
  
注：影响将Vite开发服务器暴露到网络（启用--host或配置server.host）且在非Deno（例如Node、Bun）上运行的应用。  
  
  
  
  
**不受影响版本**  
  
- Vite >= 6.2.6  
  
- 6.1.5 <= Vite < 6.2.0  
  
- 6.0.15 <= Vite < 6.1.0  
  
- 5.4.18 <= Vite < 6.0.0  
  
- 4.5.13 <= Vite < 5.0.0  
  
  
  
  
**3****漏洞检测**  
  
**3.1 人工检测**  
  
相关用户可通过查看当前Vite版本是否在受影响范围，对当前服务是否受此漏洞影响进行排查。  
  
通过npm全局安装的可使用下列命令进行查看：  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/VvfsuOanecp7nvZWFiccw7GFTMIYeG2qR05JT6R8nY5S6h8s0SL4uGsib8dn0LAIibD70yl7QZtpogdsgYhzgKuYg/640?wx_fmt=png&from=appmsg "")  
  
也可在终端命令行直接运行vite -v命令查看：  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/VvfsuOanecp7nvZWFiccw7GFTMIYeG2qRRQlAC1fdzHuT3prkW0dv2p2WrbUZs0w7XYoibA4ZAxNDzwaLLsFUVNA/640?wx_fmt=png&from=appmsg "")  
  
  
**4****暴露面风险排查**  
  
**4.1 云端检测**  
  
绿盟科技外部攻击面管理服务（EASM）支持上述漏洞风险的互联网资产排查，目前已帮助服务客户群体完成了暴露面排查与风险验证，在威胁发生前及时进行漏洞预警与闭环处置。  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/VvfsuOanecrRnIoQzG2CQAEK1BuM1dcJibe4icT9ZnwK3vaUm6Kfg45JibAwFnwULwCDV14QWC9x7eVUEU5Ub2o2Q/640?wx_fmt=png&from=appmsg "")  
  
感兴趣的客户可通过联系绿盟当地区域同事或发送邮件至rs@nsfocus.com安排详细的咨询交流。  
  
  
**4.2 本地排查**  
  
绿盟科技CTEM解决方案可以支持主动进行Vite相关资产和漏洞风险的发现和排查：  
  
用户使用外部攻击面发现功能将上述漏洞线索同步至云端，通过资产测绘的方式获取目标单位的受影响资产。  
  
通过指纹识别或PoC扫描进行测绘：  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/VvfsuOanecrRnIoQzG2CQAEK1BuM1dcJRNGjrFbBuAb7hXIP9eJkpjzXGSPthr6vCs8ssC1WmJhIp5y8C3CWbw/640?wx_fmt=png&from=appmsg "")  
  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/VvfsuOanecrRnIoQzG2CQAEK1BuM1dcJGbjlKAsaBKbW7l4ibrKpBKvy3Ehptv6CYbjluLULDPoCdtFDRneMBqw/640?wx_fmt=png&from=appmsg "")  
  
**5****漏洞防护**  
  
**5.1 官方升级**  
  
目前官方已发布新版本修复此漏洞，请受影响的用户尽快升级防护，下载链接：https://github.com/vitejs/vite/releases  
  
  
**5.2 临时防护措施**  
  
若相关用户暂时无法进行升级操作，可在不影响业务的前提下，通过对Vite开发服务器进行访问限制来临时缓解。  
  
  
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
  
  
