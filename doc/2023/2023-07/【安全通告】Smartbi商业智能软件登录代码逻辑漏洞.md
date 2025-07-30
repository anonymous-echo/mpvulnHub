#  【安全通告】Smartbi商业智能软件登录代码逻辑漏洞   
原创 NS-CERT  绿盟科技CERT   2023-07-03 15:28  
  
**通告编号:NS-2023-0029**  
  
2023-07-03  
  
<table><tbody><tr><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top" width="120.33333333333333"><strong><span style="font-size: 14px;">TA</span></strong><strong><span style="font-size: 14px;">G：</span></strong></td><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top" width="415.3333333333333"><p style="vertical-align: inherit;line-height: 1.75em;font-size: 14px;color: rgb(0, 0, 0);font-family: 微软雅黑;"><strong style="caret-color: red;line-height: 1.57em;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;"><span style="font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Smartbi、登录代码逻辑漏洞</span></strong></p></td></tr><tr><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top" width="67"><span style="color: rgb(0, 0, 0);"><strong><span style="font-size: 14px;">漏洞危害：</span></strong></span><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 14px;"></span></strong></span></td><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top" width="395.3333333333333"><p><strong style="caret-color: red;font-size: 14px;line-height: 1.5em;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">攻击者利用此漏洞可造成敏感信息泄露</strong></p></td></tr><tr><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top" width="67"><strong><span style="font-size: 14px;">版本：</span></strong></td><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top" width="395.3333333333333"><strong><span style="font-size: 14px;">1.0<br/></span></strong></td></tr></tbody></table>  
  
**1**  
  
  
**漏洞概述**  
  
  
近日，绿盟科技  
CERT  
监测到  
Smartbi  
官方修复了一个登录代码逻辑漏洞，由于  
Smartbi  
登录代码存在逻辑缺陷，攻击者可利用该漏洞对目标系统进行攻击，最终造成敏感信息泄露。请相关用户尽快采取措施进行防护。  
  
Smartbi是广州思迈特软件有限公司旗下的商业智能BI和数据分析品牌。Smartbi致力于为企业客户提供一站式商业智能解决方案。  
  
  
参考链接：  
  
https://www.smartbi.com.cn/index/news_cont/nid/6010  
  
  
**SEE MORE →******  
  
**2****影响范围**  
  
**受影响版本：**  
  
- Smartbi >= V9  
  
  
  
  
**3****漏洞防护**  
  
**3.1 官方升级**  
  
目前官方已发布补丁包修复此漏洞，建议受影响的用户及时安装防护，安全补丁下载链接：https://www.smartbi.com.cn/patchinfo  
  
安全补丁更新详细操作文档，参考链接：https://wiki.smartbi.com.cn/pages/viewpage.action?pageId=50692623  
  
  
**END**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qR4ORTNELImFwJM2rh6GKbnrurdFA28jJ8chUPyC1U6aW3jhenqEiaXkmeGVmfOnvAJy8j3My901JQ7emHaicYzA/640?wx_fmt=png "")  
           
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qR4ORTNELImFwJM2rh6GKbnrurdFA28jib7icfic0lJJHh3eLRpIXiaia08KqOSEibBsz64vlOH9aqicu3lmjccEeAFWQ/640?wx_fmt=jpeg "")  
          
  
**声明**  
  
本安全公告仅用来描述可能存在的安全问题，绿盟科技不为此安全公告提供任何保证或承诺。由于传播、利用此安全公告所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，绿盟科技以及安全公告作者不为此承担任何责任。              
  
绿盟科技拥有对此安全公告的修改和解释权。如欲转载或传播此安全公告，必须保证此安全公告的完整性，包括版权声明等全部内容。未经绿盟科技允许，不得任意修改或者增减此安全公告内容，不得以任何方式将其用于商业目的。              
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qR4ORTNELImFwJM2rh6GKbnrurdFA28jib7icfic0lJJHh3eLRpIXiaia08KqOSEibBsz64vlOH9aqicu3lmjccEeAFWQ/640?wx_fmt=jpeg "")  
  
  
**绿盟科技CERT**  
****  
∣  
微信公众号  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/VvfsuOanecqCnKkfTiaJLeoI20L5s7Q1eScPIO3ley6jWLx6ctu1hrq5NRYaOXwcbezVictEU7lQj59Z610p4MibQ/640?wx_fmt=jpeg "绿盟科技CERT公众号.jpg")  
  
![](https://mmbiz.qpic.cn/mmbiz/Hu8hctxHqSW0nSJn8p8OHVEQwHicSwTibFJMBE650AxdzfISoeY8woe2QsgCINIBrccBOOUft2HuU0GsNQWibSG7g/640?wx_fmt=png "")  
  
长按识别二维码，关注网络安全威胁信息  
  
  
  
