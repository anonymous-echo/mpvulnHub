#  【漏洞通告】Nacos Raft协议反序列化代码执行漏洞   
NS-CERT  绿盟科技CERT   2023-06-07 12:01  
  
**通告编号:NS-2023-0023**  
  
2023-06-07  
  
<table><tbody><tr><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><strong><span style="font-size: 14px;">TA</span></strong><strong><span style="font-size: 14px;">G：</span></strong></td><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><p style="vertical-align: inherit;line-height: 1.75em;font-size: 14px;color: rgb(0, 0, 0);font-family: 微软雅黑;"><strong style="caret-color: red;line-height: 1.57em;font-family: 微软雅黑, sans-serif;"><span style="font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">Nacos、Raft、反序列化</span></strong></p></td></tr><tr><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><span style="color: rgb(0, 0, 0);"><strong><span style="font-size: 14px;">漏洞危害：</span></strong></span><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 14px;"></span></strong></span></td><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><p><strong style="caret-color: red;font-size: 14px;line-height: 1.5em;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">攻击者利用漏洞可实现代码执行。</strong></p></td></tr><tr><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><strong><span style="font-size: 14px;">版本：</span></strong></td><td style="margin: 5px 10px;border-color: rgb(216, 216, 216);word-break: break-all;" valign="top"><strong><span style="font-size: 14px;">1.0<br/></span></strong></td></tr></tbody></table>  
  
**1**  
  
  
**漏洞概述**  
  
  
近日，绿盟科技CERT监测发现到Nacos的Raft协议存在反序列化漏洞。由于Nacos集群对部分Jraft请求进行处理时，未限制使用hessian进行反序列化，从而导致攻击者可以实现代码执行。请受影响的用户尽快采取措施进行防护。  
  
Nacos是一个更易于构建云原生应用的动态服务发现、配置管理和服务管理平台。它提供了一组简单易用的特性集，实现动态服务发现、服务配置、服务元数据及流量管理。  
  
  
漏洞状态：  
<table><tbody><tr><td style="border-top-width: 2px;border-left-width: 2px;border-color: windowtext;" valign="top"><p style="text-align:center;line-height: 1.75em;"><span style="font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="line-height: 125%;color: rgb(55, 61, 65);letter-spacing: 1px;">漏洞细节</span></strong></span></p></td><td style="border-top-width: 2px;border-color: windowtext;" valign="top"><p style="text-align:center;line-height: 1.75em;"><span style="font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="line-height: 125%;color: rgb(55, 61, 65);letter-spacing: 1px;"><strong>漏洞</strong><strong>PoC</strong></span></strong></span></p></td><td style="border-top-width: 2px;border-color: windowtext;" valign="top"><p style="text-align:center;line-height: 1.75em;"><span style="font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="line-height: 125%;color: rgb(55, 61, 65);letter-spacing: 1px;"><strong>漏洞</strong><strong>EXP</strong></span></strong></span></p></td><td style="border-top-width: 2px;border-right-width: 2px;border-color: windowtext;" valign="top"><p style="text-align:center;line-height: 1.75em;"><span style="font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;"><strong><span style="line-height: 125%;color: rgb(55, 61, 65);letter-spacing: 1px;">在野利用</span></strong></span></p></td></tr><tr><td style="border-bottom-width: 2px;border-left-width: 2px;border-color: windowtext;" valign="top"><p style="text-align:center;line-height: 1.75em;"><span style="line-height: 125%;color: rgb(51, 51, 51);letter-spacing: 1px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td style="border-bottom-width: 2px;border-color: windowtext;" valign="top"><p style="text-align:center;line-height: 1.75em;"><span style="line-height: 125%;color: rgb(51, 51, 51);letter-spacing: 1px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td style="border-bottom-width: 2px;border-color: windowtext;" valign="top"><p style="text-align:center;line-height: 1.75em;"><span style="line-height: 125%;color: rgb(51, 51, 51);letter-spacing: 1px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">未公开</span></p></td><td style="border-right-width: 2px;border-bottom-width: 2px;border-color: windowtext;" valign="top"><p style="text-align:center;line-height: 1.75em;"><span style="line-height: 125%;color: rgb(55, 61, 65);letter-spacing: 1px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;">暂不存在</span></p></td></tr></tbody></table>  
  
参考链接：  
  
https://github.com/alibaba/nacos/releases  
  
  
**SEE MORE →******  
  
**2****影响范围**  
  
**受影响版本：**  
  
- 1.4.0 <= Nacos < 1.4.6  
  
- 2.0.0 <= Nacos < 2.2.3  
  
  
  
  
**不受影响版本：**  
  
- Nacos < 1.4.0  
  
- 1.4.6 <= Nacos < 2.0.0  
  
- Nacos >= 2.2.3  
  
  
  
  
  
**3****漏洞防护**  
  
**3.1 官方升级**  
  
  
目前官方已发布新版本修复该漏洞，请受影响的用户尽快升级版本进行防护，官方下载链接如下：https://github.com/alibaba/nacos/releases/tag/1.4.6https://github.com/alibaba/nacos/releases/tag/2.2.3  
  
**3.2 临时防护措施**  
   
  
默认配置下该漏洞仅影响Nacos集群间Raft协议通信的7848端口，此端口不承载客户端请求，可以通过限制集群外部IP访问7848端口来进行缓解。  
  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/VvfsuOanecrCvvN1WNwMaOibd79VgR03ze234LOMk3sMzIzbsiboKI70N8N91Pl94DPNeCicOCYricmhU8O1Mv3QXA/640?wx_fmt=jpeg "绿盟科技CERT公众号.jpg")  
  
![](https://mmbiz.qpic.cn/mmbiz/Hu8hctxHqSW0nSJn8p8OHVEQwHicSwTibFJMBE650AxdzfISoeY8woe2QsgCINIBrccBOOUft2HuU0GsNQWibSG7g/640 "")  
  
长按识别二维码，关注网络安全威胁信息  
  
  
