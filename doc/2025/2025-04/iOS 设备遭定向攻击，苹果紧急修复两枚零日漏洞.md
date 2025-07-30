#  iOS 设备遭定向攻击，苹果紧急修复两枚零日漏洞   
 FreeBuf   2025-04-18 12:34  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
苹果公司已发布iOS 18.4.1和iPadOS 18.4.1更新，修复两个被用于针对特定iPhone用户实施高度定向、复杂攻击的关键零日漏洞。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icWJxQGpmdcL3xJefu6qYSibUiaON6siczZB3z50Dv9pwbu3yeE2VOzNBzyMfSvS8mvplYIY5oQUzBcw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
这两个漏洞存在于CoreAudio和RPAC组件中，攻击者可利用它们在受影响设备上执行任意代码或绕过安全保护机制。  
  
  
**01**  
  
  
  
**两个正被活跃利用的零日漏洞**  
  
  
**1. CoreAudio漏洞**  
  
****  
第一个漏洞编号为CVE-2025-31200，存在于负责iOS和iPadOS设备音频处理的CoreAudio框架中。  
  
  
苹果公司表示，处理恶意构造的媒体文件可能触发内存损坏问题，最终导致代码执行。  
"处理恶意构造媒体文件中的音频流可能导致代码执行。苹果已收到报告，该漏洞可能已被用于针对iOS特定用户的极其复杂的攻击。"  
  
  
苹果与谷歌威胁分析小组合作确认，该漏洞已被用于针对部分iOS用户的高级攻击。  
  
  
**2. RPAC漏洞**  
  
****  
第二个漏洞CVE-2025-31201影响RPAC（面向返回编程攻击防护）安全机制，该机制旨在防范漏洞利用。  
  
  
该漏洞可能使具备任意读写能力的攻击者绕过指针认证（Pointer Authentication）功能，该功能可防止代码被篡改。  
  
  
苹果表示："具备任意读写能力的攻击者可能绕过指针认证。苹果已收到报告，该漏洞可能已被用于针对iOS特定用户的极其复杂的攻击。"  
  
  
苹果指出，该漏洞在同一针对性攻击活动中被利用，目前已通过移除易受攻击代码得到缓解。  
  
  
**3. 受影响设备及修复措施**  
  
- iPhone XS及后续机型  
  
- iPad Pro 13英寸  
  
- iPad Pro 13.9英寸（第三代及后续机型）  
  
- iPad Pro 11英寸（第一代及后续机型）  
  
- iPad Air（第三代及后续机型）  
  
- iPad（第七代及后续机型）  
  
- iPad mini（第五代及后续机型）  
  
**02**  
  
  
  
**针对性攻击凸显威胁升级**  
  
  
虽然苹果未披露攻击具体细节，但将其描述为"极其复杂"且针对特定个人，暗示可能是国家支持或资源充足的威胁行为者所为。  
  
  
此类利用未知漏洞的零日攻击因复杂性和高成本，通常被用于间谍活动或针对性网络攻击。  
  
  
苹果强调其政策是在补丁可用前不披露安全问题。  
  
  
该公司于2025年4月16日发布的安全更新说明中提供了漏洞和受影响设备的详细信息。用户可访问苹果产品安全页面获取更多安全实践信息。  
  
  
苹果强烈建议所有符合条件的用户尽快更新，确保免受这些漏洞影响。  
要安装iOS 18.4.1或iPadOS 18.4.1，请前往设备上的设置 > 通用 > 软件更新。  
  
  
**03**  
  
  
  
**年度漏洞态势**  
  
  
这两个漏洞使得苹果今年需要修复的零日漏洞总数达到五个。此前在1月、2月和3月各发现一个零日漏洞。在不到四个月的时间里，苹果已接近其2024年全年六个零日漏洞的总数（包括"三角测量行动"中使用的两个著名漏洞）。这也意味着，当前威胁环境对代码错误容忍度极低，攻击者会利用任何细微的编码失误发起攻击。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1y91mvSZuxibf3Q3g2rJ32FNzoYfx4yaBmWbfwcRaNicuMo3AxIck2bCw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651318777&idx=1&sn=1c9c7f2561b2b3ce09438b7f1ff25807&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651318673&idx=1&sn=fc4885839a5fa2d029e0e95474e9432b&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651317804&idx=2&sn=3d017ae8749aa67775bcd2302b38931b&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651317737&idx=1&sn=99fed7dcc16d21127eb031fd187b35f5&scene=21#wechat_redirect)  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1uEIoRxNoqa17tBBrodHPbOERbZXdjFvNZC5uz0HtCfKbKx3o3XarGQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS5KDnCKUfVLVQGsc9BiaQTUsrwzfcianumzeLVcmibOmm2FzUqef2V6WPQQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38mFMbqsUOVbBDicib7jSu7FfibBxO3LTiafGpMPic7a01jnxbnwOtajXvq5j2piaII2Knau7Av5Kxvp2wA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
