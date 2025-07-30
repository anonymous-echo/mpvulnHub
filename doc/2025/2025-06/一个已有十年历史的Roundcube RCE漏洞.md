#  一个已有十年历史的Roundcube RCE漏洞   
Guru Baran  潇湘信安   2025-06-04 05:46  
  
<table><tbody><tr><td data-colwidth="557" width="557" valign="top" style="word-break: break-all;"><section style="margin-bottom: 15px;"><span style="font-size: 14px;"><span style="color: rgb(217, 33, 66);"><strong><span leaf="">声明：</span></strong></span><span leaf="">该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载，未经授权，严禁转载，如需转载，联系开白。</span></span></section><section><span style="font-size: 14px;"><span leaf="">请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。</span></span></section></td></tr></tbody></table>  
  
现在只对常读和星标的公众号才展示大图推送，建议大家把  
“  
潇湘信安  
”  
设为星标  
，  
否则可能看不到了  
！  
  
  
Roundcube Webmail 中发现一个已有十年历史的严重安全漏洞，该漏洞可能允许经过身份验证的攻击者在易受攻击的系统上执行任意代码，从而可能影响全球数百万个安装。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/AnRWZJZfVaFiaOEaWPiaNQG1WT0h3zf9iauibEFqMF2lVDKZudXjXqJ4GjQjREJXzxq92Q31Y7RicbuzEPSAH17nNzw/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
该漏洞的编号为 CVE-2025-49113，CVSS 评分高达 9.9（满分 10.0），是近年来发现的最严重的漏洞之一。  
  
  
该漏洞影响 Roundcube Webmail 1.5.10 之前的所有版本以及 1.6.11 之前的 1. 6.x 版本，影响范围惊人，涉及全球超过 5300 万台主机。  
  
  
该漏洞涉及流行的网络托管控制面板，例如 cPanel、Plesk、ISPConfig 和 DirectAdmin，它们将 Roundcube 捆绑作为其默认的网络邮件解决方案。  
  
  
迪拜网络安全公司 FearsOff 的创始人兼首席执行官 Kirill Firsov 发现了这个利用 PHP 对象反序列化的经过身份验证的远程代码执行漏洞。  
  
  
该安全漏洞因为 URL 中的 _from 参数未在 program/actions/settings/upload.php 中验证，从而导致恶意用户能够操纵序列化的 PHP 对象并在服务器上执行任意代码。  
  
  
视频来源：x（@ptswarm）  
  
  
Roundcube 一直以来都是  
APT  
组织的首要目标。该网络邮件平台此前存在的漏洞曾被 APT28 和 Winter Vivern 等  
APT  
组织利用。  
  
  
去年，身份不明的黑客试图利用 CVE-2024-37383 进行网络钓鱼攻击，旨在窃取用户凭证。  
  
  
最近，ESET 研究人员记录了 APT28 利用包括 Roundcube 在内的各种网络邮件服务器中的跨站点脚本漏洞来收集东欧政府实体和国防公司的机密数据。  
  
  
多国网络安全中心强烈建议各组织在全面测试后以最高优先级安装更新。目前已发布修复版本，包括 Roundcube Webmail 1.6.11 和 1.5.10 LTS，可修复此漏洞。  
  
  
使用 Roundcube Webmail 的组织应优先立即修补并实施增强的监控功能，以检测任何可能表明试图利用此严重漏洞的可疑活动。  
  
  
更多信息，参考fearsoff公司发布的安全公告：  
  
https://fearsoff.org/research/roundcube  
  
  
新闻链接：  
  
https://cybersecuritynews.com/10-year-old-roundcube-rce-vulnerability/  
  
  
**关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
 还在等什么？赶紧点击下方名片开始学习吧   
![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOeSsicAgIUNHtMib9a69NOWXw1A7mgRqqiat1SycQ0b6e5mBqC0pVJ3oicrQnCTh4gqMGiaKUPicTsUc4Tw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
**知 识 星 球**  
  
  
  
  
星球已过800人，暂不再发放优惠券，如还有需要的师傅可加我  
VX  
：**S_3had0w，等你一起来学习...！**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/XOPdGZ2MYOe8h8vDq3IN1GhNuNnkbWYgcibYRicgo0SRy1febylE4kBDdibgIJV1ia1QNSBYiaZAZWCzAjESoYfxNjw/640?wx_fmt=jpeg&from=appmsg "")  
  
**推 荐 阅 读**  
  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg4NTUwMzM1Ng==&mid=2247499188&idx=1&sn=9ce15a0e66b2595285e544aaa0c49c24&chksm=cfa559a7f8d2d0b162f00e0c1b02c85219f2668c282b32967b2530f15051b47b21ee2855a783&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg4NTUwMzM1Ng==&mid=2247496043&idx=1&sn=4daa27ade9915de6021fea1c2a21d7bc&chksm=cfa55578f8d2dc6ef887ce27215f942ec233320fa6878bc1666ce0fecb0e7f6c7f96a3ba4e2b&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg4NTUwMzM1Ng==&mid=2247486327&idx=1&sn=71fc57dc96c7e3b1806993ad0a12794a&chksm=cfa6af64f8d1267259efd56edab4ad3cd43331ec53d3e029311bae1da987b2319a3cb9c0970e&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/XOPdGZ2MYOdAPjIVeN2ZahG9ibP0Y3wlfg6BO1WO7MZfo1JeW7zDWcLSTQ5Ek8zXAia5w1nMnogpbpXP6OxXXOicA/640?wx_fmt=png "")  
  
