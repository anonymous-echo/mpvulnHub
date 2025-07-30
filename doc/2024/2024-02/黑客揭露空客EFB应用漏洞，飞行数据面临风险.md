#  黑客揭露空客EFB应用漏洞，飞行数据面临风险   
疯狂冰淇凌  FreeBuf   2024-02-12 08:12  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
多年来，渗透测试公司Pen Test Partners的网络安全研究人员致力于测试各种电子飞行包（EFB）、物联网和车载应用程序的安全性。基于深入研究，他们发现了空客Flysmart+管理套件中的一个重要漏洞，并在漏洞披露后的19个月内进行了修复。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibE7qkicW106hCFyjuYQykvccIx6c8wKkiac3NCbcuicCMrUWIOTGUYmnshtibfobbRd1p8xewpqNQgHQ/640?wx_fmt=jpeg&from=appmsg "")  
  
> Flysmart+ 是空客旗下的IT服务公司NAVBLUE专为飞行员电子飞行包（EFB）设计的应用程序套件，用于同步和安装航空公司数据到其他应用中。而电子飞行包主要用于存储关键的飞行数据和信息，用途尤其重要。  
  
  
  
2024年2月1日，Pen Test Partners发表的研究表示，该套件中的一个iOS应用程序故意禁用了应用传输安全（ATS）功能。这一问题容易使应用程序受到Wi-Fi拦截攻击，从而干扰发动机性能计算，导致机尾撞击或跑道偏离事故发生，并且现行的标准操作流程可能无法有效检测出任何篡改行为。  
  
  
之前，Flysmart+应用程序由于缺乏ATS（应用传输安全）保护而被禁用。ATS保护的目的是防止未加密的通信，因为缺乏该功能，不安全的通信就会发生，Flysmart+允许攻击者拦截并解密传输中的敏感信息。在info.plist文件中，一个设置项允许应用程序加载任何域的不安全的HTTP内容。  
  
  
航空公司通常为中转停留的飞行员安排同一家酒店，使得攻击者可以通过定向的Wi-Fi网络修改飞机的性能数据。Pen Test Partners利用这一机会访问了NAVBLUE服务器上的数据，包括含有飞机信息和起飞性能数据（PERF）的SQLite数据库，以及具有特定表名的数据。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibE7qkicW106hCFyjuYQykvcUU5CMSylUaCLqXxqkUsxYO1ZfOT32k2Jc7WVk4u29oHKPCFSPhBAtg/640?wx_fmt=jpeg&from=appmsg "")  
  
研究员从NAVBLUE服务器下载的数据（来源：Pen Test Partners）  
  
  
需要注意的是，数据库表对于飞机性能至关重要，包括最小设备清单（MEL）和标准仪表离场程序（SID）。比如吉姆利滑翔机燃油耗尽事件中对MEL和SID的误解。另外，像美国加仑、英制加仑、升、千克和磅单位之间的混淆也可能造成安全问题。  
  
  
渗透测试合作伙伴安东尼奥·卡西迪表示：“我们已经与波音、汉莎航空和空客合作就安全漏洞进行了披露，并且成功修复这一漏洞，对我们而言，这是航空安全性和保障性的一大进步。”  
  
  
2022年6月28日，研究人员向空客提交了漏洞报告，空客在次日确认了这一漏洞。直至2022年7月25日，该公司复现了这一漏洞，并承诺将在2022年底之前在Flysmart+新版本中修复此漏洞。  
  
  
2023年2月22日，空中客车VDP（漏洞披露计划）团队确认已在Flysmart+的最新版本中修复了该漏洞，并于2023年5月26日向客户通报了缓解措施。这些研究成果在2023年于拉斯维加斯举行的DEF CON 31安全会议以及在都柏林的航空村和航空信息共享与分析中心（Aviation ISAC）上进行了展示。  
> 参考来源：  
Hackers Uncover Airbus EFB App Vulnerability, Risking Aircraft Data (hackread.com)  
  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复“加群”，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
> https://www.securityweek.com/data-of-750-million-indian-mobile-subscribers-sold-on-hacker-forums/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492331&idx=1&sn=406428ff5a9e185e658948e896b0b4a8&chksm=ce1f1874f9689162105cf92ee082dcafbd164bbe3fb15d3bde4d4c8328c2ac2d3526fd006d84&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492331&idx=1&sn=406428ff5a9e185e658948e896b0b4a8&chksm=ce1f1874f9689162105cf92ee082dcafbd164bbe3fb15d3bde4d4c8328c2ac2d3526fd006d84&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
