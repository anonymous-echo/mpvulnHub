#  热门游戏《我的世界》模组存在RCE漏洞，已被多次利用   
 安全内参   2023-08-03 11:16  
  
**关注我们**  
  
  
**带你读懂网络安全**  
  
  
上周六，Minecraft安全社区MMPA的研究人员在一篇博客中提醒游戏用户，《Minecraft》游戏的部分1.7.10/1.12.2模组中存在一个已被多次利用的重大安全漏洞，该漏洞允许黑客在游戏服务器上运行恶意命令并危及游戏玩家设备安全。  
  
据了解，微软旗下的热门游戏《Minecraft》是有史以来销量最高的视频游戏，已售出超过2.38亿份，每月活跃玩家接近1.4亿。MMPA称，BleedingPipe漏洞允许黑客在玩家设备和运行Minecraft模组的服务器上执行完整的远程代码。  
  
根据MMPA的说法，热门模组平台Forge使用了不安全的反序列化代码（反序列化是将复杂数据从序列化格式转换回其原始形式的过程，能够方便存储或传输。如果实施不慎，可被攻击者利用并实现远程代码执行），BleedingPipe漏洞已经被多次利用，该平台上的许多Minecraft模组都受到了影响（数量超过三十个）。已知受影响的模组包括但不限于以下几个：EnderCore（EnderIO的前置模组）、LogisticsPipes、BDLib（1.7-1.12版本）、Smart Moving 1.12、Brazier、DankNull和Gadomancy。并且，只要安装了受影响的模组，任何Minecraft版本都可能受到此漏洞的影响。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8EprCkKjgu7CXuB2W52ZOH14TXdXd02KPdicK2wUibGV3HQHmekEvCJ9CwTrq1rSpkAe6ljy9nFZhmw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
这个Minecraft漏洞最早是在2022年3月被发现。当时mod开发团队GTNH为此发布了一个修复补丁。然而，7月初，一位名为Yoyoyopo5的Minecraft玩家在一个带有Forge模组的公共服务器上进行直播时，攻击者利用BleedingPipe漏洞获取了对所有连接玩家设备的控制权并执行了代码。Yoyoyopo5在其帖子中报告了这一事件，称黑客利用这个访问权限从Discord和Steam中窃取了会话cookie。  
  
在最初的报告之后，研究人员发现黑客对IPv4地址空间上的所有Minecraft服务器进行了扫描，并在受影响的服务器上部署了恶意载荷。为降低安全风险，MMPA给出了如下建议：  
  
对于服务器管理员：建议检查服务器中的可疑文件，并更新/删除受此漏洞影响的模组。由于恶意软件通常会感染系统上的其他模组，因此建议在所有已安装的模组上运行jSus或jNeedle之类的程序。  
  
对于玩家：如果游戏玩家不在服务器上游玩游戏，则不受影响。否则建议检查可疑文件，运行杀毒软件进行防病毒扫描。  
  
编辑：左右里  
  
资讯来源：MMPA、bleepingcomputer  
  
  
**推荐阅读**  
- [网安智库平台长期招聘兼职研究员](http://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247499450&idx=2&sn=2da3ca2e0b4d4f9f56ea7f7579afc378&chksm=ebfab99adc8d308c3ba6e7a74bd41beadf39f1b0e38a39f7235db4c305c06caa49ff63a0cc1d&scene=21#wechat_redirect)  
  
  
- [欢迎加入“安全内参热点讨论群”](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247501251&idx=1&sn=8b6ebecbe80c1c72317948494f87b489&chksm=ebfa82e3dc8d0bf595d039e75b446e14ab96bf63cf8ffc5d553b58248dde3424fb18e6947440&token=525430415&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
  
  
  
文章来源：看雪学苑  
  
  
点击下方卡片关注我们，  
  
带你一起读懂网络安全 ↓  
  
  
  
  
