#  Windows远程桌面服务漏洞允许攻击者执行远程代码   
Zicheng  FreeBuf   2024-12-13 11:10  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
2024 年 12 月 10 日，微软披露了Windows 远程桌面服务中的一个严重漏洞，能够让攻击者在受影响的系统上执行远程代码，从而对系统机密性、完整性和可用性构成严重威胁。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibMz3fQrPsXun70eiaxdJGjWrQrZK3T4CIbaEJnmictITtzxjnteIEsybFgN0CKfcf0ev3UhZZlP5TA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
该漏洞被跟踪为 CVE-2024-49115，CVSS 评分为 8.1，由昆仑实验室的研究员 k0shl发现。漏洞影响Windows Server 的多个版本，包括Windows Server 2016、Windows Server 2019、Windows Server 2022和Windows Server 2025。  
  
  
漏洞源于两个关键缺陷：  
- CWE-591：在锁定不当的内存中存储敏感数据  
  
- CWE-416：释放后使用  
  
攻击者可通过连接到具有远程桌面网关角色的系统并触发竞争条件来利用此漏洞。这会产生 “free-after-free”  情况，从而执行任意代码。  
  
  
值得注意的是，这种攻击不需要用户交互或权限，但其高度复杂性使得没有高级技术技能的攻击者不太可能成功利用该漏洞。  
  
  
目前所有受影响的版本都已作为微软 2024 年 12 月 "星期二补丁"更新的一部分，打上了相应的安全补丁。虽然漏洞利用代码的成熟度目前尚未得到证实，也没有证据表明存在主动利用或公开披露的情况，但其潜在影响仍然很大。成功利用后，攻击者可通过远程代码执行完全控制目标系统。  
  
  
此漏洞反映了与远程桌面协议 （RDP） 等远程访问技术相关存在的持续性风险。虽然目前还没有主动利用漏洞的报告，但这一漏洞的严重性凸显了立即采取行动保护系统免受潜在攻击的必要性，包括将 RDP 访问限制在受信任的网络、启用网络级身份验证（NLA）和监控可疑活动。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
> https://cybersecuritynews.com/windows-remote-desktop-services-vulnerability/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651307029&idx=1&sn=809e704f3bd356325cf8d85ed0717a8d&chksm=bd1c2e9e8a6ba788529249c685d4979c6b11853cf8f2d798a6d8e9ce362926ec50e3639cf79f&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651308240&idx=1&sn=96d32c8e6fa90561c84164ed75f4dca0&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
