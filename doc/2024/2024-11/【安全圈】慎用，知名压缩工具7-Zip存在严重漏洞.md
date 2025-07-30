#  【安全圈】慎用，知名压缩工具7-Zip存在严重漏洞   
 安全圈   2024-11-26 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
近日，主流文件压缩工具7-Zip被曝存在一个严重的安全漏洞，允许远程攻击者通过精心制作的存档执行恶意代码。该漏洞编号为CVE-2024-11477，CVSS评分7.8分，表明受影响版本的用户面临重大安全风险。![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaJT9LOL4Vm2kyopU9Gnk9cn25BPtrpGic59VfZK9T6kmVYiaoeYfjIYmghIibH4ooQ0BIviaU1VweA3g/640?wx_fmt=jpeg&from=appmsg "")  
  
  
漏洞存在于 Zstandard 解压缩的实现中。此问题是由于未正确验证用户提供的数据而导致的，这可能导致在写入内存之前出现整数下溢。攻击者可以利用此漏洞在当前进程的上下文中执行代码，但要利用此漏洞，需要与此库交互，但攻击媒介可能因实施而异。  
  
根据趋势科技安全研究部的Nicholas Zubrisky的说法，攻击者可以通过说服用户打开精心准备的存档来利用此漏洞，这些存档可以通过电子邮件附件或共享文件分发。  
  
Zstandard格式在Linux环境中尤为普遍，通常用于各种文件系统，包括Btrfs、SquashFS和OpenZFS。  
### 漏洞影响  
- 在受影响的系统上执行任意代码  
  
- 获得与登录用户相同的访问权限  
  
- 可能实现完全的系统绕过  
  
### 缓解措施和修复  
  
7-Zip已在24.07版本中解决了此安全问题。由于该软件缺乏集成的更新机制，用户必须手动下载并安装最新版本以保护其系统，官网地址：https://www.7-zip.org/  
  
在企业环境中使用7-Zip的IT管理员和软件开发者应立即将其安装更新为已修补的版本。需要注意的是，由于7-Zip钓鱼邮件和带病毒的假冒产品非常多，在搜索引擎中搜索下载时请注意甄别。  
  
该漏洞最初于  
  
2024年6月，安全研究人员向7-Zip报告了该漏洞，并于11月20日公开披露。尽管目前没有已知的恶意软件针对此漏洞。，但安全专家强烈建议用户及时修补，因为利用该漏洞所需的技术专业知识最少，  
  
这一事件突显了应用程序安全中输入验证的关键重要性，特别是在处理可能不受信任的数据时，使用7-Zip或包含其功能的产品组织和个体应优先更新到最新版本以维护系统安全。  
  
参考来源：https://cybersecuritynews.com/7-zip-vulnerability-arbitrary-code/  
  
  
  
  
  
   END    
  
  
阅读推荐  
  
  
[【安全圈】威联通NAS的QTS系统新版本导致无法正常访问 目前该固件已经被撤回](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652066218&idx=1&sn=a4d403fd36bee9add5a2da4f1ca2462c&scene=21#wechat_redirect)  
  
  
  
[【安全圈】维基解密告密者使用防NSA VPN对抗AI监控](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652066218&idx=2&sn=5f496ab01a0c1c8bbacd6e3cc8f77599&scene=21#wechat_redirect)  
  
  
  
[【安全圈】Fortinet VPN服务器设计缺陷能隐藏攻击者行踪](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652066218&idx=3&sn=383839a7010797557f1d931f08bba980&scene=21#wechat_redirect)  
  
  
  
[【安全圈】超2000 台 Palo Alto Networks 设备遭入侵](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652066218&idx=4&sn=8b68cb431919cf30facf1ad47ba67cfe&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
