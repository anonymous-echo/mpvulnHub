#  慎用，知名压缩工具7-Zip存在严重漏洞   
老布  FreeBuf   2024-11-26 10:57  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39aST9HN0x6QslibemgBPRxB1zOoZISTZ7wIm9r4XHvywdTcRmYrVY4xlx6yZc7cYpo245L0zAeR2w/640?wx_fmt=png&from=appmsg "")  
  
  
近日，主流文件压缩工具7-Zip被曝存在一个严重的安全漏洞，允许远程攻击者通过精心制作的存档执行恶意代码。该漏洞编号为CVE-2024-11477，CVSS评分7.8分，表明受影响版本的用户面临重大安全风险。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39aST9HN0x6QslibemgBPRxBZH78fz4XoHQDlx8R5BWic4PHl6EDqvKXzgtvwWLAicOjvoFy0HokJQAA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
漏洞存在于 Zstandard 解压缩的实现中。此问题是由于未正确验证用户提供的数据而导致的，这可能导致在写入内存之前出现整数下溢。攻击者可以利用此漏洞在当前进程的上下文中执行代码，但要利用此漏洞，需要与此库交互，但攻击媒介可能因实施而异。  
  
  
根据趋势科技安全研究部的Nicholas Zubrisky的说法，攻击者可以通过说服用户打开精心准备的存档  
来利用此漏洞，这些存档可以通过电子邮件附件或共享文件分发。  
Zstandard格式在Linux环境中尤为普遍，通常用于各种文件系统，包括Btrfs、SquashFS和OpenZFS。  
  
### 漏洞影响  
  
****- 在受影响的系统上执行任意代码  
  
- 获得与登录用户相同的访问权限  
  
- 可能实现完全的系统绕过  
  
### 缓解措施和修复  
  
****  
7-Zip已在24.07版本中解决了此安全问题。由于该软件缺乏集成的更新机制，用户必须手动下载并安装最新版本以保护其系统，官网地址：  
https://www.7-zip.org/  
  
  
在企业环境中使用7-Zip的IT管理员和软件开发者应立即将其安装更新为已修补的版本。需要注意的是，由于7-Zip钓鱼邮件和带病毒的假冒产品非常多，在搜索引擎中搜索下载时请注意甄别。  
  
  
该漏洞最初于  
2024年6月，安全研究人员向7-Zip报告了该漏洞，并于11月20日公开披露。  
尽管目前没有已知的恶意软件针对此漏洞。  
，但安全专家强烈建议用户及时修补，因为利用该漏洞所需的技术专业知识最少，  
这一事件突显了应用程序安全中输入验证的关键重要性，特别是在处理可能不受信任的数据时，使  
用7-Zip或包含其功能的产品组织和个体应优先更新到最新版本以维护系统安全。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
> https://cybersecuritynews.com/7-zip-vulnerability-arbitrary-code/  
  
  
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
>   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651307029&idx=1&sn=809e704f3bd356325cf8d85ed0717a8d&chksm=bd1c2e9e8a6ba788529249c685d4979c6b11853cf8f2d798a6d8e9ce362926ec50e3639cf79f&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651307635&idx=1&sn=63635c9ba9b91d7fb1b4c07ca89098c0&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
