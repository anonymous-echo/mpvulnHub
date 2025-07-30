#  VMware vCenter Server远程代码执行漏洞正被黑客广泛利用   
Zicheng  FreeBuf   2024-11-19 11:35  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oQ6bDiaGhdyoFWEgZIHic7sqnootFEuOic7RlQNGhKY6d2ZESG3WpiaTMRlD0z4xO6mQrTZjkWHCkMpO2QtCfUJH6g/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
据Cyber Security News消息，11月18日，博通发布了紧急警告，称 VMware vCenter Server 中的两个关键漏洞现在正被广泛利用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39uD8TzUAG6icPT99CvicxqoBG7LtljpciaHq2S2Npggf0hnHS7zOiaia9C3nCYTDx69pg9t1h6JZYjkiaw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
这两个漏洞包含一个CVSS评分达9.8分的远程代码执行 （RCE） 漏洞，被跟踪为 CVE-2024-38812。该漏洞源于 vCenter Server 实现 DCE/RPC 协议时的堆溢出问题，具有网络访问权限的攻击者可以通过发送特制数据包来触发此漏洞，从而可能导致远程代码执行和整个系统受损。  
  
  
第二个漏洞被跟踪为CVE-2024-38813， CVSS 评分7.5，允许攻击者通过发送恶意构建的网络数据包将权限升级到根权限。  
  
  
这两个漏洞最初是由 TZL 团队的研究人员 zbl 和 srs 在中国 2024 年矩阵杯黑客大赛期间发现并报告，受到影响的版本包括 VMware vCenter Server 7.0 和 8.0 版本以及 VMware Cloud Foundation 4.x 和 5.x 版本。  
  
  
11月18日，博通发布了最新安全公告，指出 CVE-2024-38812 和 CVE-2024-38813 都已在野外被积极利用。鉴于这些漏洞的严重性和主动利用，博通强烈建议使用受影响的VMware 产品要立即应用最新的安全更新。  
  
  
博通于 2024 年 9 月 17 日首次发布了针对这些漏洞的补丁，但值得注意的是，该公司在10月21日再度发布了补丁更新，指出先前的修复并不完整，强烈建议用户立刻更新最新的补丁。  
  
  
目前最新的受影响产品修复版本包括：  
  
- VMware vCenter Server 8.0：需更新到 8.0 U3d 版本  
  
- VMware vCenter Server 7.0：需更新到 7.0 U3t 版本  
  
- VMware Cloud Foundation 5.x：将异步修补程序应用于 8.0 U3d版本  
  
- VMware Cloud Foundation 4.x：将异步修补程序应用于 7.0 U3t版本  
  
这一事件凸显了及时应用安全更新的重要性，尤其是对于 VMware vCenter Server 等关键基础架构组件。因此建议企业组织审查自身的VMware 部署，应用必要的补丁，并监控是否有任何泄露迹象。鉴于存在远程代码执行和权限提升的可能性，任何可能已暴露的系统都应经过全面的安全评估。  
  
  
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
> https://cybersecuritynews.com/vmware-vcenter-server-rce-vulnerability-2/  
  
  
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
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302087&idx=1&sn=29d91904d6471c4b09f4e574ba18a9b2&chksm=bd1c3a4c8a6bb35aa4ddffc0f3e2e6dad475257be18f96f5150c4e948b492f32b1911a6ea435&token=21436342&lang=zh_CN&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651302006&idx=1&sn=18f06c456804659378cf23a5c474e775&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
