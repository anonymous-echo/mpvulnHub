#  新的macOS漏洞允许攻击者绕过安全控制   
Zicheng  FreeBuf   2024-10-20 09:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oQ6bDiaGhdyoFWEgZIHic7sqnootFEuOic7RlQNGhKY6d2ZESG3WpiaTMRlD0z4xO6mQrTZjkWHCkMpO2QtCfUJH6g/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icRiceD1WyppLprtfBatTs4cxBTeHmSCYlsxUaqUcpmvwZmlZFJv1ib6xm5cK5LYqD61dZ0vU3TOArg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
据Cyber Security News消息， 微软威胁情报发现，macOS出现了一个名为“HM Surf”的新漏洞，能允许攻击者绕过操作系统的透明、同意和控制（TCC）技术，在未经授权的情况下访问用户受保护的数据。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icRiceD1WyppLprtfBatTs4cTFpibSawfNMDMChSrZ5cLAG5Km82NbIwicaF0tx5zGHTKic5F2dYe89uQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
该漏洞被追踪为CVE-2024-44133，能够被利用收集敏感信息（例如浏览历史记录），并在未经授权的情况下访问设备的摄像头、麦克风和位置。  
  
  
HM Surf 能够更改当前用户的主目录，修改用户真实主目录下的敏感文件，以及运行 Safari 打开一个网页，该网页拍摄相机快照并跟踪设备位置。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icRiceD1WyppLprtfBatTs4cGcdoTw8VCSAgGrzcn8CQgTtTRco9xNy6y7SIMKticZBicyl8TohusBdQ/640?wx_fmt=jpeg&from=appmsg "")  
  
Safari 弹出窗口  
  
  
攻击者可以执行一些隐秘的操作，例如私下托管快照、保存整个摄像头数据流、录制和串流麦克风音频，以及在小窗口中启动 Safari 以避免引起注意。  
  
  
微软通过 Microsoft Security Vulnerability Research （MSVR） 的协调漏洞披露 （CVD） 与 苹果分享了这一漏洞发现。目前，只有 Safari 使用 TCC 提供的新保护，微软正在与其他主要浏览器供应商合作，以调查强化本地配置文件的好处。  
  
  
目前苹果已在9 月 16 日发布的 macOS Sequoia 最新安全更新中修复了该漏洞。微软建议macOS 用户尽快应用 Apple 发布的安全更新。  
  
  
此前，微软已发现多个存在于macOS和Linux系统中的漏洞，随着跨平台威胁的持续增加，对漏洞发现和威胁情报共享的协调响应将有助于加强保护技术，以保护用户在所有平台和设备上的安全。  
  
  
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
> https://cybersecuritynews.com/macos-vulnerability-bypass-security-controls/  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
