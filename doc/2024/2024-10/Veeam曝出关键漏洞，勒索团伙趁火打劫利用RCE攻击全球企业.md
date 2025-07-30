#  Veeam曝出关键漏洞，勒索团伙趁火打劫利用RCE攻击全球企业   
小薯条  FreeBuf   2024-10-11 19:47  
  
##   
  
  
勒索软件团伙现在利用一个关键的安全漏洞，让攻击者在易受攻击的 Veeam Backup & Replication (VBR) 服务器上获得远程代码执行 (RCE)。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38iaLH1sCCqKO5RW4IzCrBCvANZzS95Qh5Qfz3biabNuq5u8mLbkpsrSx8U4IhibuDzcAqiadUsrxmEcQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Code White安全研究员Florian Hauser发现，该安全漏洞（现在被追踪为CVE-2024-40711）是由未受信任数据的反序列化弱点引起的，未经认证的威胁行为者可以利用该漏洞进行低复杂度攻击。  
  
  
Veeam 于 9 月 4 日披露了该漏洞并发布了安全更新，而 watchTowr Labs 则于 9 月 9 日发布了一份技术分析报告。不过，watchTowr Labs 将概念验证利用代码的发布时间推迟到了 9 月 15 日，以便管理员有足够的时间确保服务器安全。  
  
  
企业将 Veeam 的 VBR 软件作为数据保护和灾难恢复解决方案，用于备份、恢复和复制虚拟机、物理机和云计算机，从而导致了这一延迟。这也使其成为恶意行为者寻求快速访问公司备份数据的热门攻击目标。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38iaLH1sCCqKO5RW4IzCrBCvn4E3fErKXwtLRgAgicpMCF77ZChIcRWvcUg00z2zfZqm56TpKCF1yBw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
正如 Sophos X-Ops 事件响应人员在上个月发现的那样，CVE-2024-40711 RCE 漏洞很快被发现，并在 Akira 和 Fog 勒索软件攻击中被利用，与之前泄露的凭证一起，向本地管理员和远程桌面用户组添加“点”本地帐户。  
  
  
在一个案例中，攻击者投放了Fog勒索软件。同一时间段的另一起攻击则试图部署 Akira 勒索软件。Sophos X-Ops表示：所有4起案件中的迹象都与早期的Akira和Fog勒索软件攻击重叠。  
  
  
在每起案件中，攻击者最初都是使用未启用多因素身份验证的受损 VPN 网关访问目标。其中一些 VPN 运行的是不支持的软件版本。  
  
  
在Fog勒索软件事件中，攻击者将其部署到未受保护的Hyper-V服务器上，然后使用实用程序rclone外泄数据。  
##   
## 这并非勒索软件攻击针对的首个Veeam漏洞。去年，即 2023 年 3 月 7 日，Veeam 还修补了备份与复制软件中的一个高严重性漏洞（CVE-2023-27532），该漏洞可被利用来入侵备份基础架构主机。  
  
  
几周后的3月下旬，芬兰网络安全和隐私公司WithSecure发现CVE-2023-27532漏洞部署在与FIN7威胁组织有关的攻击中，FIN7威胁组织因与Conti、REvil、Maze、Egregor和BlackBasta勒索软件行动有关而闻名。  
  
  
几个月后，同样的Veeam VBR漏洞被用于古巴针对美国关键基础设施和拉美IT公司的勒索软件攻击。  
  
  
Veeam表示，其产品已被全球超过55万家客户使用，其中包括至少74%的全球2000强企业。  
  
  
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
> h  
ttps://www.bleepingcomputer.com/news/security/akira-and-fog-ransomware-now-exploiting-critical-veeam-rce-flaw/  
  
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
  
