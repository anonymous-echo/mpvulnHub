#  MOVEit再曝9.1分高危漏洞，又要引发供应链大事件？   
小王斯基  FreeBuf   2024-06-29 09:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib4dqcV4HBY0Tss2ukcGlYf1XPCO8GoqLXoXJkh7X2XbB2libQHjGv0zRyLvicjIqPAxqtMcNDG3LlQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib4dqcV4HBY0Tss2ukcGlYfLpicTpeoUBasdDOTTHUCibXeU6fhMZibVJsMYnCkNCiaWEOpjpXgckkzhg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9Jeia3kKz374L8B6T1akwiaWFfnezfLtmD48biaA3tH7f8jC0QgdLXId0DM1mezicboK0CyJDFwJ8oR4s/640?wx_fmt=svg&from=appmsg "")  
  
左右滑动查看更多  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9Jeia3kKz374L8B6T1akwiaWFfnezfLtmD48biaA3tH7f8jC0QgdLXId0DM1mezicboK0CyJDFwJ8oR4s/640?wx_fmt=svg&from=appmsg "")  
  
  
  
近日，MOVEit 文件传输工具中的一个安全漏洞再次引起业内人士的警觉，Progress 软件公司敦促客户尽快修补这个「高危」漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib4dqcV4HBY0Tss2ukcGlYffCib8I5JmCbDB3xJapgEWUaKbAJWnibkhUCQ5n85Ekewr8xticFFpyA4w/640?wx_fmt=jpeg&from=appmsg "")  
  
> 漏洞追踪编号为 CVE-2024-5806，存在于 MOVEit 管理软件的 SFTP 模块中，威胁攻击者可以利用该漏洞轻松绕过身份验证，不仅可以访问存储在 MOVEit Transfer 服务器上的数据，并且能够外渗、删除或更改数据信息。  
  
  
  
Progress 软件公司表示，一旦第三方供应商发布修复补丁程序，就会立刻将向 MOVEit Transfer 客户提供。另外， CVE-2024-5806 安全漏洞的评分正在逐步升高，最新的更新公告中，安全漏洞的严重性评分已经从 7.4 分提高到了 9.1 分（满分 10 分）。  
  
  
Progress 软件公司方面的发言人向 Recorded Future News 透露，CVE-2024-5806 安全漏洞主要影响该公司用于传输文件的两款旗舰产品 MOVEit Transfer 和 MOVEit Gateway，并指出，目前公司还没有收到任何关于安全漏洞已被利用的报告，也没有发现安全漏洞对客户的运营有任何直接影响。  
  
  
**漏洞利用的可能性正在增加**  
  
  
  
多个安全组织发现并报告称过去 48 小时内，威胁攻击者对 CVE-2024-5806 安全漏洞的「兴趣」有所增加。网络安全公司 WatchTower 的研究人员已经发布了概念验证代码和有关 CVE-2024-5806 安全漏洞的详细信息，这大大增加了修补漏洞工作的紧迫性。  
  
  
英国 Shadowserver 基金会表示，CVE-2024-5806 安全漏洞细节公布后不久，就发现有人试图利用该漏洞，德国政府也表示看到了攻击企图。该基金会的数据显示，有 1772 个 MOVEit 实例暴露在互联网上，但其无法追踪哪些实例已经修补了该安全漏洞。  
  
  
此外，Censys 方面指出，它们的研究人员在网上观察到 2700 个 MOVEit Transfer 实例，主要集中在美国，几乎与 2023 年 MOVEit 上一次漏洞被利用时的数量相同。WatchTower 方面则表示，Progress 软件公司数周乃至数月来一直在与客户联系，最大程度上修补这一安全漏洞问题，预计不会有太多客户会受到安全漏洞的影响。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ib4dqcV4HBY0Tss2ukcGlYfyQYiayAf6sB2YsUqEalVu8YrDXIDDKBEf4O9qRsNMVpclIurlFvY1aw/640?wx_fmt=png&from=appmsg "")  
  
  
**MOVEit 安全漏洞问题影响深远**  
  
  
  
上一次 MOVEit 安全漏洞爆发时，全球成千上万的政府、企业和大型组织报受到影响。其中，知名勒索软件团伙 Clop 利用 MOVEit 安全漏洞开展了大规模网络攻击活动，大肆窃取受害者数据信息，勒索了巨额资金。  
  
  
安全公司 Emsisoft 估计，2023 年期间，有超过 6200 万人和 2000 家组织机构受到 MOVEit 安全漏洞的影响。Progress Software 在去年提交的监管文件中表示，由于与 MOVEit 相关的一系列漏洞，该公司正面临 58 起集体诉讼以及联邦、州和国际调查。  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://therecord.media/progress-software-elevates-severity-bug  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493976&idx=1&sn=70a35df0a9bd52d9ac09818483ff8810&chksm=ce1f13c7f9689ad10260fd6af11bcf78034d697b75e295281d4d5ce4a941d42ec8a24b9fc044&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247493939&idx=1&sn=8c3abe1ec23e6fa5dc21cb8e0d1a4993&chksm=ce1f13acf9689aba1da87cd2ce259f8510c502e974681a3dec60d0e6cefed0bd7e3d1cebd4bf&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
