#  【MalDev红队开发】笔记阶段汇总   
原创 玄鹄安全  高级红队专家   2024-12-16 02:00  
  
   
# 1-前言  
  
首先感谢各位大佬客官的支持和鼓励，目前【MalDev红队开发】系列已经完成前两部分共8个章节的实战笔记梳理，基本完全复现教材中的内容，教材中缺失的命令也进行了补全，笔记章节如下：  
  
[【MalDev-00】学习环境准备](https://mp.weixin.qq.com/s?__biz=MzIzODMyMzQxNQ==&mid=2247484181&idx=1&sn=31a6e046b565327138b53e67ca18a753&scene=21#wechat_redirect)  
  
  
[【MalDev-01】基础入门](https://mp.weixin.qq.com/s?__biz=MzIzODMyMzQxNQ==&mid=2247484191&idx=1&sn=b2183b3d01eb0d7caffe45c4e144a02a&scene=21#wechat_redirect)  
  
  
[【MalDev-02】注入基础与实战](https://mp.weixin.qq.com/s?__biz=MzIzODMyMzQxNQ==&mid=2247484213&idx=1&sn=0438525f80b4a122f13af1534364d173&scene=21#wechat_redirect)  
  
  
[【MalDev-03】劫持基础及实战](https://mp.weixin.qq.com/s?__biz=MzIzODMyMzQxNQ==&mid=2247484214&idx=1&sn=8edb082d8e925cb38e7721a36a57f69c&scene=21#wechat_redirect)  
  
  
[【MalDev-04】API Hook基础与实战](https://mp.weixin.qq.com/s?__biz=MzIzODMyMzQxNQ==&mid=2247484215&idx=1&sn=7c1a8158c344933f0dd5f21d166de772&scene=21#wechat_redirect)  
  
  
[【MalDev-05】持久化基础与实战-1](https://mp.weixin.qq.com/s?__biz=MzIzODMyMzQxNQ==&mid=2247484220&idx=1&sn=13b981f275c8b834be415d7400710e89&scene=21#wechat_redirect)  
  
  
[【MalDev-05】持久化基础与实战-2](https://mp.weixin.qq.com/s?__biz=MzIzODMyMzQxNQ==&mid=2247484253&idx=1&sn=9f62887a4210dccbf03bcd1cda8ef1ab&scene=21#wechat_redirect)  
  
  
[【MalDev-06】提权基础与实战-1](https://mp.weixin.qq.com/s?__biz=MzIzODMyMzQxNQ==&mid=2247484254&idx=1&sn=231342f0f09c27072435522d395b806a&scene=21#wechat_redirect)  
  
  
[【MalDev-06】提权基础与实战-2](https://mp.weixin.qq.com/s?__biz=MzIzODMyMzQxNQ==&mid=2247484255&idx=1&sn=77115801ceb65bdfee1d5e005c789206&scene=21#wechat_redirect)  
  
  
[【MalDev-07】Anti-Debugging反调试-1](https://mp.weixin.qq.com/s?__biz=MzIzODMyMzQxNQ==&mid=2247484286&idx=1&sn=af36cbd4ddf15022cbe66b08e92b0e58&scene=21#wechat_redirect)  
  
  
[【MalDev-07】Anti-Debugging反调试-2](https://mp.weixin.qq.com/s?__biz=MzIzODMyMzQxNQ==&mid=2247484291&idx=1&sn=e625c68e03d369e0e347fbd3a967cb0b&scene=21#wechat_redirect)  
  
  
[【MalDev-07】Anti-Debugging反调试-3](https://mp.weixin.qq.com/s?__biz=MzIzODMyMzQxNQ==&mid=2247484338&idx=1&sn=9027a615b51110970118c7542b5d989f&scene=21#wechat_redirect)  
  
  
[【MalDev-08】反虚拟机](https://mp.weixin.qq.com/s?__biz=MzIzODMyMzQxNQ==&mid=2247484339&idx=1&sn=3f7607badf404e2423c94c3f7f866e6e&scene=21#wechat_redirect)  
  
  
[【MalDev-09】对抗反汇编-1](https://mp.weixin.qq.com/s?__biz=MzIzODMyMzQxNQ==&mid=2247484340&idx=1&sn=38983d7420c1638bdc816e1e7f159921&scene=21#wechat_redirect)  
  
  
[【MalDev-09】对抗反汇编-2](https://mp.weixin.qq.com/s?__biz=MzIzODMyMzQxNQ==&mid=2247484341&idx=1&sn=d4e6bb2d864b4dca24cc7b8cc07f1933&scene=21#wechat_redirect)  
  
  
[【MalDev-10】免杀-1](https://mp.weixin.qq.com/s?__biz=MzIzODMyMzQxNQ==&mid=2247484342&idx=1&sn=6aa22db05980732baa5b1ea0c1b89c34&scene=21#wechat_redirect)  
  
  
[【MalDev-10】免杀-2](https://mp.weixin.qq.com/s?__biz=MzIzODMyMzQxNQ==&mid=2247484343&idx=1&sn=491225b73b55711f66cddec178cd8201&scene=21#wechat_redirect)  
  
  
[【MalDev-10】免杀-3](https://mp.weixin.qq.com/s?__biz=MzIzODMyMzQxNQ==&mid=2247484344&idx=1&sn=23bea36464fb1ec449f66047871fdf87&scene=21#wechat_redirect)  
  
  
目前第一和第二部分笔记PDF文档已经上传到【红队研习社】QQ群  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VZNmh6ic5umfAwo27ichgO5dI99KVZnKQ92AB2kmoHBJB0L73PV1QMRg6gkNldJYibJ1bzj2XJNU7TDyygjDkKCvg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VZNmh6ic5umcMmRzLqQzpgibtYDxKKBECPALApyibib22FUOEd9CNZgia03epQ5BUlgxFGTTxHbBfZVCyPvmJEoszQQ/640?wx_fmt=png&from=appmsg "")  
  
各位同学可以扫码免费加群获取PDF文档  
# 2-后续计划  
  
这套教材共计四个部分，主要技术内容是前三部分，目前我们已经完成前两部分的笔记，后续也会急需更新，但发现越往后大家的关注度和阅读量就较少很多，学习一本书能长期跟进坚持学习是一件不容易的事情，我也会尽量坚持更，欢迎大家监督鼓励，但后续更新周期可能不会这么稳定了  
  
因为计划花一些精力做一个收费学习群组的计划，之前也进行了投票调研，投票情况如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/VZNmh6ic5umcMmRzLqQzpgibtYDxKKBECPyyovPXDkia3zhshXguRqXAyWYSUxxhXUpsfvlic3ejmD9wwJHgOPUfoA/640?wx_fmt=png&from=appmsg "")  
  
  
结合之前OSCP笔记系列（[OSCP | 教材笔记汇总下载](https://mp.weixin.qq.com/s?__biz=MzIzODMyMzQxNQ==&mid=2247483846&idx=1&sn=f288a2d134a255ad779e25df8a4dbbcf&scene=21#wechat_redirect)  
）重新梳理渗透测试流程和体系框架，按照日常工作及考试中的干货结构进行框架重构：  
  
1-扫描探测  
  
2-出口权限获取  
  
3-权限提升  
  
4-横向移动  
  
按照上面框架进行梳理完善，内容覆盖OSCP、CPTS、CRTO等，会融合各教材内容不断完善，适合有一定计算机基础入门安全的同学，以及准备上述考试认证的同学，这套笔记会不断更新完善，通过内部QQ群方式有偿分享交流  
  
早鸟价（截止2025年1月31日）：3389元（笔记终身可下载）  
  
有兴趣的同学可以微信交流  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/VZNmh6ic5ume1vsTAxTFAQx5IQbOQ0NRjJBPWYhvUyFrfK38HCtufXZMaOLHCrNndOVM0dnV3pEkltL3m6SE6rA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
