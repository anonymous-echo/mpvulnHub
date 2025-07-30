#  【安全圈】微软修复Windows 10/Windows 11上BlackLotus UEFI漏洞   
 安全圈   2023-05-10 19:02  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGyljsJVJHhaCOeUkoze16FrNjE24yjZVib01Tl7diaq0PGm6wazJMuo3K51rsrhdiagwEDicqXQtmMQlIJQ/640?wx_fmt=jpeg "")  
  
**关键词**  
  
  
  
漏洞  
  
  
  
ESET 安全研究人员于今年 3 月发现了 BlackLotus，被认为是首个可以在 Win11 系统上绕过 Secure Boot 的 UEFI bootkit 恶意软件。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylj1RNThTS5VHhX6cLofTXL6IrjuAvxpxgiamjNicicvibEmGa9ibicnwrgxT4gd9zoFcKDxvSHRJYypzXibw/640?wx_fmt=jpeg "")  
  
微软于今天面向 Win10、Win11、Windows Server 发布了 KB5025885 更新，重点修复了这个追踪编号为 CVE-2023-24932 的漏洞。  
  
  
IT之家附微软官方摘要信息如下：  
  
本文介绍如何使用由 CVE-2023-24932 跟踪的 BlackLotus UEFI bootkit 来防止安全启动安全功能绕过公开披露，以及如何启用保护和指南来更新可启动媒体。  
  
bootkit 是一个恶意程序，旨在尽早在设备的序列中加载，以便控制操作系统启动。  
  
安全启动建议 Microsoft 通过 Windows 内核的受信任启动序列从统一可扩展固件接口 (UEFI) 创建安全且受信任的路径。  
  
安全启动有助于防止启动序列中的 bootkit 恶意软件。禁用安全启动会使设备面临被 bootkit 恶意软件感染的风险。  
  
修复 CVE-2023-24932 中所述的安全启动绕过需要撤销启动管理器。这可能会导致某些设备的启动配置出现问题。  
  
2023 年 5 月 9 日的安全更新提供了配置选项，用于手动启用安全启动绕过保护，但不会自动启用这些保护。  
  
在启用这些保护之前，必须验证设备和所有可启动媒体是否已更新并准备好进行此安全强化更改。  
  
使用 Microsoft 基于云的解决方案的客户应遵循 更新可启动媒体 / Azure 云 中的指南。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyliavGLlka4ryB5YcPwZDUbQeOk2HTbEldxIlI1jSbFSO9UwQAaaibqictAlMu21nrGBicO8DMgwpQwHicQ/640?wx_fmt=png "")  
[【安全圈】只要一部“诺基亚”，15秒就能偷走一辆车](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652033652&idx=1&sn=797b61c94be70a0742295f127ceb2e62&chksm=f36ffe34c4187722a97beeb2d21605a276ab2fb97b4f42228590a2acbe65c11ecba4d51aa68b&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyliavGLlka4ryB5YcPwZDUbQeq0aKa6eVzjIj15eoicmiaianu46Dxr1epA4MRsevou9P2iaztK3FibV9XIQ/640?wx_fmt=png "")  
[【安全圈】三星电子为何禁止AI工具？](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652033607&idx=1&sn=94ed923ad31b5356baf15324f363b43a&chksm=f36ffe07c4187711262c0fc19fb8d3c22cad8dbb2e75e17ca5b80e9339ca9eedf09183c2d729&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyliavGLlka4ryB5YcPwZDUbQenwqbibUKIuCN8UtaugwpO91c8KHEzd8WPmsKbPeWfxHuyVxoEkkZEXw/640?wx_fmt=png "")  
[【安全圈】百度文库接入“文心一言”，15 秒即可帮你创作一篇文档！](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652033526&idx=1&sn=8e7773fe007e75a24d99c4c659cabaff&chksm=f36ffdb6c41874a0e3c8d2f8fee9a1b1475aa87f5eab82ec06607f52ff67bc0e8c605a795039&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGyliavGLlka4ryB5YcPwZDUbQeibkKnzYctYHKOyI8UIOjicDJx2d7J5icVtP21s0FFx29YPgP94axRkmsg/640?wx_fmt=png "")  
[【安全圈】男子雇佣“黑客”恢复聊天记录，4000元换来的却是一只插座](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652033652&idx=2&sn=c5b599489b78290d83ffeeb5d2a638bf&chksm=f36ffe34c4187722e8d90c9ecce2c7215efcede47f4395be2b5527625861131bc8823b6b4a77&scene=21#wechat_redirect)  
  
  
  
[【安全](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652030093&idx=4&sn=e988dc890e595695befbdb177d11b98c&chksm=f36fe8cdc41861dbd78f5270a42fca19c1d45cb375ef4469e8a36bef1f42620f990d03714872&scene=21#wechat_redirect)  
  
  
‍  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
