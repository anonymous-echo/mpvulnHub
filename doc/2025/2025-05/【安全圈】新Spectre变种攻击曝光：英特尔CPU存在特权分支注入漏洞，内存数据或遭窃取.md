#  【安全圈】新Spectre变种攻击曝光：英特尔CPU存在特权分支注入漏洞，内存数据或遭窃取   
 安全圈   2025-05-16 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
Intel  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyliayKhlPFNUbibCF4s1UHbmEEqL7DXOICTnMtu8YgXcPtDKyq1ic95WwpQUvNxMbicozZyibN7pn1VlWvQ/640?wx_fmt=png&from=appmsg "")  
  
苏黎世联邦理工学院（ETH Zürich）的安全团队近日披露了英特尔处理器中的一个新型侧信道漏洞——**分支特权注入（Branch Privilege Injection, BPI）**  
。该漏洞允许攻击者利用CPU的预测执行机制窃取内存中的敏感数据，这标志着自2018年首次曝光的Spectre漏洞至今仍持续衍生新变种。  
  
研究显示，攻击者可通过制造**分支预测器竞争条件（BPRC）**  
，在处理器为不同权限用户切换预测计算时突破安全隔离。计算机安全组负责人Kaveh Razavi指出："无特权的攻击者能借此读取其他用户的处理器缓存及工作内存。"英特尔已为此漏洞（CVE-2024-45332，CVSS v4评分5.7）发布微码补丁，但承认其影响了所有现代处理器，可能通过本地访问导致信息泄露。  
  
与此同时，阿姆斯特丹自由大学VUSec团队揭示了名为**Training Solo**  
的Spectre v2自训练攻击。与早期攻击不同，此类攻击不再依赖eBPF等沙箱环境，即可实现跨特权层的数据窃取。实验证明，针对英特尔9-11代酷睿及2-3代至强处理器的攻击（CVE-2024-28956/24495）能以17KB/s速度泄漏内核内存，甚至能突破虚拟化隔离重新启用用户-用户、虚拟机-宿主机间的传统Spectre攻击。  
  
目前英特尔已推送微码更新，而AMD则更新了Spectre/Meltdown防护指南，特别强调传统伯克利数据包过滤器（cBPF）的使用风险。专家建议用户尽快安装补丁，并关注CPU供应商后续发布的缓解措施。  
  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】Interlock勒索软件因间谍驱动的数据泄露而袭击美国国防承包商AMTEC](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069650&idx=1&sn=7da38b2af3f6c3d9d008e6e7dbf6a691&scene=21#wechat_redirect)  
  
  
  
[【安全圈】PyPI恶意软件警报:恶意的“索拉纳令牌”包瞄准索拉纳开发人员](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069650&idx=2&sn=938d25c710b282a91672b5b04220c9f5&scene=21#wechat_redirect)  
  
  
  
[【安全圈】*Telegram成犯罪温床："新币担保"黑市涉案84亿美元，牵涉杀猪盘与朝鲜洗钱](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069650&idx=3&sn=54144bc4949719692769276efdef9cf1&scene=21#wechat_redirect)  
  
  
  
[【安全圈】OpenPubkey和OPKssh中的关键身份验证绕过使系统面临远程访问风险](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652069650&idx=4&sn=d8cc7ac650197265d67dcbf81f43b31c&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
