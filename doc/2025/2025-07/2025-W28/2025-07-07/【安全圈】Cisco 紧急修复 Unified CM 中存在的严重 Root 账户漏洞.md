> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070540&idx=4&sn=6fe8ab50588c2035d0ee523bcf26b3ea

#  【安全圈】Cisco 紧急修复 Unified CM 中存在的严重 Root 账户漏洞  
 安全圈   2025-07-07 11:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylhhVaU4PoHklxWs6tZerY0TWImg32XaPNrcOFR0GZZNIawurcXnBDqcibVcKr7sl24rbRySglaFfNw/640?wx_fmt=png&from=appmsg "")  
  
网络设备巨头 Cisco 公司近日发布紧急安全通告，并针对其 Unified Communications Manager（统一通信管理器，简称 Unified CM）及 Session Management Edition（SME）中的一个关键漏洞（CVE-2025-20309）发布修复更新。该漏洞被评为 **CVSS 10.0 的最高严重等级**  
，表明它极易被远程攻击者利用，后果极其严重。  
### 漏洞详情  
  
Cisco 公告指出，该漏洞源于设备中**预设的静态 root 用户凭据**  
，原本用于开发测试，但在生产环境中仍然存在。这些凭据不可修改也不可删除，使攻击者可**无需身份验证即可远程以 root 身份登录系统**  
，从而获得完全控制权限。  
  
一旦成功利用该漏洞，攻击者可：  
- 访问和窃取敏感通信数据；  
  
- 篡改或瘫痪语音通信服务；  
  
- 将受害系统作为跳板，攻击内部网络的其他系统。  
  
### 受影响版本  
  
漏洞影响如下版本的 Unified CM 与 Unified CM SME：  
  

```
版本范围：15.0.1.13010-1 至 15.0.1.13017-1

```

  
  
漏洞存在于系统核心，不受配置影响，因此几乎所有部署此版本的客户都面临风险。  
### 官方响应与建议  
  
Cisco 表示该漏洞尚未被发现遭到实际利用，但**没有可行的临时缓解措施**  
。官方已发布修复补丁，强烈建议所有客户**立即升级**  
受影响的系统。  
- 拥有服务合同的用户可通过正常渠道获取补丁；  
  
- 非合同用户可联系 Cisco TAC（技术支持中心）免费获取更新。  
  
### 安全专家建议  
  
安全公司 Black Duck 的首席工程师 Ben Ronallo 指出：  
  
“组织应立即升级系统，并参考 Cisco 提供的威胁指标，启动应急响应流程。该漏洞具备高危权限利用能力，可能被用于数据泄露或网络钓鱼攻击。”  
  
  
 END   
  
  
阅读推荐  
  
  
[【安全圈】Linux“sudo”严重漏洞：任何用户均可接管系统](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070525&idx=1&sn=7b6337e89711c9e9f413dd1cb303bd76&scene=21#wechat_redirect)  
  
  
  
[【安全圈】订单爆了，突然“崩了”！“全国人民都在薅羊毛”，平台紧急回应](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070525&idx=2&sn=3c5d67bf949efc3dafaeafca5cb1d3d5&scene=21#wechat_redirect)  
  
  
  
[【安全圈】德国全面封杀DeepSeek，中欧数据冲突升级](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070525&idx=3&sn=165c17d95e26e385745a0b80adf28250&scene=21#wechat_redirect)  
  
  
  
[【安全圈】你的耳机在被偷听！20+音频设备曝出漏洞：索尼、Bose、JBL等沦陷](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652070509&idx=1&sn=6cf6b923bca528cc5cc03d57ebcc2bf6&scene=21#wechat_redirect)  
  
  
  
  
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
  
  
