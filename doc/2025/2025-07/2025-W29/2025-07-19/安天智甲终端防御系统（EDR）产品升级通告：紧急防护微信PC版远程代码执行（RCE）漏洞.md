> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5MTA3Nzk4MQ==&mid=2650211641&idx=1&sn=ff2dc976a59a468983e558afa92a912f

#  安天智甲终端防御系统（EDR）产品升级通告：紧急防护微信PC版远程代码执行（RCE）漏洞  
 安天集团   2025-07-18 15:57  
  
点击上方"蓝字"  
  
关注我们吧！  
  
  
## 发布时间：2025年7月18日 近日，安天CERT监测到微信PC版（3.9及以下版本）存在高危远程代码执行（RCE）漏洞。攻击者可通过构造恶意聊天记录，诱导用户点击后在其终端设备上执行任意代码，可能导致敏感数据泄露、设备被控等严重后果。建议用户及时从微信官网下载最新版本进行更新。安天已于今日（7月18日）23点完成安天智甲终端防御系统主动防御规则紧急更新，可有效阻断该漏洞攻击链，有效防护该威胁。请及时升级安天智甲病毒库。请将客户端病毒库版本升级至2025071823，即可确保防护能力生效。智甲托管版用户升级策略已完成推送。安天智甲的主防基于执行体治理理念设计，面向主机环境全量执行体的全生命周期管控。不仅基于安天AVLSDK反病毒引擎的检测识别和信誉分析能力管控执行体的初始运行，同时依托驱动级主防实现细粒度的行为管控。即使是带有常见数字签名的操作系统文件、常见应用文件等高信誉执行体，依然会管控有效拦截其行为异常。可以灵活添加行为控制策略，确保安天应急响应中心可快速配置、快速升级。本次更新中我们改善了微信（PC版）的管控策略，使其即使发生漏洞利用，也无法实现执行体落地和持久化。智甲的相关机理在面对0day漏洞响应中，在防御者没有获得漏洞细节和POC代码背景下，依然可以在运行链中设置拦截点，包括对Nday漏洞响应中，在用户没有及时修补漏洞或不具备修补漏洞条件时，有效实现漏洞缓解。  
  
  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_gif/krU5D4C1q6Qp5ibY5FNyUU9Xg9IkGU3RvjPcITwHD6HnXDQo0FicqNrZIxAiaexKsIIID6F2o8doIhgmwfcxZNToA/640?wx_fmt=gif "")  
  
**往期回顾**  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5MTA3Nzk4MQ==&mid=2650206285&idx=1&sn=2914ede1c58fd13f877b8ff3d1975be2&chksm=beb9537f89ceda696be771c195f85f8f6d7f6acb28d6d730f8fb945e6826e6b60dff33f2c322&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5MTA3Nzk4MQ==&mid=2650202104&idx=1&sn=f18c0cf27d5f51cb2f7e6de1a17b5dc1&chksm=beb97cca89cef5dcbfe386ed8e4430f9d86f5f2f7cd3b9cbe52a4b985cb4cdef1dad9a8adbc3&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5MTA3Nzk4MQ==&mid=2650188804&idx=1&sn=9cf5ecd1b102a11c2252c928dc999c19&chksm=beb90f3689ce86200c9bedb9a51f26818bb836b8be2c3883650d4dff944b280b09ae299dcf1d&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5MTA3Nzk4MQ==&mid=2650187497&idx=1&sn=e0dcd78df8f12af58aedc51194c1f801&chksm=beb905db89ce8ccdbc7581557376889b857d84d28e2934b7d74fa060bb590b6daae451aefbe2&scene=21#wechat_redirect)  
  
  
