#  AI 安全｜DIFY 大模型平台漏洞预警（已复现）   
原创 灵悉实验室  灵悉实验室   2025-05-28 08:02  
  
前言  
  
  
  
  
由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，灵悉安全团队以及文章作者不为此承担任何责任。灵悉安全团队有对此文章的修改和解释权。如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经灵悉安全团队允许，不得任意修改或者增减此文章内容，不得以任何方式将其用于商业目的。  
  
  
红蓝队技战术一手资料分享！关注我们 ❤️添加星标 🌟  
  
本文字数：544  
  
阅读时长：5～ 6in  
  
声明：仅供学习参考使用，请勿用作违法用途，否则后果自负！  
  
  
近期公司官网上线，打一波广告  
  
https://www.cybertrust360.com  
  
  
背景介绍  
  
  
  
  
Dify是一个开源的LLM应用程序开发平台。其直观的界面结合了代理AI工作流程、RAG管道、代理功能、模型管理、可观察性功能等，使用户能够快速从原型转移到生产。  
  
  
影响范围  
  
  
  
  
dify <1.4.0，fofa看了下，影响范围还是挺广的。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/TYPVL8UXJDliaFQnQhnAIsgFher8yoN87avU0XFiaogaDzI6ia4a6qS3nDIYmAicAOvW8PW8ibgjORLxhJZBicM82vpg/640?from=appmsg "")  
  
  
  
复现过程  
  
  
  
  
github issue中已知高危漏洞，目前团队已复现。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/TYPVL8UXJDliaFQnQhnAIsgFher8yoN87az9EZic8E2nCgIZsz9icbP8mXREaevXTT5ibVB9Diaa99NJfXvC9tB1PAQ/640?from=appmsg "")  
  
  
  
# 漏洞一 任意用户密码重置  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/TYPVL8UXJDliaFQnQhnAIsgFher8yoN87j7iasAUoKQia4LlUQcA43kiamfzxvIfmejtKicNN7Ivz1Z2bRtXDGeGQSQ/640?from=appmsg "")  
  
  
# 漏洞二 SSRF  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/TYPVL8UXJDliaFQnQhnAIsgFher8yoN87cuXUj7fwdZN8wdU6Znjib9aBuibzColPjEJckvhlCnibXppMqqkKf7MTQ/640?from=appmsg "")  
  
  
加固建议  
  
  
  
  
目前官方已修复，建议升至最新版本1.4.1。  
  
  
求关注  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/2x1zRIU2W4ZsOdsVsia2bqTnXJ1LN5V2LTT0eMp20FVjsaAB12wmrPKn6IgZA6cChNf0PzQhtVibX4kO7dU3QG4w/640?from=appmsg "")  
  
点个赞，证明你还爱我  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/2x1zRIU2W4ZsOdsVsia2bqTnXJ1LN5V2Lqtw7d2gxUzWZe1CicfGG2IKXMURpuPpd3vZmBoZuKaibyRSANSK3SnIA/640?from=appmsg "")  
  
扫码关注  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/2x1zRIU2W4ZsOdsVsia2bqTnXJ1LN5V2Lqtw7d2gxUzWZe1CicfGG2IKXMURpuPpd3vZmBoZuKaibyRSANSK3SnIA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/TYPVL8UXJDliaFQnQhnAIsgFher8yoN87czFrGO6SRbdtozFYbhayUibt3vvc8ibnaLSYVArjWEqpjicdZLgLe5QQg/640?from=appmsg "")  
  
  
  
