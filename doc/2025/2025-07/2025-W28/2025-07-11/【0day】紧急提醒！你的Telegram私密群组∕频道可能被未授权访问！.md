> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxNzY5MTg1Ng==&mid=2247489948&idx=2&sn=79ab72f7569e04c16df9eed805a95538

#  【0day】紧急提醒！你的Telegram私密群组/频道可能被未授权访问！  
 富贵安全   2025-07-11 03:04  
  
## 免责声明  
> ❝  
> 由于传播、利用本公众号"隼目安全"所提供的信息而造成的任何直接或者间接的后果及损失,均由使用者本人负责,公众号"隼目安全"及作者不为此承担任何责任,一旦造成后果请自行承担!如有侵权烦请告知,我们会立即删除并致歉谢谢！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9HKdHo8BvC2iclAicrYMZiaAf3O6mzeibW1LVMcSKUDA5tLEN6ffTM1CfzqRKJk3eNmHrlaXUcZc15niczOzFuNWMFg/640?wx_fmt=png&from=appmsg "")  
  
在此前黄豆安全实验室发现了
```
“Telegram消息屏蔽绕过0day”
```

  
  
[黄豆安全实验室捕获在野telegram消息屏蔽绕过0day](https://mp.weixin.qq.com/s?__biz=MzkzNjczNzEyMw==&mid=2247484417&idx=1&sn=d8b44f163ca18983f7d8ddc3d5b1a589&scene=21#wechat_redirect)  
  
  
经过我们更深入的研究，有了如下发现：  
  
一、**漏洞深度利用风险**  
：  
- 原初始屏蔽机制漏洞可被进一步深度利用，影响用户的权限和查看内容  
  
- 该漏洞影响范围将覆盖所有私密频道和群组  
  
二、**平台机制缺陷**  
：  
- 发现Telegram屏蔽机制存在系统性缺陷  
  
- 涉及频道指向和用户权限管理等多个关键环节  
  
**目前我们已确认该漏洞可导致：**  
- 敏感数据泄露。各种媒体、文件一览无余。对于攻击者已经加入或已屏蔽的频道，删除媒体、文件后攻击者仍可以查看  
  
- 用户账户安全，可能存在账号密码泄露等情况……  
  
- 非授权访问所有私密群组、频道  
  
- 权限提升风险  
  
Tips：以上内容除非Telegram官方修复，否则均无法防范。  
  
下图为
```
“影响用户的权限和查看内容”
```

  
证明，可以看到频道名与下方频道消息所显示的频道名截然不同，频道原名为*ECHNOLOGY……，而下方频道消息所显示的频道名为K.P……  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9HKdHo8BvC2iclAicrYMZiaAf3O6mzeibW1LnxTkGSzmqfL13rfbHRwuEpTFI4lOh5K1KVQDbjEeKfWaibylop3OQ4g/640?wx_fmt=png&from=appmsg "")  
  
下图为
```
“影响范围将覆盖所有私密频道和群组”
```

  
证明，这是一个老外的家庭私密频道，媒体为其孩子的照片（已打码），可见频道描述页面无公开频道字样与链接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9HKdHo8BvC2iclAicrYMZiaAf3O6mzeibW1LTib8Oibykl5hXLoYfHl4yOAicdiaf169LWyP0hofUTfpM00SUeO4lZ41iag/640?wx_fmt=png&from=appmsg "")  
  
下图为
```
公开频道
```

  
的描述页面，可见描述页面存在公开频道字样与链接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9HKdHo8BvC2iclAicrYMZiaAf3O6mzeibW1L129GGOOKy1f9o1MZqlCeicUzhcMNW44W9siaDibNur0OVfdCjjOfCc3lQ/640?wx_fmt=png&from=appmsg "")  
  
由于该漏洞仍存在深度利用和发掘价值，故
```
暂不公开
```

  
利用过程，原黄豆安全实验室所发现的
```
“Telegram消息屏蔽绕过0day”
```

  
已被修复，但仍然存在绕过方式，只是更为复杂。  
  
结论：该漏洞可以查看所有私密频道、群组的文件、消息记录、链接和图片视频等，包含已经封禁的频道与群组。且除非官方修复，则均无法避免。对用户数据以及隐私安全造成严重威胁，但可以用于取证和各种神神秘秘操作。  
# 温馨提示  
  
切勿在私密群组、频道中存储例如账号、密码、个人信息数据等敏感内容。如已经在私密频道或群组存储了敏感信息的，建议立即删除。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/9HKdHo8BvC2iclAicrYMZiaAf3O6mzeibW1LjXMzTibQy1puEUBcC0WmLcenpSIhzzhUYLvljjJQowCpicUPX4iaETMwQ/640?wx_fmt=png&from=appmsg "")  
  
  
文稿 | x8i、骨头  
  
制作 | x8i  
  
审发 | 隼目安全  
  
