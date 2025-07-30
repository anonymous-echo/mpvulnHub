> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NTMxMjQ4OA==&mid=2247486206&idx=1&sn=54ac4aeb8ed3a97da9e43223f1b071af

#  XBOW 发现Wordpress 任意文件读取漏洞的过程  
外文转  AI与安全   2025-07-17 00:07  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rhmRSVBNbicoic0Oz3Xia3kgibNPynBOuMXc9SM0kxWibk77OTwIm2sE2Lphe9DXEuH7440Gomric3ZxFuZicqdPPubYA/640?wx_fmt=png&from=appmsg "")  
  
XBOW最近很火，他们声称是用AI系统做全自动化渗透（看上去也确实是AI系统），但未透露任何技术细节。他们最近在Hackone上排名达到第一(见上图）。  
  
HackerOne是漏洞悬赏程序和解决方案的领先提供商，帮助组织直接与道德黑客合作，主动保护其资产安全，能在这里排第一，非常不易。  
  
虽然缺少技术细节，我们仍然可以阅读一些他们的资料，推测一些能力出来。 以下文章来自于他们的博客，是一个发现Wordpress漏洞的过程，过程很详细，该漏洞已经被接受。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fRp5p4jMuDQjdXQXUMBDtPtLS0iaiaxVKblUBecgRUn30Lv2liaIUfnwcVib2D28Om4F0LpOd4oiah0psOJlRBHqewA/640 "")  
  
正文  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jLdw7EZFJmIjAic1276gZeyjcsS9UMqa3VkvD2WgU11EyJAoVCSagkO3Kmia89jgusIXDficZIgTTb6ia32cibxVKgQ/640 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rhmRSVBNbicoic0Oz3Xia3kgibNPynBOuMXcT1mao7icXCamZWvrNa35WccS0e5iazIfFjowmTQUyMY7ic5WSTTyTWmxw/640?wx_fmt=png&from=appmsg "")  
  
  
面对现实：如今的 Web 应用已是庞然大物。面对琳琅满目的插件、集成和小部件，维护它们的安全就像一场永无止境的打地鼠游戏，这不足为奇。正因如此，我们打造了 XBOW——一个由人工智能驱动、永不休眠、始终保持好奇心的安全渗透测试工具。  
  
在这篇文章中，我将分享 XBOW 如何在热门 WordPress Ninja Tables 插件中嗅探到一个隐蔽的任意文件读取漏洞的故事。XBOW 并非偶然发现这个漏洞——它绘制了站点地图，搜索了各个端点，并持续挖掘，直到找到宝藏。  
  
如果你对安全、开发感兴趣，或者只是想看看在真实应用中让人工智能自由运行会发生什么，那就继续阅读吧。本文将带你深入幕后，了解自主渗透测试的实际运作方式。发现 WordPress Ninja Tables 中的任意文件读取漏洞  
  
此次探索始于 XBOW 作为 HackerOne 漏洞赏金计划评估的一部分，对目标网站进行侦察。XBOW 首先系统地搜索可能接受文件路径参数的端点。这项初步探索是识别路径遍历漏洞潜在载体的关键第一步。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rhmRSVBNbicoic0Oz3Xia3kgibNPynBOuMXcuXA4u3QqWWLpUu9jMb6FSmlXLkl9FVjLxiar8tRU6KHnosyJDQF7j9Q/640?wx_fmt=png&from=appmsg "")  
  
  
XBOW 迅速识别出它正在处理的是一个 WordPress 网站——robots.txt、站点地图以及所有常见的可疑内容。这有助于它锁定最有可能引起关注的端点类型。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rhmRSVBNbicoic0Oz3Xia3kgibNPynBOuMXcUNX7wCQdYXAA6mhLxfhlKH5Ng7Qwu8WMeRgtdm0Pube361aibyqAn8g/640?wx_fmt=png&from=appmsg "")  
  
### 针对 WordPress 端点的侦察  
  
在建立了 WordPress 上下文后，XBOW 列举了一系列可能处理文件的端点，包括 REST API 和 AJAX 端点。这种系统性方法确保覆盖了常见和不太明显的向量。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rhmRSVBNbicoic0Oz3Xia3kgibNPynBOuMXcPJ6kDgJaUnr6jvjUCc0tmmAbSoWa8dKx5VBFUybNEvia0KXECFG16hA/640?wx_fmt=png&from=appmsg "")  
  
  
  
但正如通常的情况一样，显而易见的途径往往行不通。没有目录列表，LFI 也难以轻易获胜。于是 XBOW 改变了思路，开始研究博客文章、代码示例以及其他任何看起来有希望的东西。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rhmRSVBNbicoic0Oz3Xia3kgibNPynBOuMXcEKAW3tFSmqCyMMoOvaqueAPb7cSr9KuyVFQqGd837Hlqhq9Z8qKbWA/640?wx_fmt=png&from=appmsg "")  
  
  
### 发现下载功能  
  
事情开始变得有趣了。XBOW 偶然发现了页面上一些 JavaScript 代码
```
/api-[REDACTED]/
```

，提示用户执行某个 
```
ninja_table_force_download
```

操作——其中包含一个用户控制的
```
url
```

参数。这真是一个典型的“这可能会发生”的时刻。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rhmRSVBNbicrxruzWH8YQODnfmWaia7ibASo5mTcSjEgk5lpCOiaUibKoW2rsKbgzMEXiaoetrErHVeBg3Eiapx94jUXw/640?wx_fmt=png&from=appmsg "")  
  
  
XBOW 编写了一系列利用尝试脚本，以各种文件路径和方法瞄准疑似存在漏洞的端点，展示了一种发现漏洞的系统性方法。  
  
现在是时候使用一些老式但又聪明又专注的暴力破解方法了。XBOW 编写了一个脚本，使用一组目标文件路径和不同的方法（GET、POST 和 AJAX 请求）来攻击这个端点。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rhmRSVBNbicrxruzWH8YQODnfmWaia7ibASRICuDxIicGz7SaRUEm4CA8BHtbRj3RmaILL2axicbrajyVbQS9EkN5pA/640?wx_fmt=png&from=appmsg "")  
  
  
### 识别细微的指标  
  
XBOW 对 WordPress 的细致理解最终得到了回报：虽然大多数尝试都返回了 403 Forbidden（暗示存在 WAF 或其他安全控制措施），但 AJAX 端点却返回了 422——这意味着操作确实存在，但验证出了问题。这条线索值得追踪！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rhmRSVBNbicrxruzWH8YQODnfmWaia7ibASXoKIDGcJDtj62fbBZjXibUjBqlB1lXw57VF4RPSlYibYzBEUcVX5TMFQ/640?wx_fmt=png&from=appmsg "")  
  
  
XBOW 暂时偏离了主题，但随后又回到了有希望的线索
```
ninja_table_force_download
```

，深入挖掘 JavaScript 并获取发出合法请求所需的随机数。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rhmRSVBNbicrxruzWH8YQODnfmWaia7ibASaPyOaudGCGKbhibd2UuHbWqm7ehZh1NpxyOfSdKeSianFQfqBDXgBy2A/640?wx_fmt=png&from=appmsg "")  
  
  
XBOW 找到了连接下载的精确 JavaScript，确认需要 nonce 并准确显示请求应如何：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rhmRSVBNbicrxruzWH8YQODnfmWaia7ibASdU7IlG4SoXnnTH5ReJs16wYjxZmAzmZQL2vuG3gHggLIGrClCzO0Og/640?wx_fmt=png&from=appmsg "")  
  
  
### 任意文件读取已确认  
  
有了正确的随机数和请求格式，XBOW 回到脚本，然后——砰——终于成功了。 
```
/etc/os-release
```

返回 200 和文件内容。中奖了。  
  
  
  
存在漏洞的URL： 
```
https://[REDACTED]/wp-admin/admin-ajax.php?action=ninja_table_force_download&url=/etc/os-release&ninja_table_public_nonce=b69b8c2ef0
```

  
  
因此，即使像这样的文件
```
/etc/passwd
```

被锁定，XBOW 的坚持也得到了回报——证明 Ninja Tables 插件可以被诱骗读取任意文件。  
### 影响  
  
该任意文件读取漏洞允许攻击者访问敏感的服务器文件，可能导致关键信息泄露，例如来自“wp-config.php”的数据库凭据。  
  
鉴于 Ninja Tables 插件的流行度，此漏洞的影响范围非常大，影响了众多 WordPress 网站和多个漏洞赏金计划。  
### 披露与回应  
  
任意文件读取漏洞确认后，我们立即启动了负责任的披露流程。我们与 Ninja Tables 插件的维护人员分享了漏洞细节，他们的响应速度非常快，展现了他们对安全的坚定承诺。  
  
我们对他们迅速的回应和解决此问题的速度表示感谢。  
  
  
  
参考： https ://ninjatables.com/docs/change-log/#521-date-july-9-2025  
  
原文链接  
  
https://xbow.com/blog/xbow-ninja-tables/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/55LhWNqR1eEIvTRaeSGqOic2WdN4owxXx4UzauQgeevfp7WbH82nic0ict9rBIHza7ZkYRxXupK0a8IIPDyicUpjPg/640 "")  
  
END  
  
  
  
