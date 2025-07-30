> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxMTY1MTIzOA==&mid=2247484678&idx=1&sn=8fb6a009659a1f1fb876aa73c199c9d7

#  【应急响应】记OpenAI爬虫造成的数据流量异常事件排查  
 剁椒Muyou鱼头   2025-06-21 08:34  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4lX6c4yYnERUGvnHo7SQreGiboYBj0ib7TlaUx1DKtEGlU8mqS9ZtLZRw/640?wx_fmt=gif "")  
  
**阅读须知**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4lX6c4yYnERUGvnHo7SQreGiboYBj0ib7TlaUx1DKtEGlU8mqS9ZtLZRw/640?wx_fmt=gif "")  
  
  
****  
**本公众号文章皆为网上公开的漏洞，仅供日常学习使用，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。**  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把**剁椒Muyou鱼头**  
“设为星标”，否则可能就看不到了啦！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2hvEA8gEIeGOEiba9uWicXD01hM2Bw8oTpcNCZl68Bj8T0aLpOHAMFCv9Qd6KeeQgTscOURdQUDbLw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/92Yia6FpSFA2QiaAzq0Dumm39PGIsC7mk4Z7hc6oGV6C6IwibzfQUM1oq1yUciadAKQ3Ap29o8GGnBU52wXgSSicBxQ/640?wx_fmt=gif "")  
  
  
****  
**2025/06/05 星期四**  
  
**多云·西南风5级**  
  
  
//01 前言  
  
  
    最近协助处理了一起  
数据异常出境事件，简单总结报告来说每天都有400M-1GB的数据流量流向多个国家，通联几万次，累计数据总流量通常可以达到几十GB的流量。通过前往现场排查后，发现此次  
数据流量异常出境事件是因为  
OpenAI爬虫造成的，随即分享了此次文章。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2xfjHtB7pBmP4uNia1exE40XsLenKJhI5mujBk8cUeVhMeQRyicMk3mformWcxWvzpGib5oEJ9HKLTA/640?wx_fmt=png&from=appmsg "")  
  
  
//02   
GPTbot  
  
  
      
GPTbot是OpenAI  
在2023年8月推出  
开发的一个网络爬虫，主要用于自动收集公开可用的网页数据，以帮助训练和改进其AI模型。  
GPTbot会爬取公开的网页内容（文本、代码等），用于扩展训练数据集，提升AI的语言理解能力。  
通过分析更多样化的数据，改进AI的准确性、多样性和上下文理解能力。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2xfjHtB7pBmP4uNia1exE400JNDDmmBRmn2WuWOal4zxrfFKMCssZ06QSAKFbxmepHQENrQmyZgWw/640?wx_fmt=png&from=appmsg "")  
  
  
    OpenAI此前表示该工具遵守付费墙规则，不抓取需付费内容及个人身份信息，网站所有者可通过修改robots.txt文件或屏蔽指定IP地址限制其访问。尽管OpenAI强调数据收集旨在提升模型性能，但其操作引发了关于隐私保护、版权合规及数据安全的争议。  
除此之外，OpenAI还公布了OpenAI使用的爬虫IP地址，也可以根据 IP 地址来拒绝访问。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2xfjHtB7pBmP4uNia1exE40mrgibwDzZz206wDUSnvG9gLg1ib0p4pNgZMpSicrkic186B21paR84SZgA/640?wx_fmt=png&from=appmsg "")  
  
  
//03   
日志  
排查  
  
  
      
该套出现问题的系统使用  
Nginx搭建，通过访问  
Nginx保存的  
access.log  
日志文件，发现足足有300多个GB。第一次见这么大的日志文件，且该日志文件无法直接使用文本打开，否则电脑根本处理不了。只能现在服务器中备份出来外接移动硬盘放在主机上进行排查，这里推荐一款工具  
LogViewPro，  
一款文本日志查看软件可以秒开  
任意大小的文件  
(4GB或者更大),支持高亮某行文字(例如警告,错误)。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2xfjHtB7pBmP4uNia1exE40xztSYLP03q1xoy3ia5NDOG2WQPTW22nBqYn64jVKmy4d6D8zHjbygXg/640?wx_fmt=png&from=appmsg "")  
  
  
    简单对日志进行分析，发现  
GPTbot爬虫大量爬取网站的html、css、js、jpeg、png多个资源内容，且一天爬取访问量高达十几万次。这也多亏服务器配置好，要不然估计网站打开都得缓慢运行了。可以看到全是  
20.171.207.0/24这个C段的IP，与  
OpenAI公布的OpenAI使用的爬虫IP地址可以匹配上，全部携带了gptbot字段。理论上来说  
当网络爬虫数量达到一定规模或行为过于密集时，可能引发类似‌分布式拒绝服务(DDoS)‌ 的效果，导致网站资源耗尽、响应缓慢甚至崩溃瘫痪。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2xfjHtB7pBmP4uNia1exE402hKhKrpGjDDN2IIeSwRvIB5oMWNibvqSPvBoxXSM72icA7hc13gMKtcQ/640?wx_fmt=png&from=appmsg "")  
  
  
//04   
禁止GPTBot  
  
  
      
OpenAI表示会遵循网站的robots.txt文件中明确标示的规则。如果网站配置了禁止GPTBot抓取的标签，它理论上会停止访问该网站。简单来看，如果不想让GPTBot访问网站的内容，就得将以下代码添加到目录中robots.txt里面。  
  

```
User-agent: GPTBot
Disallow: /
```

  
      
  
    但反过来想你不想被爬，还得提前  
配置好“robots.txt”文件。这相当于把责任推给了网站的负责人，你不设置防止爬取，那我们就默认为可以爬取。这又涉及到  
使用爬虫爬取网站信息是否违法的问题，但是  
如果爬虫导致目标网站瘫痪或数据损坏，是可能被追责的。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/92Yia6FpSFA2xfjHtB7pBmP4uNia1exE404iaIIbV9IJv34M0KdcovO7ArMicLZfXRdpvELq8O6GJXzs6lpwVH5PpQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
//05 结尾  
  
  
    总结一下此次安全事件，  
OpenAI的  
GPTbot爬虫  
会爬取公开的网页内容（文本、代码等），用于扩展训练数据集，提升AI的语言理解能力。当每天无时无刻都在爬取，且被爬取的网站信息过多时会产生大量的异常流量问题，最好还是按照要求设置一下  
robots.txt文件吧，要不然你的出口可能和境外产生大量的通联数据流量。  
  
  
  
    
END   
  
  
   
作者 | 剁椒Muyou鱼头  
   
  
I like you,but just like you.  
  
我喜欢你，仅仅如此，喜欢而已~  
  
  
  
  
**********点赞在看不迷路哦！**  
  
  
