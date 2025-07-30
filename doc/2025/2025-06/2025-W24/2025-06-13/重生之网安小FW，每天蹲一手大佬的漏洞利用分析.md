> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzMzE5OTQzMA==&mid=2247487149&idx=1&sn=c8e2becd3ec6a5c4d7b01692cddc2b6f

#  重生之网安小FW，每天蹲一手大佬的漏洞利用分析  
原创 chobits02  C4安全团队   2025-06-13 09:36  
  
## 前言  
  
事情是这样的，最近和认识的师傅那边拿到了一堆系统源码，打算审计看看，情况好的话挖个0 day交平台换奖励，运气差的话实在挖不出就往各大网安社区投稿代码审计历史漏洞文章，学漏洞和赚钱两不误。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06HpagRWYl9NOtXN9wDJ0ibDdCwAEhjgibaJjf1kbIg2fmpEJib1PJDyBTg/640?wx_fmt=png&from=appmsg "")  
  
然后挑系统挑了用友NC，被各种漏洞不同的请求URL规则整的死去活来，还要担心自己源码全不全，漏洞所在那个模块有没有。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06l6hKkbGjL6FW64YCGoXqOu9eHSKpDg5ibL7fasDsfgNB5rSJiaSsE4nw/640?wx_fmt=png&from=appmsg "")  
  
在网上搜索用友NC相关漏洞的时候，发现了一个大佬经常更新漏洞分析文章的博客，网上基本仅此一家。地址：  
https://mrxn.net/  
  
  
后续  
  
可以看看今天刚更新一篇用友NC的漏洞分析文章，在此之前网上都是没有该漏洞信息的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06RCzV5cHyAEDmYR3c8t4egUO0JFU3Tb3UPjLOlhvuiakqztGTEOx5CCQ/640?wx_fmt=png&from=appmsg "")  
  
用友NC相关的漏洞分析文章就要有十几篇（都是带源码分析的）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06wdxKGPeKIsibc2sqSVoK6TAPlpIwygHCYXBz2TSu2oNjEvA7ibxD6V5g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06ZlxxqtJqXXqYKPGNiccIQlUTs9FwtzXxHRk31UqCMCdGEEHQoqJHv1g/640?wx_fmt=png&from=appmsg "")  
  
好家伙，蹲到宝藏网站了  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06OSr2SvShCVknWcWJfDJxxgibItBZibdic7k25AL6uvnAUB5hVwfMf88lw/640?wx_fmt=jpeg&from=appmsg "")  
  
咱们来挑一个文章顺着分析下，6月12号更新了一个用友NC的SQL注入漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc065LCjp3CcWPvpxXyvRVNDP2h8WqMzr4oLT0a0rvPM2V0Y8B8bicTPngw/640?wx_fmt=png&from=appmsg "")  
  
POC如下，使用延时注入Oracle数据库判断是否存在漏洞，这里数据库可能不是Oracle的所以POC内容会变  

```
POST /ebvp/register/qrySubPurchaseOrgByParentPk HTTP/1.1
Host: nc65.mrxn.net
Content-Type: application/x-www-form-urlencoded


pk_group=1' AND 1337=DBMS_PIPE.RECEIVE_MESSAGE('any',3)--
```

  
用我本地代码搜索一下，搜索关键字  
RegCommonController  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc068vic3KHC9236MjUQoqziaqN4wE1dqI4VR0bHC5oP1qKGmLQTNBbG7gmg/640?wx_fmt=png&from=appmsg "")  
  
加入jar包反编译查看，搜索  
qrySubPurchaseOrgByParentPk  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06rpQHEAjUMoibYiaz4IFyzasRiaCPdoFOQ12TnZN2reK4atoe9lc4IeeeQ/640?wx_fmt=png&from=appmsg "")  
  
  
方法部分代码如下，传了俩参数进入  
queryRegisterOrgsFilterByName  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06TibTjMS8518amGdbWE3c7iajy3R5qvjNHD9fkCdTKZjDTzrDZGhmz2FQ/640?wx_fmt=png&from=appmsg "")  
  
方法咋来的，在ISRMRegisterQueryService里面，继续搜关键字  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06hgkpfXS9thibpXibR7GGoqHGcfeBgicCibxG3hiayRTib83MSXQcmic76LMsA/640?wx_fmt=png&from=appmsg "")  
  
继续反编译，可恶方法代码到头了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06AlAvliaVmdAxdAJhvwqCxbotuA2BrtS6yTOGDCHkibmnbBMEpZIa8vSQ/640?wx_fmt=png&from=appmsg "")  
  
走到这利用链子断了，要么去找代码全一点的jar包或者装完整一点版本的用友NC，要么就只能找遗留的class文件  
  
不过我选择摆烂，直接看大佬的代码分析，恰个柠檬  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06UmbtIveY9eeV6micXvGnnArMEKtMeoDNjHIibsfWpfDPflb4g7HWUA8w/640?wx_fmt=png&from=appmsg "")  
  
就俩段代码，SQL参数直接append进去查询，然后就能注入了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06W1bwWv44iajEspqhxeMnx2y84I5XyNddsUdaRzDib77Cpjuyck2eVUpw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06XDkSDv98hGhaBnDo0oD9ianC6s1oYHbmz5ib21M4dPTibc7Wg9XDuIGRQ/640?wx_fmt=png&from=appmsg "")  
  
找个目标试一下，复现成功，以后每天在这里蹲漏洞POC咯  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06ibz6zYhBSJRWF3xUsOnxcP4wviaJRIBMRwWYlyS6GjViaeBtjqsicibfUjQ/640?wx_fmt=png&from=appmsg "")  
  
最后总结  
  
感兴趣的可以公众号私聊我  
进团队交流群，  
咨询问题，hvv简历投递，nisp和cisp考证都可以联系我  
  
**内部src培训视频，内部知识圈，可私聊领取优惠券，加入链接：https://wiki.freebuf.com/societyDetail?society_id=184**  
  
**加入团队等都可联系微信：yukikhq，添加即可。**  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_gif/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06sHdBhSTMMClOr5wLWmLYIl6Yry9n3ZIL97tylQib5YLOuJFxndeFMEg/640?wx_fmt=gif&from=appmsg "")  
  
END  
  
  
  
****  
  
  
  
  
  
  
  
  
