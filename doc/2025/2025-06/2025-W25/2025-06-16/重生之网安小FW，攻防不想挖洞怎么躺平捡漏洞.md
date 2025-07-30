> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzMzE5OTQzMA==&mid=2247487164&idx=1&sn=70ef1766e7b61541d1cecdce8ff717f1

#  重生之网安小FW，攻防不想挖洞怎么躺平捡漏洞  
原创 chobits02  C4安全团队   2025-06-16 01:30  
  
## 前言  
  
平时挖洞头头是道，一到攻防对着目标干瞪眼，信息收集没找到有用的目标怎么才能不被同事以为自己在躺平呢。  
  
有个好方法，对着敏感信息挖掘就行，还不必考虑漏洞怎么利用，虽然分数给的少，但好歹贡献了自己的力量，问薪无愧了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSPW5ycz43IuIiaE9JDypyHnLE0wpYs2lJK48REbaCLfdO86oPGGeEKTuUpoAyZd8uucbONVyZsiclQ/640?wx_fmt=png&from=appmsg "")  
  
首先既然挖的敏感信息，就避不开姓名、身份证、手机号/地址这类三要素的敏感信息，该怎么挖呢  
  
这里直接Google语法在各大搜索引擎收集敏感文件，挖政府和学校的有奇效  

```
site:目标域名 filetype:xls 身份证
site:目标域名 filetype:pdf 身份证
site:目标域名 filetype:doc 身份证
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSPW5ycz43IuIiaE9JDypyHneLsd54NEyXfsLkwamDcZ9fdmlA2v7p0c7UxQz79RkX7ibEEKb7LPwLQ/640?wx_fmt=png&from=appmsg "")  
  
裁判一般对这类文件泄露敏感信息的，只要挖到了就收。不过这里可能要注意一下，如果文件在官网上可以直接下载，如下图这种属于公开信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSPW5ycz43IuIiaE9JDypyHntR5xrmdb1I1Wu7qXWvK6picBBUPWL1Q1Eoia5u5ibwib4eeK7fKOrSibXLg/640?wx_fmt=png&from=appmsg "")  
  
即使文件里面包含身份证这种敏感信息，也可能不予收取（看裁判心情了）虽然很想吐槽，身份证这种就不属于是公开信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSPW5ycz43IuIiaE9JDypyHn2RFUg91Fiaiae0lgb8gibYiaubOUnStknfqBIh9ajCXBVjWiao7gvCeJzkg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSPW5ycz43IuIiaE9JDypyHnzbVqmuwrciaHQLqYeHVoriaeKyGlyw1EQ2rv5GKjAzOu6hM8YWENdy0g/640?wx_fmt=png&from=appmsg "")  
  
反正是各种类型的后缀名文件都尝试一遍，你也说不准他把身份证信息藏哪个文件里面了，或者忘记删除脱敏发网上了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSPW5ycz43IuIiaE9JDypyHnAIrFyUibptFCH1WMkceczP7YLzJdrfWno8oibnJRHkeC9UAw2p3W9Shw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJSPW5ycz43IuIiaE9JDypyHnI66NPMooJu2KCSHuhKJdudn0RCDNJHM44t1mVvSM1FE8R6PK4nEqTg/640?wx_fmt=png&from=appmsg "")  
  
这下可以安心的捡漏洞了  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06OSr2SvShCVknWcWJfDJxxgibItBZibdic7k25AL6uvnAUB5hVwfMf88lw/640?wx_fmt=jpeg&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
Google语法搜索的时候，也可以换着关键字去搜索，可能有类似的关键字：证件号、学号、银行卡号，发挥自己的想象扩大搜索范围  
  
最后总结  
  
感兴趣的可以公众号私聊我  
进团队交流群，  
咨询问题，hvv简历投递，nisp和cisp考证都可以联系我  
  
**内部src培训视频，内部知识圈，可私聊领取优惠券，加入链接：https://wiki.freebuf.com/societyDetail?society_id=184**  
  
**加入团队、加入公开群等都可联系微信：yukikhq，添加即可。**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/EXTCGqBpVJQSCTuiawtOw7G9JFaBeBc06sHdBhSTMMClOr5wLWmLYIl6Yry9n3ZIL97tylQib5YLOuJFxndeFMEg/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
END  
  
  
