> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI1NTE2NzQ3NQ==&mid=2247487271&idx=1&sn=ca68dccf9a1028de25f8717fd5c4b585

#  【工具推荐】听说这个工具挖0day有一手  
 网络安全007   2025-07-08 09:22  
  
文末附下载地址......  
  
一、【工具介绍&使用】  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJewvic0AvJtywjACDMPEOVFb6MDP3kzZamvy3MvPqekfCVEeTuQ9cdkQ/640?wx_fmt=png&from=appmsg "")  
  
   这段时间心情糟糕，用URLfinder和JSfinder的时候感觉速度好慢，有些路径还摸不到，美化也有点不适应，用二开的又感觉差点意思，用熊猫头插件是不错，但是总感觉需要手动的去拼接访问，并且碰上数据过长的显示还会错误，就感觉用什么都不是滋味吧！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJDDdCia5BffDibQMibWwsE7sN27MVmAvrKWsicichIBUD1VVstYns8licDiazQ/640?wx_fmt=gif&from=appmsg "")  
  
  
"""  
  
    我在想，有没有一种工具，可以进行JS文件的扫描判断，提取出敏感路径和参数，并且还自带大模型进行风险评估，或者是对页面进行爬虫收集路径，并给出响应和长度，还能建议的判断漏洞呢？于是就心血来潮，写了这么一个工具，中文名叫：“转子女神”。希望能让这个工具名扬四海吧！  
  
这里展示下目前所有的功能和支持的语法，需要增加什么新功能，请各位师傅向我提出建议，万分感谢！！！  
在此致敬JSfinder，URLfinder，fscan，FindSomething等等信息收集工具和浏览器插件！感谢各位师傅！  
  
                                                                                                """  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJxSxjoGDTJ0s6PvqOliaQdBohl7gj0mIgFRsLr1BoTYOb2yxlXt0Wt9A/640?wx_fmt=gif&from=appmsg "")  
  
首先来展示下基本的功能：  
  
①：路径勘探  
  
②：JS扫描  
  
③：JS路径与参数的提取  
  
④：JS自动化分析  
  
首先是基础的扫描  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJlR22icJibic5jViaOmYSIZBPOJyj0QuibODboRvF7aeBaGjJva2T4xoIKaw/640?wx_fmt=png&from=appmsg "")  
  
因为是类似于HAE的正则匹配，所以先抛开JS文件的误报不谈可以发现有些地方判断出了可能存在SQL注入的URL，并且还能判断接口或是敏感页面  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJd2xDyiaGianCI2q0x5EicMkwOsgDiamPfZPibFCjF0drp8zIx0LIwKia8MfA/640?wx_fmt=png&from=appmsg "")  
  
这里换了个EDU的URL，发现数据会比其他小站点多得多，这里拿到了很多的接口，并且自动进行请求，也不会存在被WAF拦截或者被封IP的情况，这里可以发现长度和响应都是一样的，所以证明路径是不对的，需要拼接别的路径才能正常的请求，但是接口我们是拿到了的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJmLneqfP74D616DcfpSBibsMETPAY8aam1gXEXvTLpXObPxHTyN4empw/640?wx_fmt=png&from=appmsg "")  
  
这里可以发现自动的把JS中匹配到的路径，进行了拼接请求，拿到的接口比上面的还要多多，  
因为工具中有个功能，就是可以自动的匹配需要拼接路径的变量的值，就好比一个数据是"/" + x + "/user/admin"这种格式，爬虫会自动的匹配x的值，并重新拼接，假设x的值是12345，拼接后也就是"/12345/user/admin"，所以拿到的数据会更多，接口也是。  
  
ps：工具还会自动抓取ico的hash值，并给出黑暗引擎的语法，很爽  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJZHpAlt74ZzDic4WllOxdpTQ4kGTEH4iaEIescRO5eueHvRiafibPmgy76w/640?wx_fmt=png&from=appmsg "")  
  
下面来到了JS自动化分析并提取出AI拿到的API，会发现AI拿的接口比手工的要多多了，经过AI自动化分析的JS代码，还有功能的提示，那很好了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJHyicMvza4gYt2z42dk7aykffiaSAPYjWicl2gcia2WX5pLR1JDPdlgDYibQ/640?wx_fmt=png&from=appmsg "")  
  
会发现这里爆了ID值，经过后面的接口分析，可以拿这个ID值进行请求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJ2as3W9tU19PP7B5wG31RyBfVFrgba5EOCmufI4fldYquibBE0pRfkIw/640?wx_fmt=png&from=appmsg "")  
  
另一个AI分析出的接口爆了个未能正常登录，说明鉴权  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJpdkibCqpKicGzAIicxRpoAlAYPvnJfQGboBMrWN0ibyJ1wGcg7YUfqLk8w/640?wx_fmt=png&from=appmsg "")  
  
这里请求方式错误，说明可能需要post，put，delete等请求方式  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJmOf6UxzPXelSkRpGqANUSfGiczdXsFVXWWXPPTDgaTRO1OlhQQ8gQiaQ/640?wx_fmt=png&from=appmsg "")  
  
这里爆了个ID为空，可以直接拿JS分析中的参数去进行一个fuzz，或许能在这里打一波注入？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJibuo5dJWEMIwhn2aXm3TGdgMiaeiczWHFicyRcWZzEicaqicOmdD5Bt4rMxA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJ0ibpicZ8YibvVWjyDWcT9Zdo1Rh53VMr9vupBIW2Xh8DXK16ds78qicH5Q/640?wx_fmt=gif&from=appmsg "")  
  
  
由于缺少一些参数，我们来到文件夹中，看看参数的读取怎么样了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJOAQRqmDibF8Q60IvGm2bDoFHQK3Ak8stc1pb1PDJMoWCF3eviaRGvdLQ/640?wx_fmt=png&from=appmsg "")  
  
好多参数，后续可以拿工具fuzz一下，很快的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJ31UdYZaohvSZ8qtlr7bLFkw0KNTtT8tNTbEBxRyVBebiclzrzaFLt1w/640?wx_fmt=gif&from=appmsg "")  
  
  
如果还没发现漏洞的话，可以拿URL文件中的所有url进行跑一下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJlP9oJXoBUJr87oqVA8S0DWGwfkH9ze2kSVLXBTLXoDYNicp24k564jw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJ8EoibISQDcCVz3Ye6AjwhMxfkaHw7P7EAKnmWbMu4ta4seKfXblAtQw/640?wx_fmt=png&from=appmsg "")  
  
如果运气好的话，甚至可以直接爆出未授权或者信息泄露漏洞，那更爽了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJZFOBWbwJRG9zvNAGdv2JRWSosTLBO9x795znPuamS5I0ntleicribNxA/640?wx_fmt=png&from=appmsg "")  
  
接着是hae匹配到的url  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJahXediaC335d9VQnicBhMQG2KzlWtTgPyFJn2k4qgibicLjLWQqQNZI8Fw/640?wx_fmt=png&from=appmsg "")  
  
例如敏感信息泄露这里，会直接告诉你匹配这个的参数，直接来到目标url搜索触发的参数就好了，一目了然  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJShmNOkAXNl5YTibL9bKaB2hV7Bz53xEYZ71mw5njYeNT7ET9jFYJJqg/640?wx_fmt=png&from=appmsg "")  
  
接着来到JS分析情报这里，会发现AI对这个做了一个风险评估  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJ8vicxOEX1Plz8nYtqbFJ9K3u3e5Qicrz3TT1N0PUZ5WrkykzUrvtyicvw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJYLDwaBLGGLeXtCXFJwIiaXia1QqD711cjR0hCpibVRic2nMPcIsjJiayR5g/640?wx_fmt=png&from=appmsg "")  
  
并且路径的匹配和参数还会自动放在提取的目标JS文件中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJjB6uiaGIPoGA0MhteGnMbSN9V3G5tdgMxn3JPNICx5VHMYxFq7tmNiag/640?wx_fmt=png&from=appmsg "")  
  
包括这个输出日志，也会记录所有的URL，方便使用者随时进行查看  
  
以上就是工具的大概使用了，总共也就用了几分钟，可以在做测试的时候，挂着扫描，一下子就出结果了，效率也是杠杠的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJqRgH6LjlkOhwm2BSm7IuUWC1E0P1DCzfu8GGViberfBvbzl3mwbeoJQ/640?wx_fmt=gif&from=appmsg "")  
  
  
接下来是使用的方式，分为几个点  
  
①：--cer过证书  
  
②：--url自定义拼接  
  
③：--time=x设置超时  
  
④：url_batch文件的批量扫描  
  
⑤：请求头设置  
  
⑥：AI问话设置  
  
首先是--cer过证书  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJYVO98gT2KlJS1XYG1B3It2UZsCsqPues0v1kb52NQib2M0b1d6hE3ow/640?wx_fmt=png&from=appmsg "")  
  
直接在url后面加上--cer即可  
  
再来是--url自定义拼接  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJZEk4iaxpQwwdcavbsoYZyHyHHc07icbia3XPibFRo6WmBe4qnrgEviaLYhQ/640?wx_fmt=png&from=appmsg "")  
  
例如一个需要/#/拼接的站点，直接扫描拼接的返回数据肯定不是正确的，这个时候就需要--url功能了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJ7IICnEibY9xfxe6icfyAqlxITPNZdSIwzPMb77jWSicm832PlibCpicTvcA/640?wx_fmt=png&from=appmsg "")  
  
这样就会按照你定义的url去拼接路径了，可以看到都请求成功了  
  
接下来是--time的使用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJ2icSFUiaPNmnibrT856dYnlrROnoqYRSB7knsDqouOjHPFvpDnUkvRlWA/640?wx_fmt=png&from=appmsg "")  
  
还是一样，在后面加上--time=时间，就好了  
  
再来就是URL的批量扫描  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJBvZTej7ibL3WaJXxricAibHoeqLgQKf6KJJcKhJhf5ZekCT0Wg1TWmszA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJibcSsu7lYfG19hzNJ9oiasAZUqTJron8oicLwCSe2g5vwibYskkcb7jCEQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJKBkFwDva7oL220Qp9FP8iaib6IW4F5UVpLmLZNr5vT3BHg6oXQWsgwFQ/640?wx_fmt=png&from=appmsg "")  
  
在txt以这种方式，接着点击exe，就会自动的去进行扫描了，无需手动  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJwiamnFu72rCAZEaODKKBgXd4krKfuqs6Ihoov5HDesIyGabgYXdUfRg/640?wx_fmt=png&from=appmsg "")  
  
AI的问话也可以在这更改，删除了会自动创建新的默认的问话机制，所以各位师傅可以多尝试对AI进行问话，以达到最好的AI自动化分析效果，不过可能会破坏路径提取的函数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MwxaTtRUcew8pfesMNzhWGvPTAd8jwLJicUf55p9c6XmEpUZaz2ibhePqib4c2FUvcROduEEQlAefyjqYqsibhYdUQ/640?wx_fmt=png&from=appmsg "")  
  
接着就是haeders的设置，这没什么好说的，格式不变下更改数据即可。  
  
二、【工具获取】  
  
喜欢的师傅可关注雪山盟公众号  
  
在本公众号后台回复【  
转子女神  
】即可获取项目地址&下载链接！  
  
<table><tbody><tr><td data-colwidth="576"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;font-size: 17px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;white-space: normal;text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;color: rgb(34, 34, 34);background-color: rgb(255, 255, 255);" data-pm-slice="0 0 []"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 宋体;color: red;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">免责声明：</span></span></strong></p><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;color: rgba(0, 0, 0, 0.9);font-size: 17px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 0.544px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;white-space: normal;text-decoration-thickness: initial;text-decoration-style: initial;text-decoration-color: initial;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;background-color: rgb(255, 255, 255);"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-family: 宋体;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"> </span></span><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 14px;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">本文章仅做网络安全技术研究使用！另利用网络安全007公众号所提供的所有信息进行违法犯罪或造成任何后果及损失，均由</span><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 0, 0);"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">使用者自身承担负责</span></span></strong><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">，与网络安全007公众号</span><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 0, 0);"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">无任何关系</span></span></strong><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">，也不为其负任何责任，</span><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 0, 0);"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">请各位自重！</span></span></strong><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">公众号发表的一切文章如有侵权烦请私信联系告知，我们会立即删除并对您表达最诚挚的歉意！感谢您的理解！</span><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 0, 0);"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;">让我们一起为我国网络安全事业尽一份自己的绵薄之力！</span></span></strong></span></p></td></tr></tbody></table>  
**●****推荐阅读●**  
  
****  
**应急响应系列**  
  
**未授权访问漏洞系列**  
  
**Nessus漏扫神器之攻防两用**  
  
**红队如何在攻防演练中一夜暴富？**  
# 浅谈Nacos漏洞之超管权限后续利用  
  
****  
**超级弱口令工具+超级字典，攻防必备！**  
  
**记某APP服务端渗透测试实战GetShell**  
  
**日常实战渗透小技巧，掌握就无需担心漏洞产出为零！**  
  
**实战|某网站未授权访问=》数据库权限=》服务器权限**  
  
**全方位揭秘：50多种横向渗透提权终极技巧，一篇文章彻底掌握！**  
  
写作不易，分享快乐  
  
期待你的 **分享**  
●**点赞●在看●关注●收藏**  
  
