> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI4MjkxNzY1NQ==&mid=2247486533&idx=1&sn=12d91dccb932998fec348e17760ef684

#  工作中遇到的几个常见场景下的xss漏洞  
xuzhiyang  玄武盾网络技术实验室   2025-07-14 01:56  
  
免责声明：本文仅供安全研究与学习之用，严禁用于非法用途，违者后果自负。  
## 玄武盾技术实验室资源共享库上线，你想要的资料都在这里（全免费）：  
## 网站链接:  http://xwdjs.ysepan.com  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2luHp14f7icGCe4iaRE5vNksx06Hz7oghA1WNoY2MJWKZ71NjAw12RUibyA/640?wx_fmt=png&from=appmsg "")  
  
  
正文  
  
参考阅读：[XSS注入常用语句](https://mp.weixin.qq.com/s?__biz=MzI4MjkxNzY1NQ==&mid=2247484812&idx=1&sn=495549a6cc9c81bb9005e28f363d19bf&scene=21#wechat_redirect)  
  
  
  
**公告编辑器处**  
  
  
在发布作业的平台板块，这类配备编辑器的功能区域，往往存在较大概率遭遇 XSS（跨站脚本）漏洞风险。  
  
  
这是因为编辑器通常支持一定的文本格式化、插入链接或多媒体等功能，若开发者对用户输入的内容过滤不严格，攻击者就可能通过构造恶意脚本（如
```
<script>
```

  
标签代码），借助编辑器提交到平台。当其他用户浏览包含该恶意内容的作业页面时，脚本会被浏览器执行，进而导致 Cookie 窃取、会话劫持甚至网页篡改等安全问题。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2l2MKUTdnlrJZN77TKdVlibFsr8hPluRxzKlFaw5jIX2PlUoZduHrLRvA/640?wx_fmt=jpeg "")  
  
点提交，然后开启拦截数据包，添加payload：  
  
<details+open+ontoggle=confirm(document.cookie)>  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2lics3fkeUWkTwwUvic6KrxOVEj4ibsCzNFmrcP937p4c5HSvaOPjv5PPCg/640?wx_fmt=jpeg "")  
  
把拦截到的包放出，访问作业处弹出cookie  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2lSQ1pKDmcrne7FrnCY7wU8BwMlcQ5XsL5DZU3icZrC3ZSaAWrcCGA5uA/640?wx_fmt=jpeg "")  
  
**上传文件名处的xss**  
  
前端功能点如下  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2lA0wdBicIU4VCvWWnm6ianASE2mGWs2HdCl2OTuqdVVzuCm380b0ibgyJg/640?wx_fmt=jpeg "")  
  
点击“  
我要办理  
”  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2liam77UibCFwlzxpStcyAk9BLzfKVHTVAc13AAv6MDnKVG2gGnXA08aibg/640?wx_fmt=jpeg "")  
  
点击上传文件  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2la6GLFiccgVIfAYdlX6fB607r0FjN2FFVeibyH3NyEA12Cy8bIlxc8atQ/640?wx_fmt=jpeg "")  
  
文件名可以直接修改如下  
  
<details open ontoggle=confirm(document.cookie)>.png  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2lDrdDjibBlRAU4rKqEVL7blE4paSIFDLiaLicfAJTxb7a2d30aeIoCMzYw/640?wx_fmt=jpeg "")  
  
成功执行js代码  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2lpmPa0TX4icAibzT07iaaYtaLLiaicoiawhapJNh8F0PnCibUeyRf8jK9yZIBQ/640?wx_fmt=jpeg "")  
  
在点击 “保存草稿” 按钮时，部分网站会在这一环节对内容进行过滤处理。为了确认内容是否真正符合平台规范，或是检测过滤机制的严格程度，建议在保存后前往草稿箱查看实际保存的内容状态。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2lK0zRMFZFINTeE6ACfcuSTFCkaob0dqGIwibTWgvOBKEGc6sCz1L8upw/640?wx_fmt=jpeg "")  
  
确认没有过滤，可以触发  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2lcz5YeN5ia0LT2FQPxfib6cQ5fUbUPfr4aEWrGHzRWBELPC5vfxibYiaIgQ/640?wx_fmt=jpeg "")  
  
**针对于管理员的xss**  
  
前端功能点如下，点击发起申请  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2ll9yVtFctrkSsjsEtD9KWRopH56wcVOo3vxyIeZ4HHFhbuPLfzHWlIg/640?wx_fmt=jpeg "")  
  
这里s标签就是给中间文本划横线  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2l8vDHumR8kxvqyLJr2Lh1yEbicAWtoxZEs7B0a30Ih8aTc7ibYhGWBNEQ/640?wx_fmt=jpeg "")  
  
请求包如下  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2libjS00IuHuU4OSrOpN8mCX6aj3XA5x2KO8J4oO7QoVUoNNSHrDjNCbw/640?wx_fmt=jpeg "")  
  
这里手动再添加下s标签  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2lmL7pN5ib6alPSAWTnln1cJVJOuh9EZAYjtUo4MLpduLBoyt9jlmqPicQ/640?wx_fmt=jpeg "")  
  
从实际测试结果来看，s 标签已被成功解析。需要明确的是，即便标签未被解析，也不能完全排除存在 XSS 漏洞的可能，因为攻击者可能通过其他绕过方式触发漏洞；但反过来，只要标签被成功解析，就意味着用户输入的内容未被严格过滤，这种情况下存在 XSS 漏洞的概率会大幅提升。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2lDILB44WlKb49vxYK4B9f4z8XzK3XGVsjHhSv9Azju6WEqZ89nVutJA/640?wx_fmt=jpeg "")  
  
再重新编辑替换为最常见的paylaod  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/CgXd9Hbb64mwzqwxzhavYwGt2x9gdibMMQL8ZHAT1ibP7zJuvO29GWOEib54YEkEpDSE8CSvytBfvsAq6zYW18EIA/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
没有什么过滤，成功执行js代码弹窗  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2lUKIicLOwDXgAaeNuBfcDtLiabKHhVPjjvoCpyYHQXITkJA4GJcVjSxag/640?wx_fmt=jpeg "")  
  
**存储桶修改response导致xss**  
  
首先新建一个txt文件  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2l2o6qFbIzOQNIsfCue6Nv2OMNO3nLIOy0HfMaJMaShYgibYXE1Bp8Vibg/640?wx_fmt=jpeg "")  
  
上传文件功能点  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2lAqbbWDiaTExTcNeQIQWNESWOqogrW1aolvOZzWZyBRe6hicArsfOItCA/640?wx_fmt=jpeg "")  
  
可以看到绝对路径  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2lUsm40wHvd0sibLLSQKACdmC98qryKAiaNJk4icjlagIGic7ttEZuct3SfQ/640?wx_fmt=jpeg "")  
  
存储桶域名修改为绑定的CDN域名，后面添加?response-content-type=text/html  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2l27wHqrcsFV8tjNbWgcC9zKB9pWSwg9eLzISbK7fxIjEoPLk7hVTuBQ/640?wx_fmt=jpeg "")  
  
这种就属于低危反射型xss  
  
**并发绕过限制的存储型xss**  
  
地址簿管理  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2lhgeEXK1CCchktc4HDAzgibq9ibhcibnRtRoq1f7FJoRQ8CUxcibAbMcf5A/640?wx_fmt=jpeg "")  
  
直接添加下面payload会被过滤  
  
<input2 onmouseout=\"alert(1)\">test</input2>  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2ldE7PicMkIibC5ibr0lsonkldhvibK5mMbbcmbd7NsABP8wqw7vYgUWtD9Q/640?wx_fmt=jpeg "")  
  
遍历下面数字达到简单的并发效果  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2lcVTSHjD6SUzCEo0CyMxhp3nmI4NnEdpdutUh9Xshm4KibZQ3iaaQ0eOQ/640?wx_fmt=jpeg "")  
  
成功绕过拦截  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2ld5DpQNzzMb7ibTzTDsWdUVia5EaK4uZib8faUpjK60m52gxFeZQbd8Dww/640?wx_fmt=jpeg "")  
  
这里来说只是self-xss，但是通过下订单选择此地址，再通过并发绕过限制即可盗取目标cookie  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2l6RmVn2u7ibuwzRR1lrDcicrgccPicrddjXQDibabeST0Yf15lcBcEzibqgA/640?wx_fmt=jpeg "")  
  
**某企业论坛的存储xss**  
  
漏洞点在评论区  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2lRZ4F6icRHeozJia2GlLibVYx0hichl3ebHqOmicPjSqupA9kKYpG39UCJ4w/640?wx_fmt=jpeg "")  
  
先测试最常见的a标签  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2luazKNLicXCDYiboZYdxmoUvnJAUibQOBcMXAk1P9KeEeDqFNVbY2lrsSw/640?wx_fmt=jpeg "")  
  
发现成功解析  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2lpgaxeict6ZqqDTqWqf1ofJPlbPnaTcB6opwML4iabRZH16jmia9CNF4lQ/640?wx_fmt=jpeg "")  
  
随便打个payload：  
  
<a href=javascript:[1].find(alert)>xss</a>  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2licibBIibMVOuwKibBlQ3dAI9bV0Cu0IqGAkVGAuYpT5TGrWIGrDgRE9hicQ/640?wx_fmt=jpeg "")  
  
发现有过滤，构造事件属性，测试不太会过滤的事件，复制才会触发：  
  
<a oncopy=alert(1)>t  
  
选中t直接复制即可弹窗  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2lWIicgYdwEpGye67U7oxQfibVB7ybhD07p2yf9wjJZCfLpVJgeGIcZVKg/640?wx_fmt=jpeg "")  
  
再测试一下简单交互就触发的事件，payload如下：  
  
<a onmousemove=alert(1)>t  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2ljnKzkGsnuYmWFAUuyzkx43y8q5RiaibYudznyBYBNicxibgsbDTFYRb4Rg/640?wx_fmt=jpeg "")  
  
晃动鼠标就可以弹窗  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2llN4RafWVdIJjUzsoEcm2dNKiaGaUO9STpYWQFRxic1Hia70vawuyOFGwQ/640?wx_fmt=jpeg "")  
  
再稍微变换一下展示操作  
  
<a onmousemove=top[/al/.source+/ert/.source]('xsss')>test  
  
**银行门户的反射型xss**  
  
点击关于我们功能  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2liaia8yiag6IuNPaDtCWQeF4fy167bBQnqh9ExhvickQuZ8n77ib8SlPIGvg/640?wx_fmt=jpeg "")  
  
url中拼接title参数，发现回显到了前端  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2licu7MkIL3ap1fcloXzuYJficFTQgISFyU5Hf7AUDNGCU3MZGPDQbMW5Q/640?wx_fmt=jpeg "")  
  
随便插个payload被waf拦截  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2l5Dia6LMAna96lBBcLd9EuNZJ7YvlLMkl1tDNThmlriadgYnrHUWPbbEQ/640?wx_fmt=jpeg "")  
  
手动测试a标签，可以解析  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2laGNcQ2ic7hC5t437wR78chrI1g4jf3g00cmJPibLIqBiag8yiakWiaQtI9g/640?wx_fmt=jpeg "")  
  
直接上payload：  
  
<a onmousemove=alert(xss)>test  
  
这里本来以为会拦截，结果没拦直接弹了，省的再绕了  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/UM0M1icqlo0lIfDbzbNaXbE7ibPCId7T2lg09APjX0mf6yTkPibtXIVPiczPE9rj5mC10nZee5AobksNYichMN8yNkg/640?wx_fmt=jpeg "")  
  
  
  
为爱发电，随手点个「推荐」吧！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0knIjq7rj7rsX0r4Rf2CDQylx0IjMfpPM93icE9AGx28bqwDRau5EkcWpK6WBAG5zGDS41wkfcvJiaA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
声明：  
技术文章均收集于互联网，仅作为本人学习、记录使用。  
侵权删  
！  
！  
  
