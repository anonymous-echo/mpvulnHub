#  Src挖掘-实战中遇到的一些莫名其妙的漏洞   
 黑白之道   2024-03-02 09:05  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
原文链接：  
  
https://xz.aliyun.com/t/13790  
  
# 前言  
  
真实案例，文中所写漏洞现已经被修复，厚码分享也是安全起见，请各位大佬见谅哈！  
# 案例一：奇怪的找回密码方式  
  
某次漏洞挖掘的过程中，遇到某单位的登录框，按以往的流程测试了一下发现并没有挖掘出漏洞，在我悻悻地点开找回密码的功能并填入了基础信息之后，我发现他的业务流程与常见的安全的找回密码的方式并没有什么区别，都是需要接收到手机验证码或者邮箱验证码或者回答正确安全问题才能进行下一步重置密码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrzQpFxaia2KE2TBxOD63ibTxnhqIgfTqqRiazPVVO8Vr9SMh3h2Jr1DZucRt6hiays9e6PLe34u3riagQ/640?wx_fmt=png&from=appmsg&wxfrom=13&tp=wxpic "")  
  
但是敏锐的我，发现了右上角存在一个验证方式不可用？的功能，我点开发现竟然直接跳到重置认证方式里面去了：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrzQpFxaia2KE2TBxOD63ibTxjSQRhUWCxt0GEJq3vjTXTLKtNt0BDDANI72iaCnpjxHFBia96dO0wZwg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
然后我把原号主的安全问题重置之后，更令我意外的是直接跳转到重置密码的步骤了（令人哭笑不得2333）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrzQpFxaia2KE2TBxOD63ibTxTyVN43CicAEroR6AEkUVic4Qnm3jtZnL9dicvXHHMrV9fhZz858BU4tfw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
就这样我就修改了原号主的密码成功进入了系统进行后续安全测试：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrzQpFxaia2KE2TBxOD63ibTxTGic5ic80ej1W7bNDPhKUgdXOfGMFMpXWlKrqxWxoaJXDticJdk5GBm7A/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
# 案例二：且丘世专  
  
在某次SRC挖掘过程中，我发现了一个站点可以进行任意用户注册，在往下继续挖掘的过程中，发现了一个比较有趣的越权。  
  
当我成功登录的时候，我抓到了一个数据包大致如下(已脱敏)：  
```
```  
  
我敏锐的直觉告诉我这里很有可能存在越权的漏洞，但是这个id看起来实在确实很抽象，经验丰富的师傅可能一眼就看出来是URL编码，我们拿去解码一番：  
  
发现解码出来我们的id居然是：且丘世专  
  
有趣，经过我的一番FUZZ  
后我发现有下面的对应规则：  
<table><thead style="outline: 0px;"><tr style="outline: 0px;border-top: 1px solid rgb(204, 204, 204);"><th style="padding: 6px 13px;outline: 0px;word-break: break-all;border-top-width: 1px;border-top-color: rgb(221, 221, 221);">序号</th><th style="padding: 6px 13px;outline: 0px;word-break: break-all;border-top-width: 1px;border-top-color: rgb(221, 221, 221);">汉字</th><th style="padding: 6px 13px;outline: 0px;word-break: break-all;border-top-width: 1px;border-top-color: rgb(221, 221, 221);">URL 编码</th></tr></thead><tbody style="outline: 0px;"><tr style="outline: 0px;border-top: 1px solid rgb(204, 204, 204);"><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">0</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">丐</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">%E4%B8%90</td></tr><tr style="outline: 0px;background-color: rgb(248, 248, 248);border-top: 1px solid rgb(204, 204, 204);"><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">1</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">丑</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">%E4%B8%91</td></tr><tr style="outline: 0px;border-top: 1px solid rgb(204, 204, 204);"><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">2</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">丒</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">%E4%B8%92</td></tr><tr style="outline: 0px;background-color: rgb(248, 248, 248);border-top: 1px solid rgb(204, 204, 204);"><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">3</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">专</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">%E4%B8%93</td></tr><tr style="outline: 0px;border-top: 1px solid rgb(204, 204, 204);"><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">4</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">且</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">%E4%B8%94</td></tr><tr style="outline: 0px;background-color: rgb(248, 248, 248);border-top: 1px solid rgb(204, 204, 204);"><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">5</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">丕</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">%E4%B8%95</td></tr><tr style="outline: 0px;border-top: 1px solid rgb(204, 204, 204);"><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">6</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">世</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">%E4%B8%96</td></tr><tr style="outline: 0px;background-color: rgb(248, 248, 248);border-top: 1px solid rgb(204, 204, 204);"><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">7</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">丗</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">%E4%B8%97</td></tr><tr style="outline: 0px;border-top: 1px solid rgb(204, 204, 204);"><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">8</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">丘</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">%E4%B8%98</td></tr><tr style="outline: 0px;background-color: rgb(248, 248, 248);border-top: 1px solid rgb(204, 204, 204);"><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">9</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">丙</td><td style="padding: 6px 13px;outline: 0px;word-break: break-all;">%E4%B8%99</td></tr></tbody></table>  
所以且丘世专对应着我的id也就是4863。  
  
然后我将对应的id值进行遍历一下就越权查看了大量用户的信息：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrzQpFxaia2KE2TBxOD63ibTxfqWhfEQz6qSXoX3WJhLqj0qmF44RBB98oiaPnwLKC3HPksHia7yukKYg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
# 案例三：1 + 1 + 1 ？  
  
在另外一次SRC挖掘中，同样是找回密码功能处，我选择直接重置admin账户的密码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrzQpFxaia2KE2TBxOD63ibTxMSHRDb8ES42AnAf5Fb1mejQTTHpia00e35JRpBTccLeyFeUm4fYneVw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
该找回密码的逻辑是输入正确的密保问题，于是我随便输入了三个2来测试：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrzQpFxaia2KE2TBxOD63ibTxr2NNibAXTphpBVQxVpkWfQ06Xnyo0wffrqylGtW36h5yfFQbIPZKM5Q/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
确实很安全，那么3个1呢？  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrzQpFxaia2KE2TBxOD63ibTxRH352hANmWBzwGUdAVdHphjIVGKPMRoia4wVg4yLqjNGmZASzu3nTvg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
居然直接进入了重置密码的界面。。。。。。  
  
由于是admin账户，我没有贸然去修改密码，后续厂商也是承认了该漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTrzQpFxaia2KE2TBxOD63ibTxetMHRUHm4ias1dmSGRYKFLANVLxkQjLIzILpSFBoDAR96JG3X3ZAObw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
# 总结  
  
有些时候有些漏洞确实非常莫名其妙，本文其实并没有太深的技术支持，但是也算是一种思路的补充吧！  
  
  
> **文章来源：亿人安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
