#  Eyoucms的sql注入复现(2019Bversion)   
 船山信安   2024-01-14 00:00  
  
本cms的漏洞已经提交过cnvd已修复了。更新到最新版本即可**0x01** 漏洞复现这里我是本地搭建的eyoucms环境演示默认安装完成后，我先是访问如下urlhttp://127.0.0.1:8081/eyoucms/?m=home&c=View&a=index&aid=89  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNP8J4j7s5dA8Qib8QOtQQng1k4Ygd0XHZZI1VGML8PP7pUOmBVjPvuEhNtaCXNJHDM9mZjVrP7V6g/640?wx_fmt=png&from=appmsg "")  
  
S然后开启burp抓包，构建如下的包需要改两方面的参数一是referer，改成我们访问的页面然后将get的url构造为如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNP8J4j7s5dA8Qib8QOtQQngZnb9RIrp6uIqibgmpVvBByv8hNicBWt5xOMiab0n4jwu66hQjjLiboDoqA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNP8J4j7s5dA8Qib8QOtQQng6y6Gec89ib9onuFWtJ2Gdj7pobbibxVyx83HrTBUswX7yIZfd819yXFg/640?wx_fmt=png&from=appmsg "")  
  
然后放进sqlmap一把梭就行啦  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNP8J4j7s5dA8Qib8QOtQQngpq201DPUP2LZsBlRZ8Zf7vOE6icjOj4znb5FF9X5hXavpiciaiaS0DwILw/640?wx_fmt=png&from=appmsg "")  
  
0x02 代码分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNP8J4j7s5dA8Qib8QOtQQngDBKGLTTRudDojPCQsXKp7OczH3sNyQhKZNLR7RDNbIC2dWiblm0pp9w/640?wx_fmt=png&from=appmsg "")  
  
'url_screen_var'这个值=>'ZXLjbXM'，这里它cms也注释说明了这个参数代表了文章状态，在前台使用的。ZXljbXM这里使用这个参数是需要注册一个用户权限，正好是可以在前台使用所以上图的refer就代表我们是从用户权限的那里过来的根据它 ZXLjbXM 所需求的构造如下url。GET /eyoucms/?ZXljbXM=1&a=index&c=Lists&m=home&tid=3&yanse=1看最后的参数yanse 是它这个的cms的产品评论里的参数。本来是系统自带的但是这个参数也是属于用户发表的文章里面的构造，所以结合ZXLjbXM 即可构造可以存在注入的url链接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicNP8J4j7s5dA8Qib8QOtQQng7ghKwYmbfjQ9sgfpqJWqqdnCAIuMP6DwjZx7M8Gur5RegGYhWShhCQ/640?wx_fmt=png&from=appmsg "")  
  
它这里请求的参数没有做防护其实它这个文件的三个参数都是可以注入但是构造的请求url不相同。通过更改最后的参数即可如果安装者是经过调整此点，或者仅用来展示网站的，那利用点可能微乎其微了这个注入点比较鸡肋。其实没有多少高深的东西，只是笔者运气好，恰好看见这个参数。要不真的发现不了。因为这个文件属于它cms自带的一处产品编辑的文件，实在不容易被注意到。  
  
  
来源：【https://xz.aliyun.com/】，感谢【  
任意门  
 】  
  
