#  Eyoucms的sql注入复现   
 船山信安   2024-12-16 16:02  
  
本cms的漏洞已经提交过cnvd已修复了。更新到最新版本即可  
**0x01**  
 漏洞复现  
  
这里我是本地搭建的eyoucms环境演示  
  
默认安装完成后，我先是访问如下url  
  
http://127.0.0.1:8081/eyoucms/?m=home&c=View&a=index&aid=89  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMCic7To5Mt1BBaCZsKxI7MgGb5ylYMpQBrA5Rb8CT0JkYdjqsHxo4NdMzuRne6r9xgOAicb5owdwhg/640?wx_fmt=png&from=appmsg "")  
  
然后开启burp抓包，构建如下的包  
  
需要改两方面的参数一是referer，改成我们访问的页面  
  
然后将get的url构造为如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMCic7To5Mt1BBaCZsKxI7Mg1xA9ibgiaOfuTkaXrIoO8K5UHgtVoeI7GH7VVLlbYpv1QBlZCB8D39BA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMCic7To5Mt1BBaCZsKxI7MgbStlYQUykia9eCOuJsFWBoCqZFQGsL0fMnwh0rUBJqNIcy66coMfRwQ/640?wx_fmt=png&from=appmsg "")  
  
  
然后放进sqlmap一把梭就行啦  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMCic7To5Mt1BBaCZsKxI7MgFGOyz6XBM56XEYsicFDYicr1DUPOSP79zciaPia40p6ks4LvpAYlgkjtyQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x02 代码分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMCic7To5Mt1BBaCZsKxI7Mg0LNjVZYlYGFUFB05Nne6FUmKGFe4jYkaLwYLic5nPj25Vmia0M8fxNCQ/640?wx_fmt=png&from=appmsg "")  
  
'url_screen_var'这个值=>'ZXLjbXM'，这里它cms也注释说明了这个参数代表了文章状态，在前台使用的。ZXljbXM  
  
这里使用这个参数是需要注册一个用户权限，正好是可以在前台使用  
  
所以上图的refer就代表我们是从用户权限的那里过来的  
  
根据它 ZXLjbXM 所需求的构造如下url。  
  
GET /eyoucms/?ZXljbXM=1&a=index&c=Lists&m=home&tid=3&yanse=1  
  
看最后的参数yanse 是它这个的cms的产品评论里的参数。本来是系统自带的  
  
但是这个参数也是属于用户发表的文章里面的构造，所以结合ZXLjbXM 即可构造可以存在注入的url链接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7nIrJAgaibicMCic7To5Mt1BBaCZsKxI7MgRBhnwvR9afiaeq8ibxcZKneeHo5AN3rPibu88C8AnHQsjpD4bjE9B61vw/640?wx_fmt=png&from=appmsg "")  
  
  
它这里请求的参数没有做防护  
  
其实它这个文件的三个参数都是可以注入但是构造的请求url不相同。通过更改最后的参数即可  
  
如果安装者是经过调整此点，或者仅用来展示网站的，那利用点可能微乎其微了  
  
这个注入点比较鸡肋。其实没有多少高深的东西，只是笔者运气好，恰好看见这个参数。要不真的发现不了。  
  
因为这个文件属于它cms自带的一处产品编辑的文件，实在不容易被注意到。  
  
来源：https://xz.aliyun.com/   感谢【  
任意门  
   
】  
  
  
