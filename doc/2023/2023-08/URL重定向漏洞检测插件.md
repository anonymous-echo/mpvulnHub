#  URL重定向漏洞检测插件   
Rookie  Yak Project   2023-08-17 17:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/f7AtEgJhMZc5BYI1O7qwYC876L6gkbkACCZMJOIAPQmNqT0uZojjJZcfPsNJk6EjcbicXiaaSZ6j4APvocaxlI1w/640?wx_fmt=gif "")  
  
本文作者Rookie，预计阅读时间7分钟![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZdw4GDYHawMiba25Ww2YDQ0gqNKLBhqEV3B5KibrxB9UUicnT08cB1WQuBG8c3LYxhXicibw7ThhQTJyDw/640?wx_fmt=png "")  
  
  
URL重定向漏洞  
  
  
**漏洞信息**  
  
URL重定向漏洞是由于目标网站未对程序跳转的URL地址及参数做合法性判断，导致应用程序直接跳转到参数中指定的的URL地址。  
  
攻击者可通过将跳转地址修改为指向恶意站点。  
  
比较容易出现的地方是登录、注册、访问订单信息、以及一些需要回到上个页面的地方。  
  
此漏洞通常用于发起网络钓鱼、诈骗甚至窃取用户凭证等。  
  
下面是一个比较典型的场景  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZeiba3udA0awrRAUbvTSp4Fh9XkoGBWRKmaPcAczuzAzzeUWJliaPRicCukS44ZsWM8pA48kHiaO0Ndjw/640?wx_fmt=png "")  
  
漏洞本身是无法直接危害系统和用户安全的，按照通用漏洞定级标准属于低危，但该漏洞可被利用于钓鱼，在工信部远程检测工作中，该漏洞定义为高危。  
### 漏洞检测  
  
url重定向漏洞的检测初看会很像SSRF漏洞的检测：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZeiba3udA0awrRAUbvTSp4FhKxicKMNFmIXYoY2wGsPAglxzhn8QRfEWCEdTWSke4BGRdBeh9TJqyaw/640?wx_fmt=png "")  
  
但是仔细思考一下会发现这样并不合理，因为url重定向漏洞的跳转是针对客户端的，而客户端的跳转并不只有302一种方式，还是一些方式是使用其他浏览器前端的方式来完成跳转。  
### 跳转方式  
  
常见的跳转方式一共有三类（本质上是两类：一种http头，一种JS操作）  
- HTTP 响应头：  
  
- Location  最常见的302跳转  
  
- Refresh 表示浏览器应该在多少时间之后刷新文档，以秒计。类似Refresh: 5;URL=https://yaklang.com/  
  
- meta 标签：  
  
meta标签实现跳转的本质就是为添加一个指定的头，这个标签可以可以添加Refresh  
头，类似<meta http-equiv="refresh" content="5;URL=https://yaklang.com/">  
  
- JS(location)  
  
JS操作页面主要是操作 window.location  
对象，比如 window.location.href ="https://yaklang.com/"   
  
上述的检测方式只能检测到HTTP响应头直接跳转的情况，如果跳转是通过前端来完成，缺少浏览器渲染解析的扫描插件就无法检测出来。  
  
  
自动检测插件  
  
****  
**整体流程**  
  
针对插件检测漏洞来说，就需要通过分析请求响应包来确定漏洞是否存在。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZeiba3udA0awrRAUbvTSp4FhbLMeXFSqEZDXeVichO7RpIdJCJr9sOQOEOeMDiciav74CD9ocibNTqQvWw/640?wx_fmt=png "")  
  
### 检测参数与确认输出位置  
  
url重定向漏洞的出现位置一般来说场景相对复杂，参数量不会太少，直接无脑对所有参数进行测试是不太合适的，应该筛选部分可疑的参数进行测试，期望的效果会更好。  
  
参数检测只有两个标准，一个是参数名是否敏感，一个是参数值是否为url或者path。  
  
在Yaklang里有着完善的测试基础设施，re库下的函数可以很简单的检测出第二标准  
```

len(re.ExtractURL(value) > 0 ||  len(re.ExtractPath(value))
            

```  
  
获取到需要检测的参数，首先需要去定位参数输出的位置，可以使用原值拼接随机字符串的方式来构造特征字符串，这样产生的字符串大概率合法。  
### 检查漏洞  
  
获取到拥有输出信息位置后的可疑参数后，开始对每一个参数进行测试。不同的位置采用不同的测试手法，但是本质上就是两个阶段：  
- 找到可能会被用于跳转的 **输出值**  
  
- 解析输出值(url)的host是否是预期的  
  
这里着重介绍一下JS的部分  
#### JS解析  
  
Yaklang依靠了成熟的轻量级在 Go 语言中嵌入 JavaScript 解释器的库——"otto"，对其封装后Yaklang可以解析一段JS代码成为AST。  
  
本插件对JS的解析就是通过AST遍历，找到会自动执行的location重定向语句。  
  
下面是对Expression节点解析的代码  
```
expressionCheck = func(stat,payload){
    node = stat
    inerType = js.GetSTType(stat)
    if inerType == "ExpressionStatement"{
        inerType = js.GetSTType(stat.Expression)
        node = stat.Expression
    }
    switch inerType {
        case "CallExpression":
            if js.GetSTType(node.Callee) == "DotExpression"{
                if DotExprCheck(node,payload){
                    return true
                }
            }else if js.GetSTType(node.Callee) == "Identifier"{
                if node.Callee.Name == "setTimeout"{
                    if js.GetSTType(node.ArgumentList[0]) == "FunctionLiteral"{
                        if jsAstCheck(node.ArgumentList[0].Body.List,payload){
                            return true
                        }
                    }
                    if expressionCheck(node.ArgumentList[0],payload){
                        return true
                    }
                }
                
            }
        case "AssignExpression":
            if js.GetSTType(node.Left) == "DotExpression"{
                if AssignExprCheck(node,payload){
                    return true
                }
            }
    }
}

```  
  
  
测试  
##   
  
针对Vulinbox中几个漏洞检测  
<table><tbody style="word-break: break-all;"><tr class="ue-table-interlace-color-single" style="word-break: break-all;"><td width="167" valign="top" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;background-color: rgb(255, 255, 255);font-size: 14px;">靶场<br/></span></td><td width="135" valign="top" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;background-color: rgb(255, 255, 255);font-size: 14px;">预期<br/></span></td><td width="171" valign="top" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;background-color: rgb(255, 255, 255);font-size: 14px;">检测结果<br/></span></td></tr><tr class="ue-table-interlace-color-double" style="word-break: break-all;"><td width="187" valign="top" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;font-size: 14px;">header location重定向</span></td><td width="135" valign="top" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;font-size: 14px;">有漏洞</span></td><td width="171" valign="top" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;font-size: 14px;">有漏洞</span></td></tr><tr class="ue-table-interlace-color-single" style="word-break: break-all;"><td width="187" valign="top" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;font-size: 14px;">meta 重定向-无等待</span></td><td width="135" valign="top" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;font-size: 14px;">有漏洞</span></td><td width="171" valign="top" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;font-size: 14px;">有漏洞</span></td></tr><tr class="ue-table-interlace-color-double" style="word-break: break-all;"><td width="187" valign="top" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;font-size: 14px;">meta 重定向-等待5s</span></td><td width="135" valign="top" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;font-size: 14px;">有漏洞</span></td><td width="171" valign="top" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;font-size: 14px;">有漏洞</span></td></tr><tr class="ue-table-interlace-color-single" style="word-break: break-all;"><td valign="top" colspan="1" rowspan="1" width="16" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;font-size: 14px;">window.location.replace</span></td><td valign="top" colspan="1" rowspan="1" width="135" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;font-size: 14px;">有漏洞</span></td><td valign="top" colspan="1" rowspan="1" width="0" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;font-size: 14px;">有漏洞</span></td></tr><tr class="ue-table-interlace-color-double" style="word-break: break-all;"><td width="187" valign="top" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;font-size: 14px;">window.location.hr</span></td><td width="135" valign="top" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;font-size: 14px;">有漏洞</span></td><td width="171" valign="top" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;font-size: 14px;">有漏洞</span></td></tr><tr class="ue-table-interlace-color-single" style="word-break: break-all;"><td width="187" valign="top" height="27" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;font-size: 14px;">window.location.assign</span></td><td width="135" valign="top" height="27" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;font-size: 14px;">有漏洞</span></td><td width="151" valign="top" height="27" style="word-break: break-all;"><span style="color: rgb(0, 0, 0);font-family: Optima-Regular, Optima, PingFangSC-light, PingFangTC-light, &#34;PingFang SC&#34;, Cambria, Cochin, Georgia, Times, &#34;Times New Roman&#34;, serif;letter-spacing: normal;text-align: left;font-size: 14px;">有漏洞</span></td></tr></tbody></table>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FO0icDV9xHJSyicpvMqoFg6A2R7LFtoty3KHhJJVDXhbHxnfrhLpK9iaekalwlzT0mwoznhGDPibhaKLwwqvp4WBJw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**更新日志**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZeiba3udA0awrRAUbvTSp4FhA7E6EXyYCdicPuB4icPT6pLp4xWwY07tnibSibwVRlXmx7KMIFC4LCPGiaw/640?wx_fmt=png "")  
  
  
**Yakit  v1.2.3-sp4**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZeiba3udA0awrRAUbvTSp4Fh6Yo7g2yz72zibQL6lMpibSlgKUaal9NB42nIWYTUias24HgU7QDOE4HHw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/f7AtEgJhMZeiba3udA0awrRAUbvTSp4FhUbab4zquWFCrlZ0uLYfClC8fSaS5Hyficicl0aZQmTRNDyuZQYcFL2UA/640?wx_fmt=jpeg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZeiba3udA0awrRAUbvTSp4FhA7E6EXyYCdicPuB4icPT6pLp4xWwY07tnibSibwVRlXmx7KMIFC4LCPGiaw/640?wx_fmt=png "")  
  
  
**Yaklang 1.2.4-sp1/sp2**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZeiba3udA0awrRAUbvTSp4FhWvo9oSXjQf2NjiciaLNfLXzOANZRhZN89t1RKNhLfpn9ObOKNcibMVJnQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/f7AtEgJhMZeiba3udA0awrRAUbvTSp4FhV4gVmp0zZsdHF2VtYibXZl7Slo9yiaICicrgPAfLHzDPlLpC5ibMY47MeQ/640?wx_fmt=png "")  
  
  
More  
  
  
YAK官方资源  
  
  
YAK 语言官方教程：  
https://yaklang.com/docs/intro/Yakit 视频教程：  
https://space.bilibili.com/437503777Github下载地址：  
https://github.com/yaklang/yakitYakit官网下载地址：  
https://yaklang.com/Yakit安装文档：  
https://yaklang.com/products/download_and_installYakit使用文档：  
https://yaklang.com/products/intro/常见问题速查：  
https://yaklang.com/products/FAQ  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/f7AtEgJhMZc6nLOagqic2nNou7bAeMlkj1CKwGWMGSiaeBCN9r5JBz87nQDSDFyRsPhWia09n3icgcNQicS7bK3qv8Q/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
长按识别添加工作人员  
  
开启Yakit进阶之旅  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/f7AtEgJhMZc5BYI1O7qwYC876L6gkbkApbD3olMibe5ibfpRe8dC7ZcUc67sHfqVs4WNUdCiaxG4b2kL7AFvicpmjA/640?wx_fmt=jpeg "")  
  
  
