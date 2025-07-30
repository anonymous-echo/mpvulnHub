> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3Mzg3OTU4OQ==&mid=2247493212&idx=1&sn=26b628127785f2cd24f839e5d6fdd527

#  JS 动态解析漏洞挖掘巧技 | 正则表达式「捕获」的未授权漏洞之门  
原创 庆尘  Daylight庆尘   2025-06-20 06:36  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibelX39p4gkmLa6XvTYIqqXo0ziaBUEFXt6gpmMOOQJnPSLVU6auGI4jJ52z9nUMlQRkUu593LtIhAkvAx9eEuhA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lIQ87GZ2CQudhDaMADia7Lk87uAC193q9riboribMBrmnKEfazIPNmGyybp654xwjTYQINQedT3fIlCu45qweaWLw/640?from=appmsg "")  
  
距离上次发文已经快一个月了，上一篇文章写请假贴的时候状态确实很不好，心态也出了点问题，最近休息了一段时间，调整了一下情绪和状态，缓和了很多，这几天也通过了一个很不错岗位的面试，月底就要入职了，那挖洞也该回归正轨了，继续给大家带来新的技术文章，今天依然是Js漏洞挖掘和未授权访问漏洞，我是真喜欢研究Js里面的东西，哈哈，立志要做Js漏洞挖掘大王！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dbY9cVHpfI1Ft4Cox8GXOurG1u3BbjHrvLZJYCA9hQYwWd5V7icB79Y6yVR1XoJPyRKhqp3HjPp5iaqicKswDHlXQ/640?from=appmsg "")  
  
  
  
一、引言  
  
对于经常挖SRC漏洞的白帽师傅来说，Findsomething和Hae这俩应该是必不可少的工具吧。  
  
Findsomething自然不用说，主要就是  
提取Js文件的信息，在平时的漏洞挖掘中是很好用的。但在一些特殊情况下，例如下面的场景：  
  
特殊场景  
  
  
  
01  
  
网站使用了Webpack等前端打包器  
  
02  
  
网站使用动态Js解析  
  
03  
  
使用动，态脚本注入实现的Js懒加载  
  
04  
  
使用单页应用（如 Vue、React这些SPA框架）常用的路由懒加载  
  
这样的场景下有时候匹配的Js文件不全，导致Findsomething只能对匹配到的Js文件进行信息提取，但实际上会遗漏不少网站加载的Js文件，这时候就只能打开F12手动搜索Js，稍微麻烦一点点。  
  
再述说Hae，那也是老生常谈的东西了，主要用来匹配Js文件和数据包中的敏感信息以及一些对我们漏洞挖掘有帮助的信息，那我刚才讲了这么多特殊场景，那这些特殊场景在Js里面会不会有自己的特殊写法呢，答案是肯定的。  
  
由于篇幅原因给大家简单总结了一下，想具体了解的可以问AI。  
<table><thead><tr style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);border-top: 0px;overflow-anchor: auto;background-color: rgb(242, 242, 242);"><th data-colwidth="205" style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);padding: 12px 18px;font-size: 16px;font-weight: 600;line-height: 28px;color: rgb(0, 0, 0) !important;border-top: 0px;border-right: 1px solid rgba(0, 0, 0, 0.08);border-bottom: 0px;border-left: 0px;border-image: initial;max-width: 448px;overflow-anchor: auto;"><section><span leaf="">场景</span></section></th><th style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);padding: 12px 18px;font-size: 16px;font-weight: 600;line-height: 28px;color: rgb(0, 0, 0) !important;border: 0px;max-width: 448px;overflow-anchor: auto;"><section><span leaf="">核心代码标记（需重点分析）</span></section></th></tr></thead><tbody><tr style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);border-top: 1px solid rgba(0, 0, 0, 0.08);overflow-anchor: auto;"><td data-colwidth="205" style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);padding: 12px 18px;font-size: 16px;font-weight: 400;line-height: 28px;color: rgba(0, 0, 0, 0.85) !important;border-top: 0px;border-right: 1px solid rgba(0, 0, 0, 0.08);border-bottom: 0px;border-left: 0px;border-image: initial;max-width: 448px;overflow-anchor: auto;"><section><span leaf="">Webpack 打包</span></section></td><td style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);padding: 12px 18px;font-size: 16px;font-weight: 400;line-height: 28px;color: rgba(0, 0, 0, 0.85) !important;border: 0px;max-width: 448px;overflow-anchor: auto;"><code style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);background: none 0% 0% / auto repeat scroll padding-box border-box rgba(0, 0, 0, 0.06);border-radius: 4px;color: rgb(0, 0, 0);font-size: 14px;font-family: Menlo, Monaco, Consolas, &#34;Courier New&#34;, monospace;overflow-anchor: auto;"><span leaf="">__webpack_require__</span></code><section><span leaf="">、</span><code style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);background: none 0% 0% / auto repeat scroll padding-box border-box rgba(0, 0, 0, 0.06);border-radius: 4px;color: rgb(0, 0, 0);font-size: 14px;font-family: Menlo, Monaco, Consolas, &#34;Courier New&#34;, monospace;overflow-anchor: auto;"><span leaf="">import()</span></code><span leaf="">、模块包装器结构</span></section></td></tr><tr style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);border-top: 1px solid rgba(0, 0, 0, 0.08);overflow-anchor: auto;"><td data-colwidth="205" style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);padding: 12px 18px;font-size: 16px;font-weight: 400;line-height: 28px;color: rgba(0, 0, 0, 0.85) !important;border-top: 0px;border-right: 1px solid rgba(0, 0, 0, 0.08);border-bottom: 0px;border-left: 0px;border-image: initial;max-width: 448px;overflow-anchor: auto;"><section><span leaf="">动态 JS 解析</span></section></td><td style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);padding: 12px 18px;font-size: 16px;font-weight: 400;line-height: 28px;color: rgba(0, 0, 0, 0.85) !important;border: 0px;max-width: 448px;overflow-anchor: auto;"><code style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);background: none 0% 0% / auto repeat scroll padding-box border-box rgba(0, 0, 0, 0.06);border-radius: 4px;color: rgb(0, 0, 0);font-size: 14px;font-family: Menlo, Monaco, Consolas, &#34;Courier New&#34;, monospace;overflow-anchor: auto;"><span leaf="">eval(</span></code><section><span leaf="">、</span><code style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);background: none 0% 0% / auto repeat scroll padding-box border-box rgba(0, 0, 0, 0.06);border-radius: 4px;color: rgb(0, 0, 0);font-size: 14px;font-family: Menlo, Monaco, Consolas, &#34;Courier New&#34;, monospace;overflow-anchor: auto;"><span leaf="">new Function(</span></code><span leaf="">、字符串拼接 JS 代码</span></section></td></tr><tr style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);border-top: 1px solid rgba(0, 0, 0, 0.08);overflow-anchor: auto;"><td data-colwidth="205" style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);padding: 12px 18px;font-size: 16px;font-weight: 400;line-height: 28px;color: rgba(0, 0, 0, 0.85) !important;border-top: 0px;border-right: 1px solid rgba(0, 0, 0, 0.08);border-bottom: 0px;border-left: 0px;border-image: initial;max-width: 448px;overflow-anchor: auto;"><section><span leaf="">动态脚本注入</span></section></td><td style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);padding: 12px 18px;font-size: 16px;font-weight: 400;line-height: 28px;color: rgba(0, 0, 0, 0.85) !important;border: 0px;max-width: 448px;overflow-anchor: auto;"><code style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);background: none 0% 0% / auto repeat scroll padding-box border-box rgba(0, 0, 0, 0.06);border-radius: 4px;color: rgb(0, 0, 0);font-size: 14px;font-family: Menlo, Monaco, Consolas, &#34;Courier New&#34;, monospace;overflow-anchor: auto;"><span leaf="">document.createElement(&#39;script&#39;)</span></code><section><span leaf="">、路径映射函数（如 </span><code style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);background: none 0% 0% / auto repeat scroll padding-box border-box rgba(0, 0, 0, 0.06);border-radius: 4px;color: rgb(0, 0, 0);font-size: 14px;font-family: Menlo, Monaco, Consolas, &#34;Courier New&#34;, monospace;overflow-anchor: auto;"><span leaf="">r.u</span></code><span leaf="">）</span></section></td></tr><tr style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);border-top: 1px solid rgba(0, 0, 0, 0.08);overflow-anchor: auto;"><td data-colwidth="205" style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);padding: 12px 18px;font-size: 16px;font-weight: 400;line-height: 28px;color: rgba(0, 0, 0, 0.85) !important;border-top: 0px;border-right: 1px solid rgba(0, 0, 0, 0.08);border-bottom: 0px;border-left: 0px;border-image: initial;max-width: 448px;overflow-anchor: auto;"><section><span leaf="">SPA 路由懒加载</span></section></td><td style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);padding: 12px 18px;font-size: 16px;font-weight: 400;line-height: 28px;color: rgba(0, 0, 0, 0.85) !important;border: 0px;max-width: 448px;overflow-anchor: auto;"><code style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);background: none 0% 0% / auto repeat scroll padding-box border-box rgba(0, 0, 0, 0.06);border-radius: 4px;color: rgb(0, 0, 0);font-size: 14px;font-family: Menlo, Monaco, Consolas, &#34;Courier New&#34;, monospace;overflow-anchor: auto;"><span leaf="">() =&gt; import(</span></code><section><span leaf="">、</span><code style="-webkit-font-smoothing: antialiased;box-sizing: border-box;-webkit-tap-highlight-color: rgba(0, 0, 0, 0);background: none 0% 0% / auto repeat scroll padding-box border-box rgba(0, 0, 0, 0.06);border-radius: 4px;color: rgb(0, 0, 0);font-size: 14px;font-family: Menlo, Monaco, Consolas, &#34;Courier New&#34;, monospace;overflow-anchor: auto;"><span leaf="">React.lazy(</span></code><span leaf="">、框架路由配置</span></section></td></tr></tbody></table>  
到这里我们的目的就很清晰了，那就是  
如何在这些场景的Js文件中提取更多的Js文件路径以供我们分析？也就是尽可能保证我们对Js的分析能够覆盖站点的所有Js文件。  
  
今天我们针对其中的动态脚本注入场景来进行分析，后续我也会继续完善其他特殊场景的分析，当然师傅们也可以依葫芦画瓢，尝试自己去分析一下，相信以师傅们的能力，这都是小case。  
  
二、动态脚本注入  
  
动态脚本注入，其实在我平时SRC漏洞挖掘中，这也是非常常见的一种Js写法，特别是  
动态脚本注入实现的 JS 懒加载  
  
来看这样一段Js代码，不知道师傅们是否熟悉这种代码格式  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKow2EZHuY6AC5dymvaC7QvTonefwibhMWoAtq8V2lk4MxrYKic1LNjARPg/640?wx_fmt=png&from=appmsg "")  
  
这就是很明显的动态脚本注入实现的 JS 懒加载写法（DOM 注入引用），这种代码会对我们漏洞挖掘造成什么影响？  
  
代码影响  
  
  
  
01  
  
单个页面只会加载所需的Js文件，正常测试无法做到覆盖全局Js  
  
02  
  
传统工具难以识别运行时才加载的 JS 文件，例如fd  
  
03  
  
可以根据这段代码进行Js文件还原，有方法之后会更加方便  
  
由于这些动态加载的Js，存在测试难以覆盖，普通用户无法接触等问题（例如可能普通用户在站点中使用功能时，就不会触发高权限功能需要的Js文件，更抓不到API接口，路由等信息。这种情况是非常多的）  
  
那这时候我们发现了站点有一段这样的动态解析Js代码，就可以根据代码还原所有的Js文件路径，尽可能去将我们的  
攻击测试面覆盖到整个站点的Js文件上。  
  
  
  
想要将动态解析的Js代码还原为Js文件路径有很多方法，其实能看懂一点Js代码的都能很快还原出来，毕竟就两三行控制流代码。但有的师傅说“主播主播，这个代码实在是看不懂，有什么简单又快捷的Js还原方法吗”，别急，且听我娓娓道来。其实这个东西最方便的还是问AI。  
  
AI模版  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ibelX39p4gkmLa6XvTYIqqXo0ziaBUEFXt6gpmMOOQJnPSLVU6auGI4jJ52z9nUMlQRkUu593LtIhAkvAx9eEuhA/640?from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lIQ87GZ2CQudhDaMADia7Lk87uAC193q9riboribMBrmnKEfazIPNmGyybp654xwjTYQINQedT3fIlCu45qweaWLw/640?from=appmsg "")  
  
{JS动态加载代码段}  
  
  
将这段JS动态加载代码还原为Js路径，输出结果一行一个  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/dbY9cVHpfI1Ft4Cox8GXOurG1u3BbjHrvLZJYCA9hQYwWd5V7icB79Y6yVR1XoJPyRKhqp3HjPp5iaqicKswDHlXQ/640?from=appmsg "")  
  
  
效果如下（我这里用的豆包，你们也可以试试其他的，这是一个很简单的需求，应该AI都是没问题的）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKoRPrUicfhmY9pcqibEd3BJgCrDFvtblYSSABFHWNx4YCdwPdJHhveKmfQ/640?wx_fmt=png&from=appmsg "")  
  
再用这些js文件路径拼接到JS文件所在的域名，就会得到站点的所有Js文件的完整URL地址，这时候就可以正常的从这些Js文件中取出信息了。这时候可以进行批量提取，方法也很多，下面列举两种（文末还有一种）。  
  
提取方法  
  
  
  
01  
  
挨个在浏览器中访问，观察Findsomething匹配到的信息，配合手工观测实现信息提取和漏洞挖掘  
  
02  
  
用  
Burp的爆破模块，刚还原出来的Js路径名作为字典，批量跑，之后可以观察爆破结果中的Hae匹配结果，配合手工验证，效果一样挺不错（比较看你自己的Hae正则）  
  
后续就一样就是观察是否有敏感信息，以及测试未授权访问漏洞等操作。  
  
三、Hae使用技巧  
  
上面这个流程分析下来存在两个问题  
  
流程问题  
  
  
  
01  
  
如何在繁多的Js数据包中发现动态解析的Js代码块？  
  
02  
  
如果还原后的Js文件特别多，手工分析工作量太大，应该如何解决  
  
关于问题一，这就是我们要讲Hae的问题了  
  
Hae不仅仅是用来匹配敏感信息，其实也能定制出很多种特殊用法，将你自己的理解转化为Hae正则后，你会发现你挖洞过程中方便了很多。例如我之前发布的用于匹配请求包中的数字id的正则，这个也帮助我和很多师傅挖掘到了越权等漏洞。  
  
其实这种可自定义程度高的工具，最好是深入研究并且搭配自己的理解和挖洞习惯，让它变成你自己的专属武器。  
  
  
  
所以这里我们可以编写正则用于匹配Js中的动态解析Js代码块，但Hae的官方正则库中其实也有，官方正则库地址如下：  

```
https://github.com/gh0stkey/HaE/blob/master/src/main/resources/rules/Rules.yml
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKo17VEia5Yia8OkPiaibNQaX6pD0FyBLddoHWmwafyHjIicibVhmJmO8s76YHQ/640?wx_fmt=png&from=appmsg "")  
  
  
其实官方的正则库中也是有很多不错的正则的，毕竟这些都是各位很厉害的师傅给hae官方提供的适用于某种场景的正则，且Hae官方也认可。师傅们有空也可以去里面看看有没有  
匹配自己挖洞习惯的正则。  
  
好了回归正题，本次我们用到的正则在Hae的官方正则库中名字叫做——  
Create Script，正则如下  

```
name: Create Script
        loaded: true
        f_regex: (\{[^{}]*\}\s*\[[^\s]*\]\s*\+\s*&#34;[^\s]*\.js&#34;)
        s_regex: '&#34;?([\w].*?)&#34;?:&#34;(.*?)&#34;'
        format: '{0}.{1}'
        color: green
        scope: response body
        engine: nfa
        sensitive: false
```

  
在Hae中配置好后结果如下（名字可以随便写，我这里是换了一个名字）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKoBrhx5tEQA1LXyUUcDFM4riaRcpMUkPhhE9CibM6ZwBl6Hc9GeNM71luw/640?wx_fmt=png&from=appmsg "")  
  
匹配的效果如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKoDuBer5pszWcMuBeRSw6QLpAdUdP3FibG9RBhPDLQ5icNl64mynGV7MLQ/640?wx_fmt=png&from=appmsg "")  
  
  
这样在平时的渗透中，就可以自动化发现这种动态解析代码块，快速定位到动态解析的Js代码块，再通过AI等方式进行Js文件名还原。  
  
四、GAP使用技巧  
  
问题二也是我们覆盖全站Js文件需要遇到的问题，因为这种动态解析Js代码块，我遇到的其实还原出来最少都有30个Js文件路径，手工测试无疑工作量很大，所以这里我们也可以使用一个自动化插件——  
GAP  
  
GAP也是一个非常好用且轻量化的Burp插件，拥有强大的信息提取能力，一般多用于网站请求包的参数收集为后续的Fuzz操作做准备  
  
  
  
在本文中，我们将使用它的  
批量信息提取能力。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKoESGq7A6aVQsyOsIfTmfrYJvvhKiahU30K6rqfMM3iaGicTfYHZXAZtbQw/640?wx_fmt=png&from=appmsg "")  
  
刚刚我们介绍了对匹配出来的JS文件进行处理的第二个方法，是使用Burp的爆破模块。这个方式同样也是使用爆破模块，但在后续的处理中会方便很多。  
  
例如我们现在还原出了如下的Js文件路径  

```
digital-human-portal/js/user0.041b6d60.js
digital-human-portal/js/user258.49eae47a.js
digital-human-portal/js/user86.32fa2895.js
digital-human-portal/js/user228.b52b75e6.js
digital-human-portal/js/user196.958bc728.js 
digital-human-portal/js/user260.5e72744c.js 
digital-human-portal/js/user8.8b801985.js 
digital-human-portal/js/user88.ba5e731b.js 
digital-human-portal/js/user12.775b3949.js 
digital-human-portal/js/user4.7c86493c.js 
digital-human-portal/js/user234.16cd7bf0.js 
digital-human-portal/js/user68.741bd08a.js 
digital-human-portal/js/user210.e2264872.js 
digital-human-portal/js/default.02c9c257.js 
digital-human-portal/js/user250.78d4755e.js
```

  
那进入爆破环节，随便发一个Js存储位置根域的包到爆破模块，记得找对Baseurl，不要随便设爆破变量  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKocZLqFic6wPUCsADp56QuObp7iciatlU9dB1bxabLTW1dFmzr5bC8SlNYg/640?wx_fmt=png&from=appmsg "")  
  
设置爆破字典，也就是payload，  
记得取消下方的payload encoding  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKo1ic8uLql7JY62cRoaxobrye5puWnRVmwkbHF1bC0J57IR9lNdCAF18Q/640?wx_fmt=png&from=appmsg "")  
  
爆破结果如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKoYpOOiamY0qziakMtm0Hicibhurc7GB2LOJcGTibBpichIO6DYsKwJrMkgzHg/640?wx_fmt=png&from=appmsg "")  
  
这种一眼看过去length大小不一，就说明是跑对了的  
  
接下来就是结果分析，全选爆破结果，右键直接发送到GAP  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKonMvSjrbfWia3o1AZo3w7MEibAm8D53tWh8bmEg5T3GfaUgibHDXWY3d8g/640?wx_fmt=png&from=appmsg "")  
  
GAP结果如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKolnvetCTEERzMhBOh6N1IH7qMrRgKrmszLv0EbphlAmGOzdndKSbOkA/640?wx_fmt=png&from=appmsg "")  
  
可以看到参数，链接，接口都已经全部提取并展示出来了，这时候就可以根据接口去手动查找或测试一下可能存在的漏洞  
  
五、实战漏洞案例  
  
依旧quake挨个点网站开局，打开某个网站如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKoibibYM1QWUwv96tSZJ4QmFbkk9waCbk4Qk7S1yYPWLianvViav7JsyeyEQ/640?wx_fmt=png&from=appmsg "")  
  
现在我们处于未登录状态，观察数据包，发现匹配到Js节点信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKokTRoyTGZwYWNSpOxsalKsBkyfKJ9AhKStbhInR2jBZg0Fzy1JWbojA/640?wx_fmt=png&from=appmsg "")  
  
定位到动态解析的js代码块  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKo2z10ZeqRPoHN31MkYWuHUqOwZ8PxU4yibYVd13ZXSw868HNQq2QqRdA/640?wx_fmt=png&from=appmsg "")  
  
复制代码转发到AI，让Ai帮我们还原出Js文件地址，如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKoCnNwMvPnlpWWDZbJyjD8RliaokZAlTEKmxbJ8v4t8zPymqlz9rxhiajw/640?wx_fmt=png&from=appmsg "")  
  
复制结果作为字典，到爆破模块进行批量爆破  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKoS8hE3lsUejBXf3aRsJ19h1htr9Rpfo5eYM9AdCrbfHQl8Nrz2bzOmw/640?wx_fmt=png&from=appmsg "")  
  
将爆破结果转发到GAP  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKoYTMhaRdtKhSq740k0RzQsbZbkZkvwdNzgmXYl1I05DvT739tt89R5Q/640?wx_fmt=png&from=appmsg "")  
  
分析GAP的匹配结果，发现API  

```
/activationCode/entrance?packageName=1
```

  
猜测该API是路由，尝试拼接域名访问  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKo5ic0jT8awX46kxia8NiaL6Vh259Uyzfty5l150awHIWv3nXh3ZWmBMAicQ/640?wx_fmt=png&from=appmsg "")  
  
提示激活码已全部领取完毕，看来这是领取激活码的页面，此时观察数据包，如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKozGPVt3m8n0Vm4TCpp9DqBpQT8ZDQfQrYgXkzKJAzvXXkvjicF9stW1w/640?wx_fmt=png&from=appmsg "")  
  
可以看到url中很明显的  

```
/exhaustion/1
```

  
然后提示套餐不存在，说明这个/1中的1是通过我们访问路由时传入的packageName=1，那提示套餐不存在应该怎么办呢？那就爆一个存在的套餐出来嘛  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKo7bL0J9uTSwvhyNtARR5LKBlEWrHoUHia9XT5QZ8XKbF4UMnH7CM3icvw/640?wx_fmt=png&from=appmsg "")  
  
注意：这种路径作为参数值的，一般参数值都是数字，字符型比较少，所以第一次尝试直接爆数字就行，先爆个一两百看看效果。如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKoMr0YyGCvZricPttHvuRXKMoj7VhgJY3LXAm6fvlLXhaAH9yVbZbiarIw/640?wx_fmt=png&from=appmsg "")  
  
可以看到成功爆破出123，回显是success，此时再把123作为参数带入刚才我们构造的路由中进行访问，页面如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKoUWbHu7KibpibPiaIsSMkmYVPpWsnZ1jicFvXiay4pILda5FwPia9l58gWicwg/640?wx_fmt=png&from=appmsg "")  
  
点击领取激活码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKo2yicoWqUia7Qia2ibJ6Dic6Z3dibNL5CNFp0bZG2ocdfHp4Lva11UYe0OLQQ/640?wx_fmt=png&from=appmsg "")  
  
提示需要登录，那我们就登录账号，再点击领取激活码，如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mK8kXuuyDk8rdkiaMofmicWSoArYnTicoKoqQcnq0vkDr21mS42vyVjzU1icMWZpstdpg4ibIYPm5uP8ffltG4b2wgA/640?wx_fmt=png&from=appmsg "")  
  
成功领取激活码并成功兑换会员，中危起步漏洞到手。  
  
六、总结  
  
其实总的流程很简单  
  
测试流程  
  
  
  
01  
  
Hae匹配到JS节点信息  
  
02  
  
调用AI还原Js完整文件路径  
  
03  
  
Js文件路径做爆破变量进行爆破  
  
04  
  
爆破结果转发到GAP  
  
05  
  
对GAP的匹配结果进行分析  
  
并且这种存在动态创建JS代码块的地方，这样已经能分析到绝大部分Js文件了，基本满足我们的测试需求，能提取到不少对后续测试有用的信息。  
  
那今天的文章到这里就结束啦，希望对各位师傅们的漏洞挖掘技术的提高有所帮助。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/dB8siaunhHjrNHg8sYVBcWg4fWXg7xZgVCUqPjPl4JJq1icnoRc6gSlYKYgqxMhRuhMfmWR5VyVpE5wADeMwj5IA/640 "")  
  
师傅们如果  
对Js漏洞挖掘有自己的想法和思路的，也可以联系我一起交流和探讨哈。最后  
感谢各位师傅的阅读，我们下期再见。  
  
  
