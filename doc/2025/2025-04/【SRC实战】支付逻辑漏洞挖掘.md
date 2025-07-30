#  【SRC实战】支付逻辑漏洞挖掘   
小安  迪哥讲事   2025-04-01 23:07  
  
## 前言  
  
记录一次支付逻辑漏洞挖掘，这个支付漏洞很细，能挖出来需要十分细心和耐心，一点点看数据包，不然真的非常容易漏下，实际上这个漏洞的出现就是由于在确定订单价格时，后端数据校验缺失导致的。  
  
这是一个新能源汽车充电小程序，出现问题的功能时购买电池的功能点，一开始选择购电，可以选择购买30度，50度，80度。不同电量对应了不同的价钱，30度电248元，80度是380元，这个漏洞的效果，就是通过简单的替换，将购买80度电时的价格变成购买30度电的价格，实现降价。  
  
这篇文章将以复盘的视角，一边讲解利用过程，一边分析前后端支付发起逻辑，希望和大家交流！  
## 渗透开始  
1. 首先进入小程序购买页面，是这样的，可以选择三种不同的电量，预约购买  
  
![image-20250226135515114.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLic1dtYSngFiaCQ7XleGZ4cry8zYCW69sI0MhhRzxFpo7G7WSjZ1Md08iaM9iceMrAWA27eUEWsIfic2Jg/640?wx_fmt=png&from=appmsg&wxfrom=13&tp=wxpic "")  
  
1. 之后，点击立即预约，抓包，会发现一开始接口会发送一个priceld  
  
![image-20250226140916087.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLic1dtYSngFiaCQ7XleGZ4cry3C3kOG9dRBdD3qxOPgGzMCE1dYlnHz8cCUjd81Fwnlia9jTTbubEwxg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
这个接口返回的是订单的价格，看变量名好像还有一些付款方式什么的  
  
![image-20250226141031299.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLic1dtYSngFiaCQ7XleGZ4cryEYqSJgiahUTYc3fJHdCoBFbgP8xP8eTkQG89Dgfc4FdwSLXnCfeHCTA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
1. 紧接着，下一个请求，这里发送的也是priceld，请求如下：  
  
![image-20250226141257987.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLic1dtYSngFiaCQ7XleGZ4cryYoANP5BDIXMhTBTaIAicbKdoXq7UTmCSVcvkbZwNicfVTH7OvTMQTia7A/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
观察返回包，返回的是价格，猜测这个接口就是返回的当前选定项目的价格：  
  
![image-20250226141453698.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLic1dtYSngFiaCQ7XleGZ4cry1TiaWtuT4W0chdJEX8E7s5ibT9NtM6yoYsmd9yTHffUxNDCib20kpibSxA/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
1. 此时界面来到了准备确认订单的页面，如下图，价格显示的是248元：  
  
![image-20250226142256705.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLic1dtYSngFiaCQ7XleGZ4cryVOicTVwZHC9zeGALj5nb5s1tcdRWaICpNcIp080YSnwhG2b9vWscU6A/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
1. 到这里就可以思考一下这个过程，首先就是选择三个充电项目，也就是三个不同的电量，选择不同的电量，点击预约，费用是不同的，在这个过程中，主要有两个请求：第一就是最开始的，会直接生成个priceld发送到后端，返回订单的金额和退款规则等等；第二就是再次发送priceld，会返回当前订单的费用总计。  
  
1. 那么这里我们就可以设想：如果我点击第三个，提交的时候第一个请求首先得到了他的priceld，但是在发送第二个请求的时候，我将高价(80度电)的priceld替换为低价(30度电)的priceld，那么是不是就能实现降价呢？  
  
1. 实践起来，首先点击第三个80度电，点击预约  
  
![image-20250226144324583.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLic1dtYSngFiaCQ7XleGZ4cryAgsWDP1OPVWbfocCG2X8MbficanBjyCBgL88AMzFW6JQaQ6mfXw6YkQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
1. 之后Burp拦截开启，开始抓包，首先第一个可以看到是生成了第三个项目的priceld  
  
![image-20250226145403575.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLic1dtYSngFiaCQ7XleGZ4cryZzaQDmWtrwp1hELc9RqgcKeLpFcEsydj4DQGNhPM6q0FSsiaQSKb07w/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
观察返回包，可以发现也是第三个项目的度数和费用，80度380元  
  
![image-20250226145456432.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLic1dtYSngFiaCQ7XleGZ4cryKPFDOWqH9SJgno9YOia2HgBNpJw9oKicNcfbC5MwLcJuM0JRdOZBvD9Q/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
1. 继续抓包，可以看到此时已经来到第二个请求，通过之前的抓包，我们把之前280的priceld，替换到这里来：  
  
![image-20250226150233597.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLic1dtYSngFiaCQ7XleGZ4cryHs4VsaRZYSfJib0JPNBwicTXuBsMJmolWE2lI0YGMXrImdVkQVXd8x7Q/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
观察返回包，发现此时的数值确实变了，变成了248元  
  
![image-20250226150441999.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLic1dtYSngFiaCQ7XleGZ4crygslhqoDSbxB4H1vtZLxgCxtF7BUMGzYYUoB37hahcfv4lh7aH3ougg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
1. 此时放掉返回包，发现前端界面的数值也发生了一些变化，请求的服务是80度，服务费是340元，但是下面的费用总和却是248元？？！！  
  
![image-20250226150610241.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLic1dtYSngFiaCQ7XleGZ4crySnN6aTjl0b8ibibJoOAO5VTxmQOydIm0eFPWswbia0k3xB3U7uZTxZdcQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
1. 到这里非常欣喜，再稍作分析，结合上面创建预约单的两个请求，可以知道，上面两个请求大概分别控制的是这些部分的内容：  
  
![image-20250226151014824.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLic1dtYSngFiaCQ7XleGZ4cryXBI4cWwqbL8YyLd7zv44ndZQMnhl6F98Yfll64YydnfziaUBicWibEhiaQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
1. 到了这里，我们通过更改请求包的方式，实现了对价格的控制，按照经验来讲，已经离成功不远了，在以往的老系统，有很多的支付漏洞价格修改，信息修改等都是通过返回包来控制，这种漏洞在现在已经非常少见了，而且大多数修改返回包只是仅仅更改了前端的显示。很难达到修改实际支付数额的效果。  
  
1. 继续测试，我们点击确认订单，抓包，看到了这些参数，看起来应当就是预约单的内容，通过变量发现应该是当前预约单的一些信息，其中还是有priceld，我们再次修改，替换他成为248元的那个priceld：  
  
![image-20250226151510625.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLic1dtYSngFiaCQ7XleGZ4cryBKeQibibhiaX9QrboiboyAz3XlkRWzy5t2xaI4CGccgajuPRibF6UJOubKQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
1. 更改之后放包，这里生成了第三方支付的二维码。  
  
![image-20250226151552852.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLic1dtYSngFiaCQ7XleGZ4cryN1D3Cm6VQIf9Aja3ShF6eEJwKpC9qLjQgwWIjQOpxrtHsljSjVmg1w/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
1. 扫描后，发现确实金额变成了第一种充电度数的金额，248元，说明该系统直接向第三方支付开出了248元的订单，至此，证明支付漏洞成功利用，已经实现降价。  
  
![1740554435907.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLic1dtYSngFiaCQ7XleGZ4cryDhQz6bibRNNS5kzdSt2o8SjbOyMLnffo1F45RmoHZfQia64jBH4baRjw/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
## 复盘总结  
  
读到这里，相信你一定有一种“茅塞顿开”的感觉，是的，这个漏洞十分简单，就是因为他这个支付金额的确认逻辑是通过一个金额id(priceld)，通过简单的把A产品的金额id(priceld)，替换成其他产品的金额id(priceld)，实现”使用其他产品的钱，购买A产品“的效果。  
  
背后的支付逻辑大概如下图  
  
![image-20250226163344720.png](https://mmbiz.qpic.cn/mmbiz_png/3xxicXNlTXLic1dtYSngFiaCQ7XleGZ4crygdjrbqo9l5XgfCNRgTSoodLufchK8P43FxPRJ39ACMUClVDOEGkia2A/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
因此，我们就可以通过更改第二个请求的priceld，实现了修改最终订单的付款费用，达成了更改价格的效果。  
  
实际上这个漏洞不是特别难，但是经过调研测试发现，目前这套支付的处理逻辑有很多种，各行业的生产系统都在使用，面对C端的产品出现这种漏洞非常严重，同样根据这样的逻辑我们也可以进一步引申思考，同样的逻辑可能不光出现在支付过程，也许还可能出现在其他类似的例如积分兑换等功能上。我是小安，欢迎大家对本文章展开讨论，指点，批评，感谢你的观看！  
  
**文章来源：奇安信攻防社区**  
  
**链接：https://forum.butian.net/share/4204**  
  
**作者：新人小安**  
  
  
本知识星球独家福利:实战中有不懂问题可以直接来找星主,星主可以提供实战指导  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5EMr3X76qdKBrhIIkBlVVyuiaiasseFZ9LqtibyKFk7gXvgTU2C2yEwKLaaqfX0DL3eoH6gTcNLJvDQ/640?wx_fmt=png&from=appmsg "")  
  
往期回顾  
  
[一款bp神器](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495880&idx=1&sn=65d42fbff5e198509e55072674ac5283&chksm=e8a5faabdfd273bd55df8f7db3d644d3102d7382020234741e37ca29e963eace13dd17fcabdd&scene=21#wechat_redirect)  
  
  
[挖掘有回显ssrf的隐藏payload](https://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496898&idx=1&sn=b6088e20a8b4fc9fbd887b900d8c5247&scene=21#wechat_redirect)  
  
  
[ssrf绕过新思路](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495841&idx=1&sn=bbf477afa30391b8072d23469645d026&chksm=e8a5fac2dfd273d42344f18c7c6f0f7a158cca94041c4c4db330c3adf2d1f77f062dcaf6c5e0&scene=21#wechat_redirect)  
  
  
[一个辅助测试ssrf的工具](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496380&idx=1&sn=78c0c4c67821f5ecbe4f3947b567eeec&chksm=e8a5f8dfdfd271c935aeb4444ea7e928c55cb4c823c51f1067f267699d71a1aad086cf203b99&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips‍](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
