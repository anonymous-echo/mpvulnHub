#  一个0day的开端：失败的man与nday   
 蚁景网安   2024-12-13 08:30  
  
最近在审计java的CMS，跟着文章进行nday审计，找准目标newbee-mall Version 1.0.0（新蜂商城系统），并跟着网上文章进行审计：  
  
https://blog.csdn.net/m0_46317063/article/details/131538307  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EB1Px1F47wiarYl2ncQH23E48LxTHErFXTFZiac5IibwjTSZ9w0Zf8N21kQ/640?wx_fmt=other&from=appmsg "null")  
  
下载唯一的版本，且源码README中版本也对的上，但没想到nday全部复现失败，但在一番审计后找到了一个新的漏洞点：ssrf，且在前台可以被用户触发。  
  
失败的man与nday：  
  
失败的sql注入漏洞：  
  
（此漏洞原本可以在前台与后台进行sql注入攻击）  
  
分析文章中有两sql注入漏洞，是由于引入mybatis依赖导致，但在我下的版本中根据关键字符 ${ 找不到任何的注入点，经过与分析文章对比发现所有注入点全部由 ${ 改成了 #{ 由此完成修复。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EBmsgxTcLBrLnsiceiaZbXotnquzd3QCiaibj7mtzGcFhBluUT1bdNJ5EjCw/640?wx_fmt=other&from=appmsg "null")  
  
失败的权限绕过：  
  
（此漏洞原本可以在admin登录后台通过/;/admin/test完成权限绕过）  
  
复现文章写到以request.getRequestURI()获取路径获取路径后再进入if判断：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EBbCQWeR3CVoT7gz2TSjDwAOTNTw7ekbDgG3zDaibsicuTgNsAeqcIrMicA/640?wx_fmt=other&from=appmsg "null")  
  
但我下载的版本进行了修复：将获取前端传输的路径方法改为了：getServletPath()从而完成修复。  
  
两种方法的不同具体分析可以参考如下文章：  
  
https://forum.butian.net/share/3730  
  
失败的越权漏洞：  
  
（此漏洞原本可以根据传入的id参数越权修改他人信息。）  
  
定位到具体代码：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EBPMjamzRGQZXVuIz1VkWnF45bjkc4wqzonKibtXcvTfqtpgRiaGGic26Qg/640?wx_fmt=other&from=appmsg "null")  
  
此处代码与复现文章一样，都是先创建一个NewBeeMallUserVO对象，再通过是否为空判断信息修改是否成功。  
  
真正修改信息的代码在updateUserInfo方法里面，于是跟进该方法实现处：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EB11h8bf9kXUvzIECOu5pyCpEMv3r4fMUpY5BNZSdibn72BN0S838kgOQ/640?wx_fmt=other&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EBjzNwfFfjZb91ickMMpL8eOJbhicVDR7qxicTic9T1o8FfKXLrCjrTIHUqA/640?wx_fmt=other&from=appmsg "null")  
  
发现跟到了接口，于是我们继续跟进，找该接口的实现类：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EBic3Z7dzFeJF51iaRIFgDyVNTm4wBWqeI2VVzOWjQh7BWZC7NjOoUgpbA/640?wx_fmt=other&from=appmsg "null")  
  
跟进到如下类，找到具体实现的代码块：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EBTRLyBQV6xorchmooGWNMhLAiarkhU4Qho6x7MZEAfDRJDxa5H0tZkaw/640?wx_fmt=other&from=appmsg "null")  
  
复现文章代码在进入if判断前只有一行代码，并且代码逻辑是从前端传入的id值进行信息修改，但可以看到我下载的代码有两行：  
  
NewBeeMallUserVO userTemp = (NewBeeMallUserVO) httpSession.getAttribute(Constants.  
MALL_USER_SESSION_KEY);  
  
首先通过http.Session获取当前用户，再赋给创建的userTemp对象。  
  
MallUser userFromDB = mallUserMapper.selectByPrimaryKey(userTemp.getUserId());  
  
再从userTemp对象中获取id值进行信息修改，而非从前端请求中获取参数id的值，来完成漏洞修复。  
  
0day的发现：  
  
登录后台，点击修改或者添加商品：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EBBKysiaC5e5w5jntDicia60Wu5leQibbkFG2Vv9tkplO431ZINvYvHMlwdA/640?wx_fmt=other&from=appmsg "null")  
  
随意传入图片后点击保存并抓包。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EBaHNKH3iau3sibHs50Ccia8XwffBwp4PdzLHIXl1pJVibnmScfyp6GJ4mbA/640?wx_fmt=other&from=appmsg "null")  
  
将POST数据包如上两个参数修改为dnslog地址，放包，在商城前台搜索该商品名称。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EBVs6ia3HU3MNWrN3Q1WVLsh2piamYNjylAgh0ibYmGSHPK6DzhuGcpibBOg/640?wx_fmt=other&from=appmsg "null")  
  
点击访问，dns平台出现记录。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EBCyDf85qBNk7ZzeRHPUKnY2klIZ4mf6sic85MAo5iblUDXOXQHAz9nx6Q/640?wx_fmt=other&from=appmsg "null")  
  
漏洞代码分析：  
  
先看看商品信息存储过程：  
  
根据接口定位代码块：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EBJvGWZw0icc4ZA39nI9u5W68wtFSOOTCVPnqzKdfqYCwk9Ey0xVTCEgQ/640?wx_fmt=other&from=appmsg "null")  
  
可以发现在接受参数后进行是否为空判断后进入了核心方法updateNewBeeMallGoods，跟进：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EBoCYXk0HMUaS0WOWDb5C8g9YOKf3Hb0aViaTmibriarkZoPxH7GZJP05CA/640?wx_fmt=other&from=appmsg "null")  
  
跟到接口后再找到接口实现类，最后定位到更新信息代码块。  
  
可以看到，仅仅对传入参数值进行为空判断和相同判断后，便调用set方法进行存储。  
  
接下来再看看商品信息调用代码链。  
  
根据触发漏洞的数据包接口定位代码块：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EBoiaUIzeYkqK3z1ibdT8YpzLaB4yFhrazp5YsxLPTjiahgJD8xaXzygv2Q/640?wx_fmt=other&from=appmsg "null")  
  
此处代码根据传入goodsid参数，将商品渲染到前端，也就是搜索商品后，见到商品那刻触发漏洞。  
  
对接受goodsid参数是否<1判断后进入取商品信息代码。  
  
跟进getNewBeeMallGoodsById方法，找到方法接口后再找接口实现类，再找方法：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EByU9WialvPkcg19gdO2YK1ITzQZRtw0NwUB6oicYoj2OgtqFDQalYGveA/640?wx_fmt=other&from=appmsg "null")  
  
发现goodsid参数传入selectByPrimaryKey方法。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EBXOzRhEqS7dScknHhKqtBaAyabQBkIOpCib0k81Fk9PcFEmQdNibsYXzg/640?wx_fmt=other&from=appmsg "null")  
  
该方法通过数据访问对象（DAO）goodMapper调用，且在方法最前处由NewBeeMallGoodsMapper对其定义：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EBXOzRhEqS7dScknHhKqtBaAyabQBkIOpCib0k81Fk9PcFEmQdNibsYXzg/640?wx_fmt=other&from=appmsg "null")  
  
全局搜索，找到对应xml文件：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EB4SZNZYTPvgVljDIIOsyxz0ibpNwicnUGQ4hkqE0z5iat4zkTD3IB2ic36g/640?wx_fmt=other&from=appmsg "null")  
  
发现通过id参数对数据库操作，取出goodsCoverImg与goodsCarousel参数。  
  
回到最先前的类：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EBYfxbZpMViaEKP0ZZcYlk7wiaCvqqmxq79UU6YB8RibyfeoqWYR5xd8XHA/640?wx_fmt=other&from=appmsg "null")  
  
此时goods对象已经获取商品相关参数值。  
  
再进入if判断商品是否上架，上架则进入下一轮代码，将商品信息封装为视图模型，找到NewBeeMallGoodsDetailVO类，发现只接受了goodsCoverImg参数，也就是先前抓包修改处只用修改该参数即可：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EBvZwG9HS9MEjh3RQOnwZo60h3lFrBnxq3ULJMib7dJ84M4iaZb1G11Zpg/640?wx_fmt=other&from=appmsg "null")  
  
最后返回视图名称"mall/detail"，表示渲染商品详情页面：  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/5znJiaZxqldy2uWGbPcW5QtPrqUujn9EB5ibs5PWWJXnlHPt2dRvEd9LvmJOPwRD4D8GPHqCfmchmeKvEt5By2sw/640?wx_fmt=other&from=appmsg "null")  
  
由于存储时未做任何过滤，进行视图层渲染时直接拿出goodsCoverImg参数放到前端，导致用户一旦访问商品便触发该漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/7QRTvkK2qC6iavic0tIJIoZCwKvUYnFFiaibgSm6mrFp1ZjAg4ITRicicuLN88YodIuqtF4DcUs9sruBa0bFLtX59lQQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
学习  
网安实战技能课程  
，戳  
“阅读原文”  
  
