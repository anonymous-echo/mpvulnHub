#  Src捡钱5，为什么大佬总能挖到你挖不到的漏洞（CORS）   
原创 山河  不止Security   2025-04-22 01:52  
  
**免责声明**  
  
本公众号不止Security旨在分享网络安全领域的相关知识和工具，仅限于学习和研究之用。由于传播、利用本公众号不止Security所提供的信息而造成的任何直接或者间接的后果及损失，由使用者承担全部法律及连带责任，公众号不止Security及作者不为此承担任何责任。如有侵权烦请告知，我们会立即删除并致歉，谢谢。**工具****安全性自测**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0sjvG0TycCocg7xnrRn8LwibKOXGlMKVhMS9PkX9d4OM5LPjV3I9xNqN848hAndX42M4BtiatzT9K5XsvoqE6QUw/640?wx_fmt=png&from=appmsg "")  
  
**PART**  
  
  
**01**  
  
**工具概述**  
  
  
为什么大佬总能挖到你挖不到的漏洞（我是只会乱按键盘的猴子，我也挖不到），因为大佬的知识面广，知识面决定攻击面，今天介绍一款辅助挖掘cors漏洞的burpsuite插件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0sjvG0TycCpMIta2O0iabOOP0giav5dfQkRpWQPhUYUgOJGxpcfxicxEJ48fXiba76KjDh7czwKqK4NIy4M93mu3SQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
还有一种情况就是不使用插件，直接在burpsuite的请求中添加一个测试cors漏洞的字段，每次访问网站时都会自动添加上这个请求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0sjvG0TycCpMIta2O0iabOOP0giav5dfQkfe08ibj3Rr92KsDzJxuyVh0QIJAibOfZTcHicN8JEEyiaCntVhv0AzobkA/640?wx_fmt=png&from=appmsg "")  
  
  
但是这种查看结果没有cors插件来得直观，还需要去历史记录里面筛选，还有就是加了这个字段会导致某些网站访问不了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0sjvG0TycCpMIta2O0iabOOP0giav5dfQkvHY110uDtxhuFzabXoFZRRtopRTe66KuCQNanwtctKo7LSVdsN8KyA/640?wx_fmt=png&from=appmsg "")  
  
  
**PART**  
  
  
**02**  
  
**工具下载**  
  
  
**关注名片进入公众号**  
  
**回复关键字【250422】获取下载链接**  
  
**PART**  
  
  
**03**  
  
**往期精彩**  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzU3OTYxNDY1NA==&mid=2247484600&idx=1&sn=90910a4676ed1ed1c0161d5ca5658254&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzU3OTYxNDY1NA==&mid=2247484980&idx=1&sn=9cf1b917da3aa3ea9a235b8efd330b13&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MzU3OTYxNDY1NA==&mid=2247485296&idx=1&sn=0a89e7ce6257537d371ad6cc201571bd&scene=21#wechat_redirect)  
  
  
