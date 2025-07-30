#  【漏洞分享】泛微OA漏洞 任意文件读取 OA E-Cology ln.FileDownload 任意文件读取   
 Undoubted Security   2024-11-25 08:00  
  
前言  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnKVibeL72YzLH79T4AjdRH13DzX1avCNqbSeU0Xb1nicv59X6oLLh7kDFEvYM8xzc2FNaTyUeuPNejw/640?wx_fmt=png "")  
  
声明：本文仅供学习参考使用，如若造成其他不良影响，均与本公众号无关！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnKKVhibmmQYk6h7BJniaX1Pkr9ic8Xw9Fu6W3ObsRKIxiaOQ698AxA5OUUiaHO2DZlBAlpjibzKAuNMEYmw/640?wx_fmt=png&from=appmsg "")  
  
漏洞复现  
‍  
‍  
‍  
‍  
‍  
  
fofa查询语句：  
```
fofa：app="泛微-OA（e-cology）"
```  
  
‍  
‍利用脚本进行检测：  
‍  
‍  
‍  
‍  
‍  
  
‍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnLU4EQXMHjLaHYCRU151nz5iaZD1hdn8CUiaAPZgpPvGLFsDwLgh4hPrWn2TVknpxTicLk3qFQZTvcVA/640?wx_fmt=png&from=appmsg "")  
  
手工复现：  
  
‍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnLU4EQXMHjLaHYCRU151nz5iaUya2iad4dXmFwD6YfNBTwIzG5hw84ha9okG1HGa7ibyQ1OKK0YtyXKQ/640?wx_fmt=png&from=appmsg "")  
  
后台发送  
20241125  
，  
  
右下角点击  
点赞、在看  
，  
获取POC及批量检测脚本  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnLU4EQXMHjLaHYCRU151nz59ea8V4ezw8owmvd4eHJJezUCsmxUK05w4avXqjH0ETeJSO5ydD63eA/640?wx_fmt=png&from=appmsg "")  
  
  
关注不迷路  
‍  
‍  
‍  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnLC22Wa3B8Lb3AkPOhcfqzORXBdEyiajPX2GJd1patuUzlhgOZia7X11licPvQvJviakdHTDt0NWxjicOw/640?wx_fmt=png&from=appmsg "")  
  
关注本微信公众号，点击下方微信群，扫码加好友，备注“微信群”，拉你进交流群，后面会在群里抽奖！群里会不定期给大家分享国内外高危严重小技巧  
‍  
‍  
‍  
‍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnKbC2ETLKh1mlITyPdJX8ESLkEQSGHGmvkt50WtyE0TiaTZvw9XQxB1vZGA0CaLhxV7yfXiaR2fJznA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DLnxHnM3icnKbC2ETLKh1mlITyPdJX8ESLV1l8YTTFX7UGNEfVj6Vro8R9IZ0tGWZ6c2iae63xyutfY8gKr8JqiaQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnImqlUjcJo52mlnG45ZdOjgL1WSJlwNlgLkMosQnqib0eJJCQpibhGnlBNI8pP0lbicnk1sv5TiaQQvMQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnImqlUjcJo52mlnG45ZdOjgDqZmZibia8anIziaID45XULyF2Xr7ebeDbnicK0FyicribzcMibeCG7g9tyaQ/640?wx_fmt=png "")  
  
  
**【Nday】知识星球介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnKnOBpBfWhj6WcA84aJtLGfbUEM2lhs30v4Aw4UP4RydILxkkxibTTweNQYVC0wa6TD1omtTt49utA/640?wx_fmt=png&from=appmsg "")  
  
```
为什么要做nday这一块内容呢？  
   在打攻防、挖src、做渗透测试的时候，总会碰到很多产品、中间件、cms、产商等等系统/设备/网站，这种时候可以先进nday刷一波。通常nday的危害都是比较大的，在src、项目渗透测试里面一般是都会收的，大部分nday在打攻防的时候也是收的。这也就是为什么我想汇总一下nday的原因之一
外面也有很多nday文章，为什么这里还要写汇总呢？
   原因其实很简单，外面的nday都比较零散，有时候搜索都是五花八门的，不容易找到想要的。还有些nday库不更新，或者更新慢，给大家带来的体验都是很差的（我也有这种感觉），这也就是为什么我想汇总一下nday的原因之二。
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DLnxHnM3icnKnOBpBfWhj6WcA84aJtLGf4UtFl3qMwg7LFksnLNnfmF6pMUp3yxZsia3iaWxOIM0IuP4yP5LFYibVw/640?wx_fmt=jpeg&from=appmsg "")  
  
或者在微信公众号后台点击微信群，添加微信，备注来意（微信群），加入交流群参与后续的抽奖活动免费进入知识星球。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DLnxHnM3icnLC22Wa3B8Lb3AkPOhcfqzOgPVvZS2m3yFq0p9LSPmyFxlyEYVJQibItTiaWNiakooek4s6dV5tZCDEQ/640?wx_fmt=png&from=appmsg "")  
  
  
**END**  
  
  
  
  
  
  
  
  
