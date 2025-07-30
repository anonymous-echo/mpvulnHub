> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIxMTg1ODAwNw==&mid=2247500966&idx=1&sn=88491b4e0826eff5e55d75c27ea04ec3

#  微信出了XSS漏洞？？？点击自动发送消息  
安全透视镜  网络安全透视镜   2025-07-13 06:44  
  
下午群里看到一个有意思的超链接  
  
payload如下  

```
<a href=&#34;weixin://bizmsgmenu?msgmenucontent=爸爸&msgmenuid=960&#34;>点我看搞笑视频</a>
```

  
将payload发送到群里，或者好友，对方点击后，会自动发送消息给payload发送者  
  
经过测试，并不是所有人都能看到超链接，很多人可直接看到源码。应该是和微信版本，以及手机系统有关系。  
  
  
需要注意的是有些复制粘贴到对话框后，有些手机微信 源码标签后面会多一个空格，需要删除。 不然源码会显示出来  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS6AeicPnfKe896GVZaOyfeuIJ8icIBAtOQk0GafwY381ZAnDP31xlplVsbibT4TdkjZyV8T29ibfeY0MQ/640?wx_fmt=png&from=appmsg "")  
  
视频演示如下：  
  
  
  
  
  
