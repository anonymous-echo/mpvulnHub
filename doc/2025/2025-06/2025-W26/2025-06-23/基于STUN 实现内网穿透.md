> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxMzIwNTY1OA==&mid=2247512548&idx=1&sn=1ee08b03dee432db19e4c77d3eb27a4a

#  基于STUN 实现内网穿透  
原创 大表哥吆  kali笔记   2025-06-23 04:40  
  
> 在前面的一篇文章中，我们讲到了在不采用公网服务器做端口映射下。如何将本地的电脑实现外网访问。具体可移步历史文章  
  
  
上述方案，虽然很简单，但是存在一个很大的缺点。就是访问比较慢，平均延时大于200ms  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatiaia3zKlwJgrB1g9yuibemT5NRWlqXfluqWJAFR85EkGLcw54n7Ib3w8uhDmHxd8AhlrdoE3RyaoOnQ/640?wx_fmt=png&from=appmsg "")  
  
因此，针对上面问题，我们推荐另外一款方案。
```
NAT
```

  
打洞。之前也写过相关文章。但是比较零碎。因此本文详细说明。  
  

```
Lucky
```

  
可以方便的实现动态域名(DDNS)、Stun内网穿透等。极大地方便用户操作。接下来，让我们来部署  
  
这里，我们通过一键安装脚本来实现。当然也可以直接Docker安装  

```
URL=&#34;http://release.66666.host&#34;; curl -o /tmp/install.sh &#34;$URL/install.sh&#34; && sh /tmp/install.sh &#34;$URL&#34;

```

  
![安装](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatiaia3zKlwJgrB1g9yuibemT5NyCBqnd8iaxgxiaXpaiaFIdW7aqrD3vwB4VgiboXzyFYD61dHxvnZBVJOdA/640?wx_fmt=png&from=appmsg "")  
  
安装  
  
![选择版本](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatiaia3zKlwJgrB1g9yuibemT5NknTo2Ce6v97iaDUEEticlR9gsL2pnoNC74S1lXg862z7opul2hK4epwg/640?wx_fmt=png&from=appmsg "")  
  
选择版本  
  
![安装目录](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatiaia3zKlwJgrB1g9yuibemT5NXlbhc0BoGoxTIRqt3Wc0N0f4tI7mR2OicamBVQyv8V6nSGr3mQRKCwQ/640?wx_fmt=png&from=appmsg "")  
  
安装目录  
  
![安装完成](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatiaia3zKlwJgrB1g9yuibemT5NRQTF45mVutoQBvCUGGtVuHC9vkXL9p6MZ14tUicQGqQObibo6pglTuhg/640?wx_fmt=png&from=appmsg "")  
  
安装完成  
  
登录 http://192.168.0.106:16601/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatiaia3zKlwJgrB1g9yuibemT5NLFn4j3Zsps7eJJmy7hosXW6ID0ff9icIEQJDwFMd7icdDf78UHusVFFA/640?wx_fmt=png&from=appmsg "")  
  
登录后，首页效果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatiaia3zKlwJgrB1g9yuibemT5NDocwWJIOiaFraPQZSEEK3EUK1JlpRrUWYiawMaXAGpkzw68YS1gZbfFA/640?wx_fmt=png&from=appmsg "")  
  
打洞测试。 这里，我们以本地80端口为例 首先，在本地启动Apache2,点击
```
STUN内网穿透
```

  
新增规则如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatiaia3zKlwJgrB1g9yuibemT5NIBVdU0RSQouibZs4O9dzQxLxtOBJcuWaZ3AScictpW7ia6FfTibWLKd3Nw/640?wx_fmt=png&from=appmsg "")  
  
穿透成功后，效果如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatiaia3zKlwJgrB1g9yuibemT5NpWQWcZFD2ySlVCu9kF3OtMZ0KxXVKrbxiccm5o3udB1BX00JPosM4XA/640?wx_fmt=png&from=appmsg "")  
  
接下来，我们访问
```
42.xx.xxx.xx:31091
```

  
便可以访问当前的ssh服务。  
  
但是，目前这种访问还是不方便，由于IP在不断的变化。因此，我们需要将其自动解析到自己的域名中。 点击配置域名，开始配置。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatiaia3zKlwJgrB1g9yuibemT5Nes7Zsh9ZfyiacdJxUsb7NEoE0O3tDunEkr1c5CugO6uZicoaA5qLl35A/640?wx_fmt=png&from=appmsg "")  
  
根据自己服务商不同，选择服务商，并填写ID  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatiaia3zKlwJgrB1g9yuibemT5Njq9pLOumKp6R8le43viclsk0DxcIBIe3cjdicf4FsVunQoOib8B3UeMiag/640?wx_fmt=png&from=appmsg "")  
  
完成后，效果如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Xb3L3wnAiatiaia3zKlwJgrB1g9yuibemT5NbOgFUnDQI7AxmibmC6up34u7O1otXfg2a1vQgL57c57Oy87UzqNfXBw/640?wx_fmt=png&from=appmsg "")  
  
这样，我们便可以通过域名访问+端口访问了。更多具体玩法，  
  
可以参考官方文档：https://lucky666.cn/docs/  
  
更多精彩文章 欢迎关注我们  
  
  
  
**BREAK AWAY**  
  
**往期推荐**  
  
**0****1**  
  
[一文读懂 NAT打洞及实践](https://mp.weixin.qq.com/s?__biz=MzkxMzIwNTY1OA==&mid=2247509492&idx=1&sn=7c78fc8066249b9e0e7c95d4a4769d35&scene=21#wechat_redirect)  
  
  
**0****2**  
  
[真正做到无公网IP实现远程访问本地业务](https://mp.weixin.qq.com/s?__biz=MzkxMzIwNTY1OA==&mid=2247512346&idx=1&sn=96f3cb3e92ac98de660c6eba8f2e1f2f&scene=21#wechat_redirect)  
  
  
**0****3**  
  
[通过“打洞”实现端口映射](https://mp.weixin.qq.com/s?__biz=MzkxMzIwNTY1OA==&mid=2247499529&idx=1&sn=81cb81d6d0c94b11822db72546f2572c&scene=21#wechat_redirect)  
  
  
