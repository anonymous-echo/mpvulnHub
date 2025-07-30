#  e0e1-wx 2.0版本更新以及关于POC项目和开源的一些想法   
 sec0nd安全   2025-04-26 13:52  
  
## 介绍  
### e0e1-wx项目  
  
主要就是关于e0e1-wx的更新，闲了1年也是良心发现给他更新更新了，直接跳到2.0阶段主要是将所有都进行本地化了算是一个新的开始了，一开始主要是也为了分享一个思路，但是没想到这么多人喜欢用。  
### POC项目  
  
然后就是eeeeeeeeee-code/POC这个项目，以后也不会**更新未公开的poc**  
，因为被人家**厂商**  
找上门了，这边也进行删除了，以后为了避免项目以及我们自己安全出现问题，这边的话，以后只会公开一些已经被公开的poc利用了，人家厂商也是挺好的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdwbHiav8b24KogahVntlGG0rWOQrPJYaL0X6PibEurH76xKC0bB25wnjjkRiaPLibkZic9dZVS9iamLCovw/640?wx_fmt=png&from=appmsg "null")  
### 开源的想法  
  
然后就是做到现在 开源的一些想法吧，收入方面的话：  
  
1. github赞赏总计：2 元  
  
2. 群友赞赏总计：159 元  
  
3. 文章收入总计：87 元  
  
4. 文章赞赏总计：20 元  
  
几个月不到300块，哈哈哈确实挺苦的，不过也有好处的，一方面可以作为一个简历使用，也可以为我们提升一个名气可能后面可以帮助自己做一些项目的转化之类，不过呢确实没什么收入，后面有时间的话可能会做一些免杀、二开之类的工具搞个星球，看看能不能多搞点收入，毕竟自己都活不够了，谁还去搞开源。  
  
然后就是开源真的来说是一个可以很好提升兴趣的地方，给你优化的动力，每一个star就是跟激励一样，当你到达一定程度的时候，就会有一些紧迫感，可以帮助自己挺好的进步，以后可能还会搞一些项目的开源。  
  
然后就是关于e0e1-config，这是我搞的一个后渗透方面的杂烩，大家可以加入群聊多给点建议，我自己认识到的一些问题就是有功能不够完善、体积有点偏大，后续肯定也是会进行优化的。  
## e0e1-wx 2.0介绍  
  
1.  
去除外部工具调用，所有功能本地化实现方便后续添加功能 (如：hook 云函数之类的)  
2.  
去除请求功能（作用不大）  
3.  
添加微信 sessionkey、iv解密加密功能，可能一些小程序还在用，遇到可能就是任意用户的登录了  
## e0e1-wx 添加失败的功能  
  
1.  
想模仿proxifier做一个小程序自动转发流量代理，但是有一些问题注入一直有点问题，等我在研究研究吧  
2.  
4.0 hook注入的问题，微信4是新出的hook方面是有一些问题的，还在尝试中~~、  
3.   想添加mac自动化支持，因为没有mac，所以只停在想象区间  
## e0e1-wx 最新功能页面展示  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdwbHiav8b24KogahVntlGG0rJ6MkER43JnJNIAQbsDYtKxkFVpqzvYomtWLpv25lyq67AkEzBvndXA/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdwbHiav8b24KogahVntlGG0ru4WbIzjBFuibIWLqM8ms00HQtIO5BUzMwNESMFJLr40CQlnpdMicpWIA/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bfMXBp6QpdwbHiav8b24KogahVntlGG0rVMMJMXoVONPZNJhQ9W61DPMy0xg2QnJcNqiaLIPNEolCVQkQgO6NJYg/640?wx_fmt=png&from=appmsg "null")  
  
  
