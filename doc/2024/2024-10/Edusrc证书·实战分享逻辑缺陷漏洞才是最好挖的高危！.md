#  Edusrc证书·实战分享|逻辑缺陷漏洞才是最好挖的高危！   
原创 zangcc  Eureka安全   2024-10-21 23:09  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/7GhZKSNyIWW7hOPGVGAFdB0LicgBD9QCTEVRdLGXklRmwEsxuNVbR5ibwLzxicafIHsW1U9WpV0Mznib50aAn0mqSQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**点击上方**  
**蓝字**  
**关注我们**  
  
## 0x01 前言  
  
网络攻与防的技术迭代很快，曾经经典的sql注入，xss之类的漏洞变得越来越少，从前年开始，我就对逻辑缺陷类漏洞非常着迷，因为它总能给我制造惊喜，像是水平/垂直越权，业务逻辑缺陷(账户余额,积分,打卡等绕过)这种反而是我最擅长的技术手段之一；也靠逻辑缺陷漏洞挖到海康威视的CNVD证书。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNdR5rL6OmeVv4FL0eY8qWvDgVJxQJaZ82UcF0M9jVRTJK5UkqU9NCbGmibzyhbNteZibHIA5cGcvMw/640?wx_fmt=png&from=appmsg "")  
  
因为我从事网安行业一坤多年🐔以来，从来没有挖到过edusrc的证书站，对这种我没有的证书，总是心有不甘，所以在某个神秘的周六，我开始了我的edusrc漏洞挖掘。  
  
💡：  
下面是正文部分。**文末小程序抽奖送书**，  
将随机抽出一名幸运儿获得149💰-《Frida Android SO逆向深入实践》一本！  
  
## 0x02 锁定目标+信息收集  
```
https://src.sjtu.edu.cn/gift/
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNdR5rL6OmeVv4FL0eY8qWvhT7c5kTib3nibgldPo4aHmOiaJRKqFWrnjjicm3icAO1xpI8M2sicwkPNVIw/640?wx_fmt=png&from=appmsg "")  
  
挑一个喜欢的，就可以开挖了。我随便点了一个喜欢的颜色，有了目标之后就开始对它信息收集，先百度学校名字，然后进官网看一圈。只找到一个统一身份认证平台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNdR5rL6OmeVv4FL0eY8qWvLI0pHbNITpia3loibjKCncMARSY7nhLc7Srqia7rkRfKVlVt7wajKNcCg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNdR5rL6OmeVv4FL0eY8qWvpibpvwvcGfrkjhN25tAUe75jkmsYnibwrjs54NGEg5PeSPwxon7mjhSA/640?wx_fmt=png&from=appmsg "")  
  
  
有使用说明和初始密码的提示，初步知道了这个系统的大致账号规律，账号是学生的学号，初始密码是身份证后6位，所以接下来的渗透思路就是找到学生的学号和ta的身份证。学号这个很好找，直接官网搜索🔍关键字“学号”，出来一大堆。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNdR5rL6OmeVv4FL0eY8qWvpSkjjFRMugCaCoTDAYB8ZgAibngKMHUzrvxwtUicvicyLyQUZa93JibPsA/640?wx_fmt=png&from=appmsg "")  
  
随意挑选一位学生：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNdR5rL6OmeVv4FL0eY8qWvXPxQ7RND3Ta5WxEibmU88zG3UscuGD1iaeoCLVDMV9klEExERu6SicWFg/640?wx_fmt=png&from=appmsg "")  
  
这里有个技巧，就是找一些名字比较小众的，姓氏小众，名字越稀有越好，如果是大众姓+大众名，那排查起来就会很困难，因为数据量太大了。社工库，搞安全的都知道，这里我就不废话了。  
  
在国内，我们的信息基本上都是裸奔。这里就是所谓的运气部分，如果运气好，没有重置密码，正好匹配后6位，那么一下子就能中。我就是运气属于不那么好的那种，试了后6位还是不行，正好系统有一个申诉功能，只需要填写完整的SFZ号和姓名加学号，就能申请一个新的账号，本来想截图复现一下，结果今天登上去看的时候，已经把这个功能给取消了。。。（修复速度真的效率👍🏻）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNdR5rL6OmeVv4FL0eY8qWvHx9bIQibLZKD2NCUrL2wdB6B7JHWibn8q1mxx7x6D6V5KCdGLEZJs00w/640?wx_fmt=png&from=appmsg "")  
  
## 0x03 逻辑缺陷-水平越权高危漏洞  
  
当前期的信息收集工作全部准备好之后，就可以登录到这个系统，开始进一步的挖掘系统业务相关的漏洞了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNdR5rL6OmeVv4FL0eY8qWvB0kiaazTcD40TibvOibaPsGdhicviaK0PUmuibn63e5urApibgDbPOXRIcszw/640?wx_fmt=png&from=appmsg "")  
  
访问里面的智慧学工系统，返回的是学生个人信息，里面的内容非常多，包括学生基本信息、家庭信息、交学费的银行卡信息、SFZ号码、手机号码、班级专业、文化成绩、宿舍信息等等，因为数据太多，我放截图的话打码不方便，所以这里就干脆不放截图了。用Burpsuite抓取这个页面的请求和响应数据包，发现有以下**两个请求**：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNdR5rL6OmeVv4FL0eY8qWv4z6RhtgD7BRs3QIOh7M0cibSurhWYRWP4kwBoXHtv8nGtyEGPOOGdCg/640?wx_fmt=png&from=appmsg "")  
  
首先是这个  
xxx/query接口，返回的就是上述说的学生的所有信息，非常的全。改变参数id，响应会报错，所以这个接口是肯定会校验参数id，但是这里的id是加密后的字符，普通白帽子看到这里可能就会放弃了，但是这里的加密就是个纸老虎，只需要将这个加密后的值放到Burpsuite中进行全局搜索，就会找到这个id值的来源。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNdR5rL6OmeVv4FL0eY8qWv5qCJfjQlYMsQfqgicRViaVnSywtIs2bwfCmxicuLLo1kquGzuKPBMQRQg/640?wx_fmt=png&from=appmsg "")  
  
如上图，  
/lxxs/api/xxx接口中的参数就是学生的学号，响应中的xsid的值正好跟第一个接口中的id值完全相同，这下思路就豁然开朗了。  
  
这里业务处理的顺序是先通过学号来获取xsid，然后这里的xsid当做第二个请求的参数id进行查询，然后返回这个学号所对应的学生的所有信息。  
  
因此，只需重放或者爆破：  
/lxxs/api/xxxx接口，将学号进行遍历，就可以得到对应的xsid（也就是  
xxx/query接口的id值）  
**查看全校任意同学的个人敏感信息**（包括学生姓名、学号、班级、SFZ号、家庭通讯信息、银行卡、文化成绩、学业情况等）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNdR5rL6OmeVv4FL0eY8qWvCo4OmFb5fAhwrib2PfibxgPkqmpyQc9E0aO0UIWONKxgY8Dd4vokhkhg/640?wx_fmt=png&from=appmsg "")  
  
一次完美的水平越权，最后也是轻松拿下高危+兑换证书。目前漏洞已经修复。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNdR5rL6OmeVv4FL0eY8qWvLDWytAu6QDzBQ2KvDzdE1u9fs6RdCuKZAhloicLqEHswMQicfHMibhXFQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNdR5rL6OmeVv4FL0eY8qWvEP6ZGNfbgwmG7OicP6Unl1dH66k11uKVbweruVpLo7gY7uMTOD0zeibQ/640?wx_fmt=png&from=appmsg "")  
  
  
## 0x04 《Frida Android SO逆向深入实践》🎁  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNdR5rL6OmeVv4FL0eY8qWvJ84vTIhNlaXwcZn44cJAgv5ibmS8KfqwG07hIe4LBnS4XMY1EsryrLA/640?wx_fmt=png&from=appmsg "")  
  
《Frida Android SO逆向深入实践》的讲解方式由易到难、由浅入深，适合Native层的初、中级读者阅读。无论您是对逆向工程感兴趣的初学者，还是有一定经验的开发者，本书都将为您提供全新的视角和实用的技巧，助力您在逆向工程领域取得更大的突破。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNdR5rL6OmeVv4FL0eY8qWvjmlpzy6pUfWgI2e7HkU56UefBCzQ51OtNrUzPdjVzsscTkNON5GTYw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWfiaAtUngV8rgLh0bIibv9SumD1Y9ZmphGxK9lKiakkOWDp2gRsLjZInPg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
更多 >>  技术分享  
  
欢迎大家关注EureKaSec，无论是技术交流还是有兴趣加入我们团队，都欢迎随时联络沟通。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CibE0jlnugbX5SLGI9312kOrkH7gXIN5NPic75bQ8WbAFMEqvZiaQ0WSk4W9eYUfJJRzlMgibjic8mIGicMvjialoDgmQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BictawU0A1NM9WYO94RZib7HaaibSibMic91gPq8qbxL1jdjlslceibTEgJaLzvA1QVIkJ1sdaLJpYRzyw25hVIlxNkw/640?wx_fmt=jpeg "")  
  
如有问题  
  
联系作者      
  
EureKaSec  
  
点个“在看”，挖洞必高危！  
  
  
人划  
  
