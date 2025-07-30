#  SRC技巧分享：某高校未授权访问+XML文件上传引发的XSS   
原创 zangcc  Eureka安全   2025-01-21 09:29  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/7GhZKSNyIWW7hOPGVGAFdB0LicgBD9QCTEVRdLGXklRmwEsxuNVbR5ibwLzxicafIHsW1U9WpV0Mznib50aAn0mqSQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**点击上方**  
**蓝字**  
**关注我们**  
  
## 0x01 前言  
  
这是之前我在edusrc挖的一个小漏洞。如果是单纯的反射型xss，平台是不收录的，但是我这个xss属于是多个漏洞在一起的组合。当时本来是想打一个有证书的高校，但是最后才发现不对劲，这个名字跟我挖的这个实在是太像了，打歪了。。。  
  
文章末尾🔚有抽奖链接（有大家最爱的Java），依然是免费包邮～  
  
## 0x02 小程序入手  
  
当时我想的是，像这种被白帽子挖了那么多次的高校目标，如果不从tg入手进内部系统挖，想从外面挖到洞几乎是不太可能的，所以我就小程序试试。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNNpQNG4McHVz3YpERZfHDZPy3zS51lOwBScXp8icbZ4Aiawa00ZDY55LjrPbFNNibIXOQRVwmbnnutw/640?wx_fmt=png&from=appmsg "")  
  
点击进去后，提示微信授权登录，如果从这里点击授权是校验不通过的，因为我的微信没有绑定他们这个系统，所以进不去。  
  
但是这里有一个未授权访问漏洞，点击左上角的图标，也就是那个小房子的图标：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNNpQNG4McHVz3YpERZfHDZXexIIzkDVVGdchj14ibyEgdjd6G8Fuicxso18zrdK8FnM4WYBNpsYSVg/640?wx_fmt=png&from=appmsg "")  
  
然后就直接进来了…… 这也太轻松了，正当我开心的时候，又把我给“踢了出去”，如果没有授权登陆的用户会自动跳转返回刚刚主页。  
  
为了避开这个校验，我又试了一次，点进来之后，在没有跳转回主页之前，可以点击里面的任意功能，并且可以进行操作，这里我选择的是笑脸墙：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNNpQNG4McHVz3YpERZfHDZ1GUsm9WUb8vCATohicB0CypUibnF1uEmXXYkwApic3NHBiaxUJFLxIgcQg/640?wx_fmt=png&from=appmsg "")  
  
然后就进去看“校友们”的姓名-信息-照片了，并且不会再跳转回主页。最下面还有个相机的图标，点击。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNNpQNG4McHVz3YpERZfHDZ6RkdqAq1E5iaGUUWScqAQxo7pN0jPnVz39DPVECCVxLBZFARyrjmVFg/640?wx_fmt=png&from=appmsg "")  
  
随便拍一张照片后，就可以上传成功，burpsuite可以抓取到这个请求包。  
  
很多文件类型会被拦截掉，所以我搞了个文件后缀的字典fuzz了一下，发现除了正常的png jpg这种图片格式，只剩下一个xml可以上传（可能是开发把这个xml类型给漏了）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNNpQNG4McHVz3YpERZfHDZE31yq7v1zUYHl3qfHQA2ViasbKZYNSTtECIyoRwOJdpsno4qKiaDub8w/640?wx_fmt=png&from=appmsg "")  
  
## 0x03 xml-xss  
  
xml我当时能想到的就是要么就两种，命令执行或者xss，命令执行试过了不行，因为最终上传的地方是一个oss存储桶，不具备条件。xss payload：  
```
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
 <polygon id="triangle" points="20,0 0,50 50,0" fill="#009900" stroke="#004400"/>
 <svg onload='top["al"+"ert"](1);'>
 </svg>
```  
  
上传后成功返回完整路径，访问路径:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BictawU0A1NNNpQNG4McHVz3YpERZfHDZf2z7oibeQxk5yc9WhFNT6ZhWFmjpLDBf3tqxnGSpricP4NrQVGcfvibBQ/640?wx_fmt=png&from=appmsg "")  
  
虽然最终的xss并没有特别严重的危害性，但是前面的未授权访问确实是一个大问题。  
## 0x04 抽奖🎁 送书  
  
一：Java面向对象程序设计  
  
二：matlab数学建模从入门到精通  
  
抽奖条件  
：需要满足  
点赞  
或者  
推荐🩶  
二选一。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BictawU0A1NNNpQNG4McHVz3YpERZfHDZ0ZIeIrEbUUDAJXwSuj68N0xcsccTAFwlzNUHMgc2BI7sibNaWRxzTGA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
```
1.《Java面向对象程序设计：AI大模型给程序员插上翅膀》AI工具助力Java编程：故事引领思政，AI助力学习；任务驱动实践，项目提升能力。
2.马世拓，毕业于华中科技大学，具备丰富的数学建模竞赛经验，Datawhale成员。在B站开设并讲解的《数学建模导论》课程，已累计获得超过14万的播放量，其幽默风趣、深入浅出的教学风格深受学生喜爱和好评。曾指导学生参加美国大/中学生数学建模竞赛，斩获多项佳绩。
```  
  
说明：2025年1月27日开奖。由于春节将至，本轮奖品将在2025年2月7日返工后寄出。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GGOWG0fficjKzq4TFicia2yUjianoH80KtrWfiaAtUngV8rgLh0bIibv9SumD1Y9ZmphGxK9lKiakkOWDp2gRsLjZInPg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
更多 >>  技术分享  
  
欢迎大家关注EureKaSec，无论是技术交流还是有兴趣加入我们团队，都欢迎随时联络沟通。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CibE0jlnugbX5SLGI9312kOrkH7gXIN5NPic75bQ8WbAFMEqvZiaQ0WSk4W9eYUfJJRzlMgibjic8mIGicMvjialoDgmQ/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/BictawU0A1NM9WYO94RZib7HaaibSibMic91gPq8qbxL1jdjlslceibTEgJaLzvA1QVIkJ1sdaLJpYRzyw25hVIlxNkw/640?wx_fmt=jpeg "")  
  
如有问题  
  
联系作者      
  
EureKaSec  
  
  
点个“推荐”，挖洞必高危！  
  
人  
  
