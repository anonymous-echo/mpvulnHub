#  从 LFI 到 RCE 的旅程！！！   
 Z2O安全攻防   2025-01-26 20:37  
  
**安全新闻**  
  
**从 LFI 到 RCE 的旅程！！！**  
  
  
  
今天开水了~别骂我  
  
  
作为一名漏洞赏金猎人，我认为最重要的是我们尝试或遵循的利用漏洞的方法，最终导致漏洞产生更大的影响，我在这里也采取了同样的方法。  
  
  
### 在搜索漏洞时，我在目标网站https://www.example.com/forum/attachment-serve?name=../../../../../../../../../../etc/shadow&path = 中发现了 LFI。如你所见，参数“name”容易受到 LFI 攻击。  
  
  
**一、上payload**  
  
  
  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5mdibkdxmdQaUsicxB4amCuokzt2d9ia4PuzADbM5VKxf45AxPbStV3SpcDowr5y8Vrq5tJAbXfjtf5Q/640?wx_fmt=png&from=appmsg "")  
###   
  
  
  
  
我确认 LFI 确实存在，所以现在我的目标是升级它以获取 RCE。现在的想法是访问某些文件，可能是日志文件，它可以提供一些用户控制器输入（以便运行某些命令）。  
  
因此我尝试读取访问日志、错误日志以及不同的位置来访问它们。  
  
**二、爆破的艺术**  
  
  
  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5mdibkdxmdQaUsicxB4amCuokGLp9e7TjzBwInUj5u2L0GnehtLqJcB8GdibVr2U7noM3a5Vps07IiawQ/640?wx_fmt=png&from=appmsg "")  
###   
  
  
  
  
但似乎我获得 LFI 的用户无权访问日志文件。我读了一点资料并做了一些研究，然后才知道“/proc/self/fd”提供了访问日志和其他各种系统相关文件的符号快捷方式。所以我尝试阅读这些内容以寻找访问日志   
  
**三、看response**  
  
  
  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5mdibkdxmdQaUsicxB4amCuokspmibibnHj74iahZZewql6I4ib2iaeAIrTppdDxT2cM9CfwicncUuryjWv2w/640?wx_fmt=png&from=appmsg "")  
  
  
  
###   
  
  
  
  
然后我在 /proc/self/fd/{number} 上运行入侵者，其中一个 fd 文件允许我访问访问日志   
  
**四、当猴子看日志**  
  
  
  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5mdibkdxmdQaUsicxB4amCuokPh7L4FXORyhSkrn6FibVaZ1gHyx2eWVAhflpn4krex6ZwqQ832cE8JA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
这里引起我注意的是“referer”标头，因为我知道它是用户控制输入的内容。是时候执行一些命令了。我在 HTTP 请求中添加了“referer”标头，将其值设置为 system(id) 并转发它  
  
**五、ID**  
  
  
  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5mdibkdxmdQaUsicxB4amCuokFgtSx5NjX8V6v1VicIziaicp6jAicnxKicK6CDrdNw1jlvCXw00uJibu2U5A/640?wx_fmt=png&from=appmsg "")  
###   
  
  
  
  
并得到了愉快的回应:)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5mdibkdxmdQaUsicxB4amCuokJoTbGwjz0RIjST9RoOM2RicR6BElogaXibiaWHicx0wE3iccyAEkb7gs64w/640?wx_fmt=png&from=appmsg "")  
###   
###   
  
  
  
  
  
  
  
   这就是我如何从本地文件包含（LFI）获取远程代码执行（RCE）的方法！  
  
建立了一个  
src专项圈子，内容包含**src漏洞知识库**、**src挖掘技巧**、**src视频教程**等，一起学习赚赏金技巧，以及专属微信群一起挖洞  
  
圈子专注于更新src相关：  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、小群一起挖洞
```  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg41LkR0ezBlmjJY4Lwgg8mr1A5efwqe0yGE9KTQwLPJTe9zyv3wgYnhA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOXg868PqXyjsACp9LhuEeyfB2kTZVOt5Pz48txg7ueRUvDdeefTNKdg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCPFgbmiaJ4ibf4LRgafQDdYodOgakdpbU1H6XfFQCL81VTudGBv2WniaDA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuY6DfYOuUzWiaPBBq4L5bV9ZRMpUcFktl9oiazJicibKEVwZoWo5dEaXGHIoa6yOEkfnicbMibJDALxuk1w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4Bd1oBmTkA5xlNwZM5fLghYeibMBttWrf57h8sU7xDyTe5udCNicuHo8w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYrUoo5XZpxN9Inq87ic71D6aUeMdaWrKXgYYia2On8nMA7bqWDySa8odAq1a0kkp3WFgf0Zp0Eut0A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4KKlic4yiafWTpLdejicQe3MllEQc24ypeI3anaK7IjJDVyq1WVQN2yKBA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOHgjJxnq1ibibJgVUx3LwCjZj62vygx8w6rxia1icmIWiax2YlP6S6LmlmlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOApVm8H605qOibxia5DqPHfbWD6lmcweDjGv4DLl45waD068ugw2Iv2vg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuY813zmiaXibeTuHFXd8WtJAOwldaSATYOh1WQpk1qz15rLxehOAn4aK7tdbSyNEuHDZpIISCtl6Q8w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4jFsKRMMNDKbsAZhscCiagnyJScMVmFUqMtae5omlLRdu095mywWszjQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuaRqDOYRFjU73rIsVy2ISg4uGJ2SA5BhZ3UyibZvVmcP3sozQEOfVr0jftWpC3YkpDiaAicS1ib3EgXHA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
