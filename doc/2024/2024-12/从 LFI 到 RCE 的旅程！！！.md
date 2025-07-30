#  从 LFI 到 RCE 的旅程！！！   
原创 菜狗  富贵安全   2024-11-30 12:15  
  
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
  
**END~**  
  
  
  
  
  
  
                                  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5ndKIU0bgZ4tmS8GBvtPG9d8vPSJtht97ticy8UJUiaLPicEgsObibkiafLiaPxPlZ9TBKgCML5sUyhX0kg/640?wx_fmt=png "")  
  
  
