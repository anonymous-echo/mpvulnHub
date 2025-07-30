#  使用Markdown RCE服务器   
Aditya Dixit  七芒星实验室   2024-06-10 14:17  
  
#### 背景介绍  
  
Hashnode是一个面向开发人员的博客平台，您可以在其中使用自定义域免费托管您的博客，其中包含许多功能，而这其中一项功能便是"批量Markdown导入器"，当我将我的博客从Jekyll迁移到Hashnode时，我正在寻找一个导入功能，幸运的是Hashnode有一个markdown导入器，允许批量导入markdown帖子，但需要采用某种特定格式，出于某种原因我在导入帖子时不断出错，由于UI上没有描述性错误，导致我无法弄清楚原因，然后我查看了我的Burp中的响应，就在那时我注意到了一个Bug  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickmHib6UxBpqXC8IbibIn1wGVOsqv8h2ANdSpbLYYiaSXc2OfrvibgyaY1uia0Rn6DSUA7KFciaKoV3zbFA/640?wx_fmt=png "")  
#### 漏洞利用  
##### 寻找 LFI  
  
Markdown有自己的怪癖和功能，允许在文件中引用图像，要在博客文章或任何MD文件中包含图像可以使用以下语法：  
```
![image.png](https://image.url/image_file.png)
```  
  
Hashnode的Bulk Importer接受一个包含所有要发布的Markdown帖子的ZIP文件，这是他们的示例帖子格式的外观：  
```
---
title: "Why I use Hashnode"
date: "2020-02-20T22:37:25.509Z"
slug: "why-i-use-hashnode"
image: "Insert Image URL Here"
---

Lorem ipsum dolor sit amet
```  
  
需要将此.md文件压缩到存档中才能上传到平台，这是响应在Burp Suite中的样子  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickmHib6UxBpqXC8IbibIn1wGVEKMKSP0MFtjuc5xtAtsloZUsKdQ1gzTtu8ibCxyz7AXZgkbXP5AAp2g/640?wx_fmt=png "")  
  
这只是一个正常的Markdown解析帖子格式，这让我们想知道Markdown功能允许用户通过指定路径来插入图像  
```
![anotherimage.png](/images/blog.jpg)
```  
  
在Burp Suite中观察时，发现Hashnode触发了一个ENOENT错误，指出它无法找到该文件，如下面的屏幕截图所示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickmHib6UxBpqXC8IbibIn1wGVE84QgEnIJ8g72fq775xhsMniaib0eUJoJ9OlmK5t4uYthjz6SAyPFUyg/640?wx_fmt=png "")  
  
为了从服务器获取内部文件，我们决定给出一个实际文件的位置，而不是一个不存在的路径，就像/etc/passwd希望它能在响应中给我们文件内容一样，下面是我们用作最终有效负载的Markdown文件：  
```
---
title: "Why I use Hashnode"
date: "2020-02-20T22:37:25.509Z"
slug: "why-i-use-hashnode"
image: "Insert Image URL Here"
---

![notimage.png](../../../../../etc/passwd)
```  
  
这一次应用程序尝试使用路径中指定的位置来获取图像，而不是直接使用Markdown正文中显示的图像，应用程序遍历目录并passwd为我们获取文件，但它没有将内容显示在响应中而是将文件上传到Hashnode CDN  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickmHib6UxBpqXC8IbibIn1wGV0Yzw3KElKgq1YYjaqcCX0x36z0SzlFAFFAF0CwAibNicB9Qz0gy3leJA/640?wx_fmt=png "")  
  
contentMarkdown参数为CDN URL提供了上传内部文件的路径，我们能够直接下载/etc/passwd，由于我们已经从passwd文件中获得了用户的名称和他们的主目录的路径，因此我们考虑将其升级为进一步尝试RCE，之后计划去创建SSH密钥，它会存储在~/.ssh/id_rsa私有密钥和~/.ssh/id_rsa.pub公共密钥的默认位置，我们相应地修改了我们的有效负载以从服务器获取私钥并且很幸运它也被上传到CDN，现在我们进入服务器所需要做的就是找到IP地址，因为它隐藏在Cloudflare后面  
```
![notimage.png](../../../../../home/username/.ssh/id_rsa)
```  
##### 寻找真IP  
  
寻找历史DNS记录以找到IP地址但没有成功，之后查看文件/proc/net/tcp，发现这些/proc接口提供有关当前活动TCP连接的信息：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickmHib6UxBpqXC8IbibIn1wGV9ag9BeOA51Oxds2ia8sW0DoQibYKzAiaI4AicGXHh9ZMNVbkH9UM9F7Zmg/640?wx_fmt=png "")  
  
kernel.org文档很好地解释了该表  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickmHib6UxBpqXC8IbibIn1wGVk3Ko75cjNNs1JgO8gqlMR1UZCzFaVBtaeRicWIiaxjnibFP2xUxSgqia2w/640?wx_fmt=png "")  
  
我们感兴趣的列是本地地址，这些地址存储为反向IP地址的十进制表示法的十六进制值，这是我在互联网上找到的一个漂亮的单行代码，可以完成所有工作并以人类可读的格式返回IP  
```
grep -v "rem_address" /proc/net/tcp | awk  '{x=strtonum("0x"substr($2,index($2,":")-2,2)); for (i=5; i>0; i-=2) x = x"."strtonum("0x"substr($2,i,2))}{print x":"strtonum("0x"substr($2,index($2,":")+1,4))}'
```  
  
这有效地为我们提供了我们正在寻找的东西-服务器的IP地址以及端口22  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUickmHib6UxBpqXC8IbibIn1wGVsWXjnO8d89sZXWouPjgorwUOyLjUho2MVmSnvff5nqVVXgjEvRFVbw/640?wx_fmt=png "")  
#### 文末小结  
  
谁会想到Markdown解析器可以导致服务器上的命令执行呢？当与其他漏洞链接时，即使是最小的低严重性问题也可能升级，在这里描述性堆栈跟踪中的一个简单信息泄露错误帮助我们找出了markdown解析器的行为，这反过来又允许我们从服务器获取内部文件  
  
