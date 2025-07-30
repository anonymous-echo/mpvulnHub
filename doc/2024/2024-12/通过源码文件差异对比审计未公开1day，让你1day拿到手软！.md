#  通过源码文件差异对比审计未公开1day，让你1day拿到手软！   
道一安全  朱厌安全   2024-12-26 02:54  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWjKYvoSviaiaDUIGf1pH9H1bpSJRC3lIk08f5m6yibtkLDhFQwmCXicNMLFniaRrN0Xqvth9XWMQkn5bGQ/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgJHGxRSfVlI02pBf15B0slPyoWRWfSP0mM3LqDQKhOhVwfvVKma68JRwQ7E2Oysib3Nsw5ny7uaSw/640?wx_fmt=gif "")  
  
**免责声明**  
  
技术文章仅供参考，此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgJHGxRSfVlI02pBf15B0slPyoWRWfSP0mM3LqDQKhOhVwfvVKma68JRwQ7E2Oysib3Nsw5ny7uaSw/640?wx_fmt=gif "")  
  
**前言**  
  
有些开源程序在更新日志里会写更新了XXX漏洞，但是互联网上还没有人公开这个漏洞代码，可以用本文的方法去审计出未公开的1day。  
  
代码差异对比工具：WinMerge  
  
下载地址：https://winmerge.org/downloads/?lang=en  
  
不想安装的师傅可以下载.exe.zip 这个是绿色版免安装  
  
工具界面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WAyrRuvrubEP3ghYxTs22clmXnsHzDEeicHL3qgrtC5Ly6qnmqEeVntK3wShsx3yv06E2xkdPiajNBsq1cSuicY2A/640?wx_fmt=png "")  
  
目标CMS：wuzhicms-4.0.0和wuzhicms-4.1.0  
  
下载地址：  
  
https://github.com/wuzhicms/wuzhicms/releases/tag/v4.1.0  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgJHGxRSfVlI02pBf15B0slPyoWRWfSP0mM3LqDQKhOhVwfvVKma68JRwQ7E2Oysib3Nsw5ny7uaSw/640?wx_fmt=gif "")  
  
**代码审计**  
  
先看一下4.1.0版本的更新日志，下面修复了一处任意文件下载漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WAyrRuvrubEP3ghYxTs22clmXnsHzDEe0iaoXoNic5ZtIH2rIYmAg8ofBzTAibfTqjHmk9nj7L5HskuQicDUrwJXqw/640?wx_fmt=png "")  
  
然后讲4.1.0和上一个版本的代码都下载下来  
  
下载地址：  
  
https://github.com/wuzhicms/wuzhicms/releases/tag/v4.1.0  
  
https://github.com/wuzhicms/wuzhicms/releases/tag/v4.0.0  
  
  
下载下来解压之后，用winmerge工具打开两个版本的代码根目录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WAyrRuvrubEP3ghYxTs22clmXnsHzDEeJIVmkJqltTzVubxZUwvjftok8Q6fzOfUrg8wYkFRoUyxk4ia7WaT1aw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WAyrRuvrubEP3ghYxTs22clmXnsHzDEe9kIibQQsnd8d5SQgLBCVfFjtXMwVzic3Ng6iboxUPziaTYwKcicwXzpgBzQ/640?wx_fmt=png "")  
  
然后点击比较，稍等几秒比较完成之后，深黄色背景标记的目录文件就是做了修改的地方。  
  
他的这个过滤器也是非常好用， 可以点击选择，新建一个过滤器，将这些静态文件全部过滤掉。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WAyrRuvrubEP3ghYxTs22clmXnsHzDEeua3DHoUvciax5WLa8LbkaCibAmHKtgY5cOkfAjeQOkaatiaNclTmVFabQ/640?wx_fmt=png "")  
  
比较完成后是这个样子的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WAyrRuvrubEP3ghYxTs22clmXnsHzDEeevQdadz3a3kkmEiayMjpLYCukgc2OqEl9Zbicf3ibv6FfUp0lboEwTlTg/640?wx_fmt=png "")  
  
然后点开文件夹会提示文件不同  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WAyrRuvrubEP3ghYxTs22clmXnsHzDEe67UTderLff9tVsaLmTP7xtaLWo9XDCv2xlb3s6VkKxgvQm64icoCQZg/640?wx_fmt=png "")  
  
  
上面这个标签这里可以来回切换文件  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WAyrRuvrubEP3ghYxTs22clmXnsHzDEe8so6ykKla4aXMyLtP2ZQRKpgGiaufnfdGvyYt6pkrtdQQczFmibbgC9Q/640?wx_fmt=png "")  
  
最终一个个文件翻看在  文件中看到了增加.../和文件名后缀的限制  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WAyrRuvrubEP3ghYxTs22clmXnsHzDEetdV6LiaoARFiaB0icwGHjMrlsPvd8J3jibibhjXPQSno0eSpQI5ByEhmUFw/640?wx_fmt=png "")  
  
  
还有一个方法也可以通过对比文件差异来审计Nday  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WAyrRuvrubEP3ghYxTs22clmXnsHzDEeurwKHPDsHgYOfCRTohwrP8sLAQ00W6syfceULX2ibO6bBt9p3NAwaIQ/640?wx_fmt=png "")  
  
选择好对比的版本后，然后选择更新记录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WAyrRuvrubEP3ghYxTs22clmXnsHzDEeh9fjoYeX39zA3n87MJmmIkEcsqvibbYphDH8P8AOWqOmLBg37Lgb7YA/640?wx_fmt=png "")  
  
进去之后点击split按钮，就可以对照了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WAyrRuvrubEP3ghYxTs22clmXnsHzDEecnuGHZqshW5PgeKT4tcAicoly3ziauyCnMIGwbtfBL8AW4wibJM2bxDrA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWiaHpokNh4uWxia9Vv2eYjfzjK9Euejia8GQQAicPWkJI7HfpDplIlc3tPr73ZYKHIdg9kIHpWaJia2tGA/640?wx_fmt=gif "")  
  
**点分享**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWiaHpokNh4uWxia9Vv2eYjfzjXjW9bUCoUia7g4iaVGGGm5AKWRMoDMQoFDdJuiceofhPJ8SJpKSGToZcw/640?wx_fmt=gif "")  
  
**点收藏**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWiaHpokNh4uWxia9Vv2eYjfzjAEe2Bq3UgWlgxribzfYtnQ6EVkxkao5qmK0xpaoycfHyGVl7zFicPGibw/640?wx_fmt=gif "")  
  
**点在看**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWiaHpokNh4uWxia9Vv2eYjfzjDia9eCL6sIvuL17F5uKHsjx0GNc6estct1jOfWh4EtOcVsvzynOar1Q/640?wx_fmt=gif "")  
  
**点点赞**  
  
