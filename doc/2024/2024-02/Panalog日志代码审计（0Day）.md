#  Panalog日志代码审计（0Day）   
原创 Ambition  进击安全   2024-02-18 20:39  
  
**免责申明**  
  
本文章仅用于信息安全防御技术分享，因用于其他用途而产生不良后果,作者不承担任何法律责任，请严格遵循中华人民共和国相关法律法规，禁止做一切违法犯罪行为。  
  
  
**0x00 前言**  
  
      
看到挺多公众号都在发这一个系统，并且之前自己审计出来的一些漏洞也都相继爆出来了，今天我也来一个相关的审计流程。  
  
**0x01 鸡肋前台RCE漏洞**  
  
****  
涉及文件mailcious_down_fornode.php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXzU9v1cBhCFdyzssSBY6yjwAXwy8vbddibAOeXKHg8vdzIRA2gU3ciauCu61JJHxEcIicGSntbEJemg/640?wx_fmt=png&from=appmsg "")  
  
在这个文件当中首先接受参数action等于check的时候，会触发RCE漏洞的exec函数，并且其中uuid是我们可控的会造成RCE漏洞，但是为什么说是鸡肋漏洞呢，看下面代码。![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXzU9v1cBhCFdyzssSBY6yjFkEgypIqHzdydrNJD9ZS6tS9N7ZLQwT54HibVv0weBuictwVxH0RzVyQ/640?wx_fmt=png&from=appmsg "")  
  
  
在这里会进行判断这个文件是否存在，否则直接进行退出代码，所以这个文件是必须要去存在的，师傅们如果感兴趣可以尝试进行看看代码哪里可以生成这个文件。  
  
**漏洞验证**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXzU9v1cBhCFdyzssSBY6yjeEhG9Nxo8sgsaDNAbPZNmTRAsfdeIvrKiaet3WRP1iby5ok7RMdVdshQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXzU9v1cBhCFdyzssSBY6yjK20oickSiaGMViaoibIxHrFWicbm1OR1S3PPQutAjqiaQZpv3DIY8BBUJXibQ/640?wx_fmt=png&from=appmsg "")  
  
成功RCE！  
  
**0x02 前台RCE漏洞**  
  
****    
在找到鉴权文件进行相关的绕过之后，我们发现一个文件存在RCE漏洞  
  
文件路径：sessiptbl.php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXzU9v1cBhCFdyzssSBY6yjblOlb4XFJGKrpD6DhGKeBtLmvoewvQwnbq0rs5Sibsib9KLD64pEeVJQ/640?wx_fmt=png&from=appmsg "")  
  
在文件当中当action等于serverdelay的时候，cmd变量当中会存在一个变量为grpid刚好这个值是我们用户可控的，导致RCE漏洞。  
  
**漏洞验证**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXzU9v1cBhCFdyzssSBY6yjO53RRXxxfSJS8O2FRnicBEqeBU66FFLGnAZSxBKlE7g6LUG1yLrawAg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXzU9v1cBhCFdyzssSBY6yj6cKkGeLJvr2qjJicr2NZAofUscF6NaOrm0lQJCuibdOyG9YXG9kkWj0Q/640?wx_fmt=png&from=appmsg "")  
  
  
**0x03 前台RCE漏洞**  
      
  
      
这个漏洞就是大家经常看到的那个漏洞，其路径在/www/content-apply/libres_syn_delete.php  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXzU9v1cBhCFdyzssSBY6yjmJQf1xk5mxQsL1xkdIGR0ticrDaXuX3QLKryNsIAibRtNZZfEvg9Z9pw/640?wx_fmt=png&from=appmsg "")  
  
可以看到使用tokne以及id进行绕过过滤之后就可以进行正常的RCE漏洞了，RCE点在host当中。  
  
**漏洞验证**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXzU9v1cBhCFdyzssSBY6yjicSjNDWVWq83Osa8qekwy6qaxJCLicoDTNdPQ6urGia2SEyZTdx5XKQmQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXzU9v1cBhCFdyzssSBY6yjiaNDa9icSM6t2Bso9uo21ASVkVIib2E0Va2H1wXRMcOFWRW0nmhNKHJPw/640?wx_fmt=png&from=appmsg "")  
  
  
**0x04 完结**  
  
**作者联系方式**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXhuxbCGecu4ibia3kSXD8ePQHrSvPSNtC7PmjzQwR88Hu0LpuXdQzamKBCPAXX82anLS8f0FF3LzzQ/640?wx_fmt=jpeg "")  
  
****  
**关于内部纷传圈子，可以加添加作者咨询**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXzU9v1cBhCFdyzssSBY6yjVSleeyQ95UwO25q97aar2cjDCB8ELfePibibxaDdHCcWsouEjySKjCxg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXzU9v1cBhCFdyzssSBY6yjp6sZfDvsAC00IJ3iaZtaD6NK8WVQUBB6BSuM2nmAj5ON7z00wficB9BA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZRKuxIKRyhXzU9v1cBhCFdyzssSBY6yjy1u9qf1szYAgIHYebBoGmXWZicuzJFDdDia764g5cDZr9XgHjTTIlU2Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/ZRKuxIKRyhXzU9v1cBhCFdyzssSBY6yjgibcSgY0Tg6AUicDy1I8rOYWTL3lxThzQ637PzSqJxCmuQ9eKlm7QImw/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
