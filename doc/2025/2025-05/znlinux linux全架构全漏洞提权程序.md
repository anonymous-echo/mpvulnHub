#  znlinux linux全架构全漏洞提权程序   
 进击的HACK   2025-05-07 14:28  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DuibU3GqmxVmRsdItbBVRKegNHicHQvAHDdZsGpLVU7touSU1AU1twHTfRjG3Vu5aUh0RnPPllfVUhs4qdWF5QYQ/640?wx_fmt=png&wxfrom=13 "")  
  
声明：  
文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途给予盈利等目的，否则后果自行承担！  
如有侵权烦请告知，我会立即删除并致歉。谢谢  
！  
  
文章有疑问的，可以公众号发消息问我，或者留言。我每天都会看的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zYJrD2VibHmqgf4y9Bqh9nDynW5fHvgbgkSGAfRboFPuCGjVoC3qMl6wlFucsx3Y3jt4gibQgZ6LxpoozE0Tdow/640?wx_fmt=png&wxfrom=13 "")  
  
  
项目地址：https://github.com/twowb/znlinux  
- 无源码  
  
- 提供release  
  
- 是否存在病毒自测  
  
我在自己虚拟机的ubuntu上是成功提权了，结果如下：  
```
./znlinux_linux_amd64 -a
```  
  
提权成功：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrj59KuMLnibV0TVkH8VZhiaA7Ex95A03yUoP4Sn5ic3zcEyyalsBO5hQBHjBViaJUdYV5w4NoY7Liarj1Q/640?wx_fmt=png&from=appmsg "")  
  
使用  
```
Usage:
znLinux [flags]

Flags:
-a, --any 一旦检测到漏洞，立即尝试利用该漏洞。在可能的情况下提供shell。
-h, --help help for znLinux
-p, --with-password 提示输入用户密码
```  
  
  
  
  
  
