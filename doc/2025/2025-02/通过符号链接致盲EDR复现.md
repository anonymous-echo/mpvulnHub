#  通过符号链接致盲EDR复现   
relaysec  Relay学安全   2025-02-10 08:24  
  
创建起因是看到了  
Ots安全  
公众号发布了一篇BYOVD 更上一层楼。使用 Windows 符号链接进行盲 EDR。  
  
大概看了一下内容，找了一下原文，是一个老外写的。  
```
https://www.zerosalarium.com/2025/01/byovd%20next%20level%20blind%20EDR%20windows%20symbolic%20link.html
```  
  
大致的看了一下，对其进行了复现。  
  
本质上是通过创建符号链接来致盲EDR的一个操作。  
  
假设有一个驱动程序需要将文件写入到  
C:\Temp\log.txt  
文件中，但是攻击者在  
C:\Temp\log.txt  
位置创建了一个符号链接。使它指向了  
C:\Windows\System32\important_file.dll  
。当程序试图写入到  
important_file.dll  
文件时，实际上它写入到了  
C:\Temp\log.txt  
。  
  
如下创建的符号链接：  
  
其实就是说假设驱动程序启动时会去往  
C:\Temp\log.txt  
写文件，那么正好我们创建了一个符号链接，当它往这个  
log.txt  
文件中写入内容时，其实实际上写到了  
important_file.dll  
文件中。  
```
mklink "C:\Temp\log.txt" "C:\Windows\System32\important_file.dll"
```  
  
其实也就是说该文章作者拿到了一个驱动程序，该驱动程序有着写入文件的功能。  
  
该驱动程序会将日志写入到  
c:\windows\procmon.pmb  
文件中。而如果对其通过符号链接到EDR的可执行文件中的话。那么当文件写入到  
c:\windows\procmon.pmb  
文件中时，实际上其实写入的是EDR可执行程序。这样就导致了致盲。  
  
利用如下:  
  
首先需要去安装promon64.exe。  
  
打开之后->Options->Enable Boot Logging。这样就可以开启日志记录功能了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2moczibsLvPS3lQ9hRHy35BsMID6icHYzBic3m1MH39JrK7CyslwzDDkue5Zic5bVnAGrSntKmuGqQibzgg/640?wx_fmt=png&from=appmsg "")  
  
然后退出该程序，紧接着就可以符号链接了。  
```
mklink C:\Windows\ProcMon.pmb "C:\Program Files\Windows Defender\MsMpEng.exe"
```  
  
创建成功之后重新启动操作系统即可致盲。  
  
重启之后我们会发现Defender已经无法启动了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2moczibsLvPS3lQ9hRHy35BsML2MSrtA1fN9Djibianehj21GdUATytRDzicxptF0ngUqtZPa2qiaRGBV4g/640?wx_fmt=png&from=appmsg "")  
  
并且签名也没有了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2moczibsLvPS3lQ9hRHy35BsM1IvAl1LkxlogprxT29I2PvgPh39n7xqkx4oJibUegibnUSpXZjEUVlyQ/640?wx_fmt=png&from=appmsg "")  
  
如上图我们也发现该文件的大小变得很大，这是因为本身驱动程序本应该写入到   
c:\windows\procmon.pmb  
文件中。  
  
因为符号链接的缘故，最后写入到了MsMpeng.exe文件中了。  
  
欢迎加入我的知识星球，目前正在更新免杀相关的东西，145/永久，每100人加29，每周更新2-3篇上千字PDF文档。文档中会详细描述。目前已更新105+ PDF文档，《2025年了，人生中最好的投资就是投资自己！！！》  
  
加好友备注(星球)！！！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mr6tnqhFeYPVHGE9zUaoOwegUopeleqcBHwM0FQKBtqMkvFOfVvicibFlm6mRvLqmF8iar7dknyKyAVw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
##### 一些纷传的资源:  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpic816FGIfRPyxLfIanSE0ldHAcibcttYtJmlNQ2bMZg71NqUNy0oxTibnicNaZgIsbbjCKHpzYhyXqQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpic816FGIfRPyxLfIanSE0lcia6THnRbFpbGu79luuz8oa2IibShuG3nIv16us2h42z7Vh3URlP1J9A/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/ia1z64qxm2mpic816FGIfRPyxLfIanSE0lBv0M63wCogocUMbvWXHloiaZ4ibn91ZEDA5QfJDicNxCgPIBDmibFYgdSw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
