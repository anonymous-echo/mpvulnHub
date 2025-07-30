#  浅谈搜狗输入法0day的原理   
原创 Ares  Ares信息安全   2024-08-01 23:17  
  
**今天在wx群、情报社区，看到了很多师傅发的搜狗输入法的漏洞复现，我自己也在本地复现了一下。**  
  
  
 复现完这个漏洞，联想到很多年前用过的破解windows7密码的一个方法，长话短说，简短的讲一下流程：  
  
在windows7的锁屏界面有一个讲述人功能，narrator.exe  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IMCE1GHaJyNGJRVA2a9JuZMuzwvjoBaBukiceorKz6TWPhriawGN3O3ftDhls8nnic3WJ8p0ibdJiaUG1rianW9dibv0w/640?wx_fmt=png&from=appmsg "")  
  
通过多次重启计算机，可以诱导系统认为发生了错误。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IMCE1GHaJyNGJRVA2a9JuZMuzwvjoBaBosh9QD5ibXkPt6I5iaZ8TBwIMT2uMs1BRsbdV6Adn8flKuMOuib0tBkjg/640?wx_fmt=png&from=appmsg "")  
  
直到出现以下的页面  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IMCE1GHaJyNGJRVA2a9JuZMuzwvjoBaBfrIpdAHm7nS3hmC9unTPiau6KpTJV6XzFfTm6JjFNg2eFJ2ZvMibWZag/640?wx_fmt=png&from=appmsg "")  
  
选择启动启动修复进入  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IMCE1GHaJyNGJRVA2a9JuZMuzwvjoBaBEoibhKhe2loKziaq5sREssolXZ1yv05dIWzmouibribF1QVKl3nrToDHlQ/640?wx_fmt=png&from=appmsg "")  
  
系统会自行检查问题，但重启是我们人为的，所以它检查不到任何问题  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IMCE1GHaJyNGJRVA2a9JuZMuzwvjoBaBibCYJUyicY4ANTs2PBgzSaPERtFTDY8bMjIIIEJZhDxqiavaj2HX8mDibw/640?wx_fmt=png&from=appmsg "")  
  
出现这个弹窗后，我们点击查看问题详细信息，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IMCE1GHaJyNGJRVA2a9JuZMuzwvjoBaBdsp9aicIsC2B6ZeLt29n5p19dQVTibFOpw8YerIlibfxtF8JIK9eG0yAQ/640?wx_fmt=png&from=appmsg "")  
  
点这个路径链接  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IMCE1GHaJyNGJRVA2a9JuZMuzwvjoBaB6HE4sviblhJMIxAm7SncZ3xpaQiczoDlT7xPjdATPXIQSKO6u1TOuJJQ/640?wx_fmt=png&from=appmsg "")  
  
再点击另存为文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IMCE1GHaJyNGJRVA2a9JuZMuzwvjoBaB616rSkb9MorcEcBUAMYMoibHD3zl8XtedfTGskcCIpYr5lpFUZggP2A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IMCE1GHaJyNGJRVA2a9JuZMuzwvjoBaBBLq71cicJuF15UOYuUMXxY672brOTb4GZavnWXBVMaMjibu15pADDvKw/640?wx_fmt=png&from=appmsg "")  
  
在system32目录中替换cmd和讲述人的文件名  
  
再次开机讲述人已经变成system权限的cmd  
  
![](https://mmbiz.qpic.cn/mmbiz_png/IMCE1GHaJyNGJRVA2a9JuZMuzwvjoBaBr3EVWNOE4icfx7Gqm7rzNrU24ibtG277lpHMwhgakDOQ9CXkibUqcoSvQ/640?wx_fmt=png&from=appmsg "")  
  
   到这里大家也理解这个思路了，在另存为文件的步骤，跟搜狗的漏洞尤为相似，所以我觉得这个漏洞应该归属于Windows的未授权访问，并不完全是搜狗的锅，在2015年也有师傅在WooYun平台提交，但复现流程基本类似  
```
https://wy.zone.ci/bug_detail.php?wybug_id=wooyun-2015-0162467
```  
  
     所以此漏洞应该属于Windows资源管理器接口调用问题，在下载新文件时，没有指定下载路径，就会弹出保存位置的窗口，正好可以利用开启的资源管理器运行cmd，由于在锁屏时并没有任何用户登录，所以这个cmd并不是用户创建的，故权限为system  
  
但此漏洞影响并不大，它只能被用于近源攻击。  
  
我的讲解并不是很全面，还请师傅们多多指正。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/IMCE1GHaJyNGJRVA2a9JuZMuzwvjoBaBp1c8JmFjTdCNDsMauHrCpyiarPcW3Ep90WNHotK12h4GUKaUOFduZAA/640?wx_fmt=jpeg&from=appmsg "")  
  
这是我的VX，感兴趣的师傅可以添加与我共同探讨  
  
