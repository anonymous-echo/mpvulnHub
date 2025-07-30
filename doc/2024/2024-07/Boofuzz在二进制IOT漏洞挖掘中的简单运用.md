#  Boofuzz在二进制IOT漏洞挖掘中的简单运用   
pureGavin  看雪学苑   2024-07-04 18:06  
  
```
```  
  
###   
### 环境  
  
  
Ubuntu 20.04  
  
Python、pip、qemu之类的直接用apt-get下载安装就好。  
  
  
binwalk里有需要用到sasquatch程序，需要手动下载一下，命令如下：  
  
  
```
```  
  
###   
### tenda AC15 CVE-2018-5767  
####   
#### 环境问题  
  
   
  
使用binwalk解包以后可以在bin文件夹下看到httpd程序，此时如果直接运行的话会卡在欢迎banner信息处。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FeKI2dpuEZmzElBSWjbK2SNnBmVmgkcbOvRj1cozsD43Xq7SeXat8jruGz2jEPr6Xs7h1uS59QvA/640?wx_fmt=png&from=appmsg "")  
  
  
需要patch一些代码，修改判断逻辑。  
  
  
下图中红框内就是已经patch好的代码，点击Edit > Patch program > Apply pathes to input file > OK 即可保存。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FeKI2dpuEZmzElBSWjbK2SBiaKHpib5zHNgTt3Hh0uFVSkUTaF9UZR2v27jJF07bxbcbs0FpgmDzEw/640?wx_fmt=png&from=appmsg "")  
  
  
修改完成后再次运行依然会报错。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FeKI2dpuEZmzElBSWjbK2Sbe8xErklh23iaibHsCPphVccWKTw2beIepOVNibZ5yOdPR9lfq1J2xSqg/640?wx_fmt=png&from=appmsg "")  
  
  
这个错误主要是IP地址不正确，需要查看一下httpd服务具体是怎么获取IP的，需要从check_network函数开始查，这个函数是引用了第三方的lib库（至少我在Linux源码里没找到这个函数）。  
  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FeKI2dpuEZmzElBSWjbK2SqFQhmMMOiajXrvpiak5Zeic0VtMmQwiaNjDibVPW8Ij7ZKic9STRkkNymTIw/640?wx_fmt=png&from=appmsg "")  
  
  
结果会找到libcommon.so文件，用IDA打开后可以看到依然是调用了别的so库代码。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FeKI2dpuEZmzElBSWjbK2Sdz75EXx7Ohzj1iayHoIyZQCLBS0tvbf7ibVBficNFxDbibvQs7B6Ric5icTg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FeKI2dpuEZmzElBSWjbK2SBCDrODk3dicoBD8Kc77W6L3qERldfuJUmorQuPlnYqJfpxFDalZnHvQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FeKI2dpuEZmzElBSWjbK2SaibR5X0icDRq3AsUvLfWnRXZib9QIrCTe03yKrX5cqTC2bjw6xBuH5LQg/640?wx_fmt=png&from=appmsg "")  
  
  
需要继续搜get_eth_name函数位置。  
  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FeKI2dpuEZmzElBSWjbK2SZTUJiaSUr4D7wUv6fjNTpjP2Ib9oRicmiaD0bAY7Qdx8HknOnyib26zCCA/640?wx_fmt=png&from=appmsg "")  
  
  
有四个匹配，事实上是libChipAPI.so文件。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FeKI2dpuEZmzElBSWjbK2SCulBPPibSIexZJ8ogliajw7GP8NhgoAp8Nse9AgVENAJToajyX9Lvlibg/640?wx_fmt=png&from=appmsg "")  
  
  
从代码里可以看到程序在尝试读网卡信息，因为没有对应的网卡，所以程序IP地址会出错，所以这里需要手动创建一个br0网卡，并给一个IP地址（在创建之前建议先保存一个快照以防万一）。  
  
  
```
```  
  
  
  
修改好后httpd程序就能正确运行了。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FeKI2dpuEZmzElBSWjbK2SVT2WnYkul4UBIAO74GqVDGnW71RL2NNh2RZe4wrU1SoHX6kDq6YVTA/640?wx_fmt=png&from=appmsg "")  
####   
#### fuzz部分  
  
  
此处需要抓包查看协议结构，但是因为只是普通的HTTP协议，我就直接给出boofuzz代码了。  
  
  
```
```  
  
  
  
在开始之前记得用pip安装一下boofuzz，因为已经知道漏洞点了，所以很快就能跑出结果了。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FeKI2dpuEZmzElBSWjbK2SQ74H3KpeDUu6n6KVsbh3zYgZVohF2Nha9TPd4WqHX7PlDKB1VcMClA/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到在password给出了一个非常长的值后程序崩溃了，验证其实也很简单，直接用Python脚本访问之前给br0的地址，端口是80，cookie中给一个超长的值就能复现崩溃了。  
  
  
```
```  
  
  
  
最后在bLanguage这个字段也有个溢出，大家可以尝试修改上面的fuzz脚本复现一下。  
  
### Vivotek漏洞栈溢出  
  
  
这是一个2017年爆出的贼老的栈溢出漏洞，不过用来学习boofuzz的使用还是不错的。  
  
#### 环境问题  
  
  
首先使用binwalk解包固件后会有不少文件，文件系统在这个目录下：  
  
```
```  
  
  
  
http服务用的是boa。  
  
  
这里有两个点需要修复。  
  
  
首先将宿主机中/etc/hosts文件夹中的内容全部复制到固件文件系统的/etc/hosts文件中去。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FeKI2dpuEZmzElBSWjbK2ShYVOEEvfmb0gcq7pI2SjNoD2BLwFMUsksfcHicorRkFL1ib5WzgntSlA/640?wx_fmt=png&from=appmsg "")  
  
  
然后将 _31.extracted/defconf/_CC8160.tar.bz2.extracted/_0.extracted/etc/ 目录直接拷贝到 squashfs-root/mnt/flash/ 目录中去，这一步主要是解决boa的config文件缺失问题。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FeKI2dpuEZmzElBSWjbK2SOYzgwPKl8xsA8uuckZ5QW41gN75T5Uo3NNCRmKve4clZhVibb4ayA8Q/640?wx_fmt=png&from=appmsg "")  
  
  
接下来直接用qemu命令运行httpd服务就行了。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FeKI2dpuEZmzElBSWjbK2Su7ia5vutTqyNDt8PibluwPhLnZgeVTP4bgAnZM0fOibUsf0TRwUocR2Zg/640?wx_fmt=png&from=appmsg "")  
####   
#### fuzz部分  
  
  
fuzz这个洞的脚本如下：  
  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FeKI2dpuEZmzElBSWjbK2S5DicUy7R2uXiam3IkfxzfU3PXJZooCvcJ3wz7MmS8bxFgpoS89IicnXRw/640?wx_fmt=png&from=appmsg "")  
  
  
几乎是一瞬间，boa服务就崩溃了，从输出信息来看，是因为 Content-Length 过长导致的，这也确实是这个洞的成因。  
  
  
  
```
```  
  
  
  
boofuzz是个挺不错的对协议的fuzz工具，比AFL好在不需要参与编译过程，也就是说不需要收集代码覆盖率信息；缺点也很明显，需要对协议格式深入分析，且因为没有代码覆盖率信息，所以对未知代码的触发基本靠运气。  
  
  
这里使用这两个IOT固件且只fuzz了HTTP服务是因为这两个固件的环境问题相对好解决且HTTP服务fuzz起来相对简单，所以解决环境问题最好的方式还是直接买硬件。  
  
  
## 参考链接  
  
https://xz.aliyun.com/t/5054?time__1311=n4%2BxnD07iti%3Dj2DBqooGkYLwq6DBDYTAD  
  
https://www.anquanke.com/post/id/185336  
  
https://blog.csdn.net/song_lee/article/details/113800058  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1UG7KPNHN8FeKI2dpuEZmzElBSWjbK2SVzkaeKjWNiacl691kr9wFtric5TWAWKgMXY719Lbn53hlrMvX1A5EWMA/640?wx_fmt=png&from=appmsg "")  
  
  
**看雪ID：pureGavin**  
  
https://bbs.kanxue.com/user-home-777502.htm  
  
*本文为看雪论坛优秀文章，由 pureGavin 原创，转载请注明来自看雪社区  
  
  
[](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458561802&idx=1&sn=26e2967f8e2f36987b08e5ea51d118a9&chksm=b18d9d8086fa149660ad8eb751d2d1cdd14e35868b60952a9f0522db79d6d2220f9d87ff049e&scene=21#wechat_redirect)  
  
  
  
**# 往期推荐**  
  
1、[Win10和Win11内存区域划分及动态随机的本质](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458562039&idx=1&sn=995437743de239147b79436f1e621d0d&chksm=b18d9d7d86fa146b9670f08e896c9d5797842af42004bdf5615208ddf639c3b480e99f79e6f6&scene=21#wechat_redirect)  
  
  
2、[Windows主机入侵检测与防御内核技术深入解析](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458561802&idx=2&sn=db9630a32c5c1aeaa311a1c9c0362cc3&chksm=b18d9d8086fa14962ffbbcdfb63373c259ec5f085f905e5c63e757474e558a32451c730e5c0c&scene=21#wechat_redirect)  
  
  
3、[反沙箱钓鱼远控样本分析](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458561661&idx=1&sn=daaa415aa700e0df08bb13330b007415&chksm=b18d9cf786fa15e1c62cc8101bc78a3cb1ec5bb536301cd6079d487550b35950f8e7293d2929&scene=21#wechat_redirect)  
  
  
4、[安全浏览器历史记录数据库解密算法逆向](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458560882&idx=1&sn=e27bca997c1990cc5540dddb4c99046d&chksm=b18d99f886fa10eecf64719afebae9102c9e33fcae4a7e003cbfd12ff8957225cdba60fac248&scene=21#wechat_redirect)  
  
  
5、[APP小说VIP功能分析](http://mp.weixin.qq.com/s?__biz=MjM5NTc2MDYxMw==&mid=2458560855&idx=2&sn=eda57c590bef26a345dd92990e26774f&chksm=b18d99dd86fa10cb16875905093f8c532049bb47386fb582a31093ebb45d93c856fba6239abe&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uia4617poZXP96fGaMPXib13V1bJ52yHq9ycD9Zv3WhiaRb2rKV6wghrNa4VyFR2wibBVNfZt3M5IuUiauQGHvxhQrA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fgp5LpLicJzyZBcAObibW18fB4z3Cib1L88C8iaTm7RUNM60aITCu3gGEsPDHJ1CqI3iamHfF4HCicjlLg/640?wx_fmt=gif&from=appmsg "")  
  
**球分享**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fgp5LpLicJzyZBcAObibW18fB4z3Cib1L88C8iaTm7RUNM60aITCu3gGEsPDHJ1CqI3iamHfF4HCicjlLg/640?wx_fmt=gif&from=appmsg "")  
  
**球点赞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fgp5LpLicJzyZBcAObibW18fB4z3Cib1L88C8iaTm7RUNM60aITCu3gGEsPDHJ1CqI3iamHfF4HCicjlLg/640?wx_fmt=gif&from=appmsg "")  
  
**球在看**  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1UG7KPNHN8Fgp5LpLicJzyZBcAObibW18fKNoDzicfjlGZia14Kjc7lYCXZZwglgVRKt20dLSGDBALfiaNJD5WMnkIw/640?wx_fmt=gif&from=appmsg "")  
  
点击阅读原文查看更多  
  
