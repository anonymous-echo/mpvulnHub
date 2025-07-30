> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NDg4MzYzNQ==&mid=2247486516&idx=1&sn=8ce41df1c1c32eddb5762dc6c362a85b

#  新一代SQL注入检测技术，小白也能轻松挖到漏洞！  
小黑子安全  小黑子安全   2025-07-09 10:11  
  
        
国内抓包工具  
Y  
akit横空出世，界面友好、功能全面。最让人关注的就是里面的上千款漏洞检测插件，只需要在渗透测试开始时启动  
yakit  
——选择需要的插件，点击目标功能点触发数据包即可开始全自动化的漏洞检测。  
  
Yakit  
下载地址：  
https://oss-qn.yaklang.com/yak/1.4.2-0704/Yakit-1.4.2-0704-windows-amd64.exe  
  
        
我们都知道目前基于爬虫的漏洞扫描，是没办法检测到需要登录之后的功能点的。插件就完美的解决了这个问题，插件使用了被动扫描机制，被动扫描可以检测到完整的功能点  
(  
比如登录后的功能点  
)  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIm5k1X78s2znNtbzcNj7LzQ0M9MyJGaMQLw1OpjSUrb8YqsacicSibmPCkerf6URS7eAnibEYthP6IuQ/640?wx_fmt=png&from=appmsg "")  
  
      但是被动扫描的也存在痛点，大量的数据包被重复检测，重复发包，开启被动扫描后网站经常建立链接失败。  
  
      于是作者针对这个问题写出了几款全自动漏洞被动检测插件，基于最小化发包原则开发的漏洞检测脚本，实战中表现良好。  
  
        
比如其中这款新型  
SQL  
注入检测插件——被动  
sql  
注入检测，在  
sql  
注入全自动化检测方面都实现了显著突破，特别是在检测准确性、速度和全面性三个核心指标上。  
  
可以看到只用了  
6  
个数据包就检测出了  
sql  
注入漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIm5k1X78s2znNtbzcNj7LzQmEcQL6MNDpO8ubak87HMHMLdzv2SJrc5gI9XS9tOicDChibgBdofTIicQ/640?wx_fmt=png&from=appmsg "")  
  
        
该方案最大的优势在于采用了  
  
去重机制  
  
和  
  
智能资源过滤。通过跳过静态资源文件和扫描时对请求过的路径进行去重避免了重复检测，实现了最小化发包，并且工具的注入  
payload  
有一定的绕过检测的能力。让我们的漏洞检测更全面、变得更加高效。并且使用三阶段验证机制大大提高了检测结果的可信度。  
  
      作者在实际场景进行了测试，发现插件在各种环境中保持了稳定的高效表现，同时对服务器的影响最小化，真正实现了既全面又高效的安全检测。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIm5k1X78s2znNtbzcNj7LzQ37aVQNUojDiaIKx634oPrLKgGOAYOrUDdJcFJxJnIekniachWjRB4CDg/640?wx_fmt=png&from=appmsg "")  
  
      插件完成后作者也是体验了一番，并且和其他插件进行了对比。速度上  
  
作者启动了存在  
sql  
注入漏洞的靶场进行对比，其他市面上的检测方案出漏洞需要  
3~4  
秒，而  
  
被动  
sql  
注入检测插件  
  
只需要  
1  
秒不到的时间。作者也使用此插件在各种场景进行了漏洞挖掘。  
  
靶场环境：  
  
可以看见，访问了  
10  
关就出了  
10  
个  
sql  
注入漏洞。不管是数字型、盲注型、报错型的注入都可以轻松挖掘出来  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIm5k1X78s2znNtbzcNj7LzQ0GZgibiafSB8GeXrkNibAYMTrMujpvJGpblZvBHNmoesiaezWODSKG3NGQ/640?wx_fmt=png&from=appmsg "")  
  
后是对补天的公益  
src  
场景进行插件漏洞挖掘，效果也是相当不错！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIm5k1X78s2znNtbzcNj7LzQVKOQeQiblhQMBKAtmC7XaTmfsTWSG2SSr3f5PRJew2bj0CKyKg2ibqicw/640?wx_fmt=png&from=appmsg "")  
  
       而后又对漏洞盒子的企业  
src  
下手，相信大家对企业  
src  
的挖掘难度是有目共睹的，但是我们的插件依旧稳定发挥，直接拿下  
2000+  
赏金！！！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIm5k1X78s2znNtbzcNj7LzQZqerqQsic5cPicYUa7DKnjGaKfqV2O7qMZbEaRFOj9pHQDz5bHPrHWXg/640?wx_fmt=png&from=appmsg "")  
  
      以上漏洞都是不需要任何技巧的，作者只是开启插件在目标网站用鼠标“点点点点”就挖掘出这么多漏洞，完全  
  
“零基础”“  
  
零成本”挖洞  
  
目前一共开发了四个插件：  
  
被动  
sql  
注入检测  
  
被动  
xss  
扫描优化版  
  
被动目录扫描好人版  
  
被动  
ssrf  
及  
log4j  
检测  
  
知识星球——小黑子安全圈  
[  
精华版  
]  
    
开业大吉！  
  
     每一个插件都是非常实用的，有没有用作者也已经通过  
  
企业  
src   
漏洞的挖掘来证明了，并且只需要开启插件  
  
点击鼠标就可以全自动挖掘漏洞。  
  
      需要获取插件的小伙伴可以扫描下方二维码加入我的知识星球，星球  
 99  
元  
/  
年  
  
，前  
50  
个加入的  
 77  
元  
/  
年。  
  
加入知识星球的同学会提供  
  
yakit  
  
安装  
  
和  
  
插件  
  
使用教程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b9ibb0kbHCIm5k1X78s2znNtbzcNj7LzQq1vDdwSicwRG9hQjdkG9NTmG4aynicDNGtzdDysUiaxwjvbJXfud2Sia7g/640?wx_fmt=jpeg&from=appmsg "")  
  
       本星球只提供精华内容，没有烂大街的东西。会持续更新  
yakit  
插件和各种漏洞漏洞探针和利用工具，哪怕你是什么都不懂的小白用了插件点点鼠标就能挖到漏洞。  
  
注！！！红包返现！！！拉新活动！！！  
  
      星球接受使用插件挖到漏洞的投稿，我审核通过会返  
30  
红包，直接微信转，文章我会发公众号  
(  
每人仅限一次，要提共漏洞平台审核通过的截图  
)  
。  
  
      拉新人加入星球待满三天也会返  
20  
红包  
(  
微信直接转  
)  
。插件会一直优化和上新，欢迎大家加入星球。  
  
  
