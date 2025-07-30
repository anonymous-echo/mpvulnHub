#  应急响应-webshell查杀  
Flag  网络安全实验室   2025-06-13 00:54  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/BSCWGKoGibicQqQMTyjnicFjCia9YMkHJRIC1ibOD4PfiahM3MiaKn8StibHq0furcHluYNFBYAqrUarmB9ZysgAoIM8JQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/dleU3icGE4HiaFHOiaDmlLaNBpiadM7SUM0g0alQpGS1Hw30Ws9vWHhrgPhEZv8TH0jIJH2uB0J8qeGicNCgBN8hKLg/640?wx_fmt=gif "")  
  
  
## 玄机靶场地址：https://xj.edisec.net  
## 第一章 应急响应-webshell查杀  
```
```  
##   
## 1.黑客webshell里面的flag flag{xxxxx-xxxx-xxxx-xxxx-xxxx}  
  
首先，需要看一下系统都有哪些服务，可以用netstat命令  
  
netstat -antlp  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/myXZGtxSCgDaqia82QuOExooSkctibDYb1Gudw0Y2DTKBgDBRUvctApBgQC9BS7mWJibTC7WkWwPaoFrosDwbvNcQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/myXZGtxSCgDaqia82QuOExooSkctibDYb1QhpmrpnNUhQYicGFZ0IRUV6pDGibicOTJI2E4mu9utCdo0VZqT6I4c8pg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
可以看到有apache和mysql服务，一般来说黑客都是通过apache对外服务上传webshell，上传的目录在apache默认的web根目录下。我们可以切换到  
cd /var/www/html  
下。  
  
前面说过，黑客上传的webshell会有一些关键字，比如eval()、assert()这种函数，上传的文件结尾为php。所以我们可以用find命令搜索一下关键字。  
  
find./ -name "*.php" | xargs grep "eval("  
  
xargs   
可以将管道或标准输入数据转换成命令行参数，也能够从文件的输出中读取数据，通常和管道符一起使用  
  
之后我们对搜索出的三个文件依次进行排查，排查  
./include/gz.php  
文件时发现  
   
Flag   
为  
027ccd04-5065-48b6-a32d-77c704a5e26d  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/myXZGtxSCgDaqia82QuOExooSkctibDYb1o29iafPRYUNfcsbbn3Z8gdWzFhNdPOhYU9sTdnoVxBTpxd8knRHsZjQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
我们也可以把整个目录打包下来，放到D盾里跑一下。  
  
## 2.黑客使用的什么工具的shell github地址的md5 flag{md5}  
  
第二题是问用的什么工具。我们在shell.php里可以看到一段key值  
3c6e0b8a9c15224a  
，熟悉哥斯拉的师傅就能看出来，这是哥斯拉工具特征。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/myXZGtxSCgDaqia82QuOExooSkctibDYb1bDiauwBibibH6Uwic9PIBlo4pAX9qQfia4MplMGh9g6l5Zn75uajuj9BAXw/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
如果不知道的可以把这段key值在网上搜索一下，也会提示哥斯拉工具。  
  
所以第二个  
flag  
就是  
Godzilla  
的  
github  
地址的  
md5  
值  
  
https://github.com/BeichenDream/Godzilla  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/myXZGtxSCgDaqia82QuOExooSkctibDYb15EBRqiaEhsOpIwr8GkqkUuta45VlVpqqUiaUNTbYsxSHOBnzXFlLKCCQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
转成  
   
md5   
为  
39392de3218c333f794befef07ac9257  
，得到  
   
Flag  
##   
## 3.黑客隐藏shell的完整路径的md5 flag{md5} 注 : /xxx/xxx/xxx/xxx/xxx.xxx  
  
问的是隐藏shell，根据之前查杀结果，有一个文件是.mysqli.php，这就是一个隐藏文件。  
需要使用  
ls -a  
命令显示隐藏文件。切换到  
/var/www/html/include/Db/.Mysqli.php目录下，用pwd命令也可以显示完整路径  
。转成  
md5   
为  
aebac0e58cd6c5fad1695ee4d1ac1919  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/myXZGtxSCgDaqia82QuOExooSkctibDYb1gzIE2VTfEUQU4h3sa9pgib6HMOh46lLx8UvV5sJAOLBsKNb9MgeFlng/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
## 4.黑客免杀马完整路径 md5 flag{md5}  
  
常用的免杀马一般用base64、  
字符串异或加密、  
Base   
家族加密、  
rot13  
加密、字符串拼接等方式实现加密。我们可以手动搜索一下  
  
find./ -name "*.php" | xargs grep "base64_decode"  
  
这里在  
/var/www/html/wap/top.php  
中找到了   
Base64   
加密方法  
  
打开确认的确是免杀马，最终生成路径  
 md5   
为  
eeff2eabfd9b7a6d26fc1a53d3f7d1de  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/myXZGtxSCgDaqia82QuOExooSkctibDYb14AjKQobxhtg0BCrsl5jhcxKaX5xvtGib3vpqzxj2TKuSOnKvdkv33mg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
知识大陆 618活动开始啦  
  
1  
  
**老用户续费 7 折！**  
  
不搞满减，不设门槛，主打一个 “老铁交情”  
  
2  
  
**登录就送 永久会员8 折券！**  
  
不玩抽奖，不搞拉人头，没有多余套路  
  
1  
  
**老用户续费 7****折——系统自动降价**  
  
帮会加入页面，点击“加入帮会”，系统**自动显示**  
7折优惠价！  
  
2  
  
**登录就送 永久会员8 折券**  
  
**方法：下方**  
优惠券二维码直接扫码领  
  
****  
  
  
  
**网络安全攻防实验室**  
  
《网络安全攻防实验室》专注于网络安全领域，包括安全岗位招聘、网络攻防对抗、红蓝队建设、CTF比赛、安全运营规划、安全技术分享等，目前帮会笔记数量近6000，全是干货笔记。  
  
**1**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCZib6GkcFrg9UiazicTe9PZdDEwZ111UTxdTXXrgeUzibuo6AQiaMuKTpNg/640?wx_fmt=gif&from=appmsg "")  
  
**参与项目即可回本**  
  
**现在加入帮会，就能参与兼职项目，即刻回本，每月稳定赚吃饭钱！**  
不仅是这一个项目，后面帮会陆续接手更多兼职项目，**赚钱路径只多不少**  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPLxib1noMpr7Oiba9oiar12G182OrtVEyhBKOF5JRfQribefYrcibFwtTPnQ/640?wx_fmt=png&from=appmsg "")  
  
**2**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCZib6GkcFrg9UiazicTe9PZdDEwZ111UTxdTXXrgeUzibuo6AQiaMuKTpNg/640?wx_fmt=gif&from=appmsg "")  
  
**帮会内容框架**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/myXZGtxSCgDe17gjarNDEMVShCGa5raZOkbDohcKhP35fbUA4icxAu4dYn1oNOCMDy9ZttFy26ZxrBx1fsPgFXQ/640?wx_fmt=png&from=appmsg "")  
  
**3**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCZib6GkcFrg9UiazicTe9PZdDEwZ111UTxdTXXrgeUzibuo6AQiaMuKTpNg/640?wx_fmt=gif&from=appmsg "")  
  
**帮会已有内容**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPcJhNQbsmxAqW2J1Vz23y9Q9Ria5dUHT07IjVxEYeIPvaLSGhEbW2c9Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPKibXI3AuY5iaMe1351iaXo0wCsicpus841x4rcLia6beuNSVX5CRqLPs99g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCHRHeTg97DMpdYdFXCHStIFAicXfv8waFYYZHTqojX6jGjOxQyXZe9w/640?wx_fmt=png&from=appmsg "")  
  
**4**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCZib6GkcFrg9UiazicTe9PZdDEwZ111UTxdTXXrgeUzibuo6AQiaMuKTpNg/640?wx_fmt=gif&from=appmsg "")  
  
**目前已更新6000+干货笔记**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/myXZGtxSCgA0ibImvqOtk3ohahrsZuk59ibhROj37ZxOAqFky4ofVDHhN36iboUsv8DkTs2Ez47QpvADjCyGM6HRQ/640?wx_fmt=jpeg&from=appmsg "")  
  
**5**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCZib6GkcFrg9UiazicTe9PZdDEwZ111UTxdTXXrgeUzibuo6AQiaMuKTpNg/640?wx_fmt=gif&from=appmsg "")  
  
**加入帮会，你可获得：**  
  
1. 各类网络安全攻防、CTF比赛信息、解题工具、技巧、书籍、靶场等资源；  
  
1. 攻防思维导图，0基础开启网络安全学习之路；  
  
1. 参与FreeBuf知识大陆官方专属兼职项目，开启兼职赚钱之旅；  
  
1. 遇到任何技术题都快速提问与讨论交流的思路；  
  
1. 组织队伍参与各类CTF比赛；  
  
1. 面试大厂心得及内推资格；  
  
1. 学习规划、人生规划也可以探讨哦！  
  
  
  
  
  
**（三）部分内容资源展示**  
  
**01**  
  
**HW/攻防对抗**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPQ8PZFCOON9dZhwiaRuN3Y8NAGwWQRwY4KJbuyUbB5bgRvv2an2rVzyw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPGr4HKrjlHRBSeAIAJKs1yL1ibiaNCDagL5QAjagsxGLiaGlk3JwXMVClw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPfBaUCuxF9TJEUMs6Gy6ibr2REMibS1Y4c24hC40XxvcLDPNG0eLR0fNg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPY2lIXljXickB5zJ5z3sreE9RngmN54L7XtpbE2Fosg8ddpMB7hTSQXw/640?wx_fmt=png&from=appmsg "")  
  
**02**  
  
**分析研判**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPBDdUSm49JDKmPGQjVadZUeqXb0wz9iaOoN1xHmLbnPYOgUBwVJvcOwg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPlhoEPIoOL644iciaVQdpFaQW5SrXic7d40j8ibU0ViaLslo0znoXyIgkQwg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPOJZYMvGLzobTymHWCc62uv7wsgmYIRC5nlJ9TficNmMROthkcHqIicbA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPEIJOEGEnmia37rUOLnN5wqjibADoiarv0ubO5VnVOwicdLpcQdacooQiaXA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPtUXW4yQicEKH2Zro2r79hZTCYoefZVMcQqjbH0ds38bpCtVBJZVsSMQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPXic1A0Q5M7V072B5VJHibylT8lTpo5dMWWdt0BjVicchYc81RGxNoia8hw/640?wx_fmt=png&from=appmsg "")  
  
**03**  
  
**APP渗透**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPodPPms90IV3ZGY50xH9UBLLdy6CibXIuH3K1hcZDvOPMz5Zf0dpNTKQ/640?wx_fmt=png&from=appmsg "")  
  
**04**  
  
**POC/EXP合集**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPMtzuPCrqAia08t8LUjSeQSfS9XiccicO0oNrO06uPiczxmN1pBeLkLhcXg/640?wx_fmt=png&from=appmsg "")  
  
**05**  
  
**网络安全报告**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPOnWnHDQmibQqMGw1N2x5gbian9icAXKRSjdXbrX6rqPaUWiciaoFxNDGK9w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPzloPvFHp9IibLCFKZzhNZWZfsS2W3stibib2zWQVuMrCjeAcaUGhg7cUQ/640?wx_fmt=png&from=appmsg "")  
  
**06**  
  
**CTF学习资料**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPhlo1pkE12GjjVbLicicV9jmhibCWF9R7gPibxyoSgxY7DIWzzSfTqShGXg/640?wx_fmt=png&from=appmsg "")  
  
**07**  
  
**红蓝队、CTF工具包**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPLzibPfWmibwDf1uZicvXW1e8oaHbdtcerYSzuKvhNBdTNw2WOPLdw4zicg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPKrfQoibcRS1xmWlzogWazU6ibKRiamOXM7ITUvnzq5P1x4sCvOZDZTl9g/640?wx_fmt=png&from=appmsg "")  
  
**08**  
  
**网络安全学习笔记**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPbSQLgpwibFn2GlAgXQ8d23ZCRgJvfJV201ThsFWPOkdibNvWFeTbsRKQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**（四）帮会资源与服务**  
  
**1**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCZib6GkcFrg9UiazicTe9PZdDEwZ111UTxdTXXrgeUzibuo6AQiaMuKTpNg/640?wx_fmt=gif&from=appmsg "")  
  
**帮会网盘**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPSWj0LEcs4sUGMnVrwI1E8FxIEgxffvABK1fgQODzyTXMClKPWGiaUMw/640?wx_fmt=png&from=appmsg "")  
  
**2**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCZib6GkcFrg9UiazicTe9PZdDEwZ111UTxdTXXrgeUzibuo6AQiaMuKTpNg/640?wx_fmt=gif&from=appmsg "")  
  
**帮会专属兼职项目**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPLxib1noMpr7Oiba9oiar12G182OrtVEyhBKOF5JRfQribefYrcibFwtTPnQ/640?wx_fmt=png&from=appmsg "")  
  
**3**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCZib6GkcFrg9UiazicTe9PZdDEwZ111UTxdTXXrgeUzibuo6AQiaMuKTpNg/640?wx_fmt=gif&from=appmsg "")  
  
**内部社群技术交流**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/myXZGtxSCgD8umTszThRd8siadXBemOSovelUaImDTdpjXVmTaFa6Omf8ROgWEjPoOfADakWcFFuWdOFvZtS0wg/640?wx_fmt=jpeg "")  
  
**4**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HaJr68L1tTTyCC8O1Oa7QCNiaQwscfJqPCZib6GkcFrg9UiazicTe9PZdDEwZ111UTxdTXXrgeUzibuo6AQiaMuKTpNg/640?wx_fmt=gif&from=appmsg "")  
  
**帮会技术力量保证**  
  
帮主：网络安全攻防实验室  
- 「网络安全攻防实验室」的帮主；  
  
- 公众号“网络安全实验室”的作者；  
  
- 资深安全专家，16年网安经验；  
  
- 拥有丰富的HW、重大保障、应急响应、安全运营、网络交换等方面经验/独特见解。  
  
  
  
  
**（五）加入方式**  
  
**目前秉持着打造**  
**人多热闹****的帮会理念，**  
  
**永久会员只需119元，现在还能领取24元优惠卷，卷后只需96元。**  
  
**之后随人数增长，将涨价至149元。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/myXZGtxSCgCj7ribUW9BkZ7WNVOrmvZbficsBPhLfmzmcH1fGd5ry809lsTOibdU20Um7csIcmibwQdMgmAvCKCZOw/640?wx_fmt=png&from=appmsg "")  
****  
如何加入帮会？  
  
- PC端可进入链接：  
  
https://wiki.freebuf.com/societyDetail?society_id=168  
  
- 也可直接微信扫码支付↓↓  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/myXZGtxSCgDAOibXuKD4fnP2A0Y5mAicyK59BZ8XAThzEYEYeU1v6x1Im8ClPPG91K06rHYSl9Qg9ibv0EGmcoEMQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**加入帮会的师傅们，可以看帮会置顶加入兼职项目赚钱哦**  
  
  
  
