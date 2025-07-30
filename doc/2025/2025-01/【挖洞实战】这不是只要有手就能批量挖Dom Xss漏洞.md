#  【挖洞实战】这不是只要有手就能批量挖Dom Xss漏洞   
原创 奥村燐  弥天安全实验室   2025-01-13 04:25  
  
网安引领时代，弥天点亮未来 ****  
  
  
  
  
  
****  
  
****  
  
**0x00前言描述**  
  
  
  
**我过去经常挖掘Dom Xss漏洞，因此写下了以下文章记录了整个过程。接下来，我计划将其改进为自动化挖掘。**  
  
  
****  
  
**0x01整体过程**  
  
  
  
**假如我发现了一个网站，并想要挖掘其中的 Dom Xss 漏洞。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MjmKb3ap0hC2ibcohibptunKKTXib2aWRbibhdsf0Bugu6m85VoURofe62OA9O0pjFs3FaFqWPzlKPvGhz5xia5zngg/640?wx_fmt=png&from=appmsg "")  
  
  
        **网站加载了一段 JavaScript 代码，乍一看就能察觉到存在 Dom Xss 漏洞。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MjmKb3ap0hC2ibcohibptunKKTXib2aWRbibelGBRvJlbwh5yxMBTVXiaKiamb4Tfy5GROa1ibp1LlowCwibvZziasWX4BA/640?wx_fmt=png&from=appmsg "")  
  
  
           **右键单击以保存网站代码。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MjmKb3ap0hC2ibcohibptunKKTXib2aWRbibzO9sRmqhMJBIsaJ3FTXz1vdPazmtr23ibOIEy9xn9PNkbsTWcoWfQEg/640?wx_fmt=png&from=appmsg "")  
  
  
**接着将网站源码打包。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MjmKb3ap0hC2ibcohibptunKKTXib2aWRbib6VZkZC1xk5ws4hAlkPntFzic9o5534EArTIpjtkTp5FkY2RrJv0icbKg/640?wx_fmt=png&from=appmsg "")  
  
  
**然后将压缩包上传到奇安信代码卫士进行扫描。**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MjmKb3ap0hC2ibcohibptunKKTXib2aWRbibK1icibIOrYlA3YlVXPsHWkro9y4TocGJgRAVlOnn0uI33aUibHUaDAUKw/640?wx_fmt=png&from=appmsg "")  
  
  
**这个时候就能发现网站存在的Dom XSS漏洞**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MjmKb3ap0hC2ibcohibptunKKTXib2aWRbibYLgdia5MUBLlicPsPtw1ZAajrOv2Os5O7JX1iaZ8aUhlluZQM4Y0c0upg/640?wx_fmt=png&from=appmsg "")  
  
  
**成功复现**  
```
http://192.168.7.104/?name=11111%3Cimg/src=%22https://www.baidu.com/img/PCfb_5bf082d29588c07f842ccde3f97243ea.png%22/onload=%22alert(1)%22%3E
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MjmKb3ap0hC2ibcohibptunKKTXib2aWRbib0y5KSFnS2HyvDLAcFibFU280kRGu2Y0w2IpelOrUqLOgoTMopJ5BDjQ/640?wx_fmt=png&from=appmsg "")  
  
  
**后期打算把整个流程进行自动化，具体流程如下 :**  
  
****  
**爬虫批量爬取网站->把网站全部保存到本地->自动进行ZIP打包->通过API接口上传到奇安信代码卫士进行扫描->复现漏洞->提交SRC->收钱->洗脚**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MjmKb3ap0hC2ibcohibptunKKTXib2aWRbibMD2ZFmrXPRLqE0UFl27WibDJ1FhECZAYLhDHlu0eChvBHgjlsIiaRMibg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MjmKb3ap0hC2ibcohibptunKKTXib2aWRbibX0eHffFB2TgGSlSInkjXBDkianJEo4MRicKKbf6hBNuUmVGtcnTSFTXw/640?wx_fmt=png&from=appmsg "")  
  
****  
  
****  
  
**0x02视频效果**  
  
  
****  
  
  
 知识分享完了喜欢别忘了关注我们哦~学海浩茫，予以风动，必降弥天之润！   弥  天安全实验室  
  
