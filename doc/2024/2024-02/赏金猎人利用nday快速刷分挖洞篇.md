#  赏金猎人|利用nday快速刷分挖洞篇   
 迪哥讲事   2024-02-03 22:33  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/icdGEWOnYLpNJUTyXhK4Iic6TJFLAAboGBK3V3tSviaWr4PZG8a6IYoiaMTg23QFLvasNxpQL1Ed9qLsPUmGPH1mPw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**0x01 前言**  
  
首先，对于0day、1day、nday在某平台提交漏洞入口是这么说明的  
```
0day（零日）漏洞：指软件厂商尚未发现并修复的漏洞。黑客利用这些未知漏洞进行攻击，而软件开发商还没有来得及发布补丁。
这类漏洞具有很高的危险性，因为黑客可以利用这些漏洞进行攻击，而用户和厂商很难发现并防范。一旦0day漏洞被公之于众，就会引起广泛关注，厂商需要尽快发布补丁来修复这些漏洞。
```  
```
1day（一日）漏洞：指在软件厂商已经发现并发布了相应补丁的漏洞，但许多用户尚未及时更新补丁。
黑客利用这些尚未修复的漏洞进行攻击，因此这类漏洞仍具有一定的威胁性。然而，1day漏洞相对于0day漏洞来说，危险程度要低得多，因为用户可以通过安装补丁来防范这些漏洞。
```  
```
nday（N日）漏洞：指在软件厂商已经发现并发布了相应补丁的漏洞，但经过一段时间后，仍有部分用户尚未更新补丁。黑客利用这些尚未修复的漏洞进行攻击。
nday漏洞的危险程度介于0day和1day之间，取决于实际情况。随着时间的推移，越来越多的用户安装补丁，nday漏洞的危险性会逐渐降低。
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpNGMrZ4k2Mo2vvnqiaiccfOI3zycqvxzDBFfXrIAqtnwGY2duf5eZM5pB5ugZUicph8B3rcNeLejZ6cw/640?wx_fmt=png&from=appmsg "")  
  
对于已经开放了的nday漏洞、各种渠道会发出相应的PO  
C(概念验证)、可利用此POC对某些单位等未进行修复，打补丁或使用旧版本的服务漏洞进行攻击，以达到攻击成功的目的  
  
关于刷分，攻击者可以对已有的POC进行编写相关脚本、脚本此处称为EXP(漏洞利用程序)、接着攻击者或RT(red team)红队会在之前已经打点好的攻击目标或以单位、域名等资产为中心进行后期存活探测等操作，导入到自编写脚本，进行刷分操作，nday刷分也是攻击者或RT刷分的一部分  
```
获取相关工具及资源请关注公众号后回复 '漏洞工具' 进行下载
```  
  
*** 以上工具来源于互联网、如有侵权请及时联系删除**  
  
*** 内容资源仅作为参考分享、切勿进行违法用途、后果自行承担**  
  
**0x02 思路刷新**  
  
前期信息资产收集打点，往往以Google、Fofa、Shodan等搜索引擎开始，以Fofa为例结合某OA历史漏洞进行复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpNGMrZ4k2Mo2vvnqiaiccfOI3mibfbS3S4qEStGJK6aXXIXlwr7b25Sicm5qJDbgdNQIR5QvIoZPtK1NQ/640?wx_fmt=png&from=appmsg "")  
  
已知此OA的历史漏洞为SQL注入，使用POC进行测试，在此返回内容中符合存在漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpNGMrZ4k2Mo2vvnqiaiccfOI3p6OD2cu6FaWfengIjfuQgA64axdnIlFia031KBRzOzjXlgZqibCxXdcg/640?wx_fmt=png&from=appmsg "")  
  
使用SQLMAP测试确认存在SQL注入漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpNGMrZ4k2Mo2vvnqiaiccfOI3plQD1dlKabZnmXdO8VdsqibjtOxCL40jggSUqZibRUJJMPiaAnPDQs3OQ/640?wx_fmt=png&from=appmsg "")  
  
对于nday官方基本上早就发布了修复方法和补丁，但是有很多还在使用旧服务，漏洞可能会存在，nday就是用来碰运气的，当资源足够多的时候，就应该使用脚本进行批量检测是否存在，以YAML格式编写简单的检测规则可以植入到一些漏扫工具中直接使用  
```
id: 漏洞名称

info:
  name: 详细漏洞名称
  author: 作者名
  severity: 等级
  description: |
    发生漏洞的组件或服务的简介
  reference:
    - none
  metadata:
    fofa-query: fofa语句
    veified: true
  tags: 备注

http:
  - method: 请求方式
    path:
      - "POC路径"

    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200

      - type: word
        part: body
        words:
          - '响应内容为xx'
        condition: and
```  
  
简单的python批量测试脚本  
```
import requests

file_path = "/root/output.txt"
url = "POC请求路径"
keyword = "响应内容为xx"

with open(file_path, "r") as file:
    lines = file.readlines()
    for line in lines:
        target_url = line.strip() + url  
        response = requests.get(target_url)
        if response.status_code == 200 and keyword in response.text:
            print(f"{target_url} 存在漏洞")
        else:
            print(f"{target_url} 漏洞不存在")
```  
  
  
当具备了day的POC及脚本后，应对符合的对应资产进行打点，以某站工具为例，可使用fofa进行批量收集，利用了fofa api进行收集导出等功能(  
漏洞工具包含)![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpNGMrZ4k2Mo2vvnqiaiccfOI3YFHA8TPEDkibZXSee74rFtTydhmKw0kPUWhdmiayeYwCptTWbibY3kVgQ/640?wx_fmt=png&from=appmsg "")  
  
  
对导出的数据加上POC写的规则脚本进行批量检测，最后存在漏洞的进行测试截图提交，基本步骤大致这些  
  
当然，中间可能会遇到很多问题比如在最后交洞环节中，可能会出现  
```
资产权重不符合
漏洞已被交
扯皮
```  
  
在某些平台可以看到一些人被挂着脚本小子的名称，且战绩频繁交洞，不同站点的同类型漏洞，基本上是刷分挖洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpNGMrZ4k2Mo2vvnqiaiccfOI3FbHXm4ts0BJhD6AQKbRmc7ngULQKyjxeeicvUrPhiaJOibq5hibAVNibqQA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpNGMrZ4k2Mo2vvnqiaiccfOI3CmW3gWmYcqXKniamL413m0Y2rXXBhiaFhicx9VEibude9oxNefbcHtqe9w/640?wx_fmt=png&from=appmsg "")  
  
以下附小白和菜狗利用nday进行刷分通过与不通过及自挖漏洞列表截图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpNGMrZ4k2Mo2vvnqiaiccfOI3haUTibfOXSk9CibS1SFDebQqcP9BIrUYQHNaxa7rdtyfmiceYe2IicQiaYQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpNGMrZ4k2Mo2vvnqiaiccfOI3XUwicEibiajqlwWoGb3c5YTNDDvuu5wMlrBJhYMo1KcK3huKjdRf3GLXg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icdGEWOnYLpNGMrZ4k2Mo2vvnqiaiccfOI3XLZetVeazVQibCibic9Uh46szj4qTv1sxMqeko5ZaGfic8VxlOKZZk5Shw/640?wx_fmt=png&from=appmsg "")  
  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
  
[xss研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487130&idx=1&sn=e20bb0ee083d058c74b5a806c8a581b3&chksm=e8a604f9dfd18defaeb9306b89226dd3a5b776ce4fc194a699a317b29a95efd2098f386d7adb&scene=21#wechat_redirect)  
  
  
[SSRF研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[2022年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
  
  
