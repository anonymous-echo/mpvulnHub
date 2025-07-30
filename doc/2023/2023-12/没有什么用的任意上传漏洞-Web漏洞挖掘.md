#  没有什么用的任意上传漏洞-Web漏洞挖掘   
原创 漏洞挖掘  渗透安全HackTwo   2023-12-10 17:31  
  
#   
# 0x00 起因  
#          
  
中午临近吃饭的日子，小冰突然发了二条微信  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7aZYqL4NU2bEnmoJS5FIK5iboM7sIMGic19P5x4MfXHDAmiaHuNeVJ8EProwq2tnLyZadvFfnCrN4icA/640?wx_fmt=png&from=appmsg "")  
  
    新社区上了还是很期待的，这说明有事情可以搞。抱着少一事，不如多一事的想法。我们就可以开始测试了。  
  
**文章末尾领取资料**  
# 0x01 前言  
  
          
  
         
 在测试的过程中发现了是阿里的oss 可以初步猜测，开发小哥应该是错误的认为文件托管在oss就可以忽略站内的上传功能存在的安全隐患。  
  
         
 先说明这是一篇看起来好像很厉害，实际并没有没有没有没有没有那么大危害的漏洞，开发为了产品跨域时设置了set-cookie: *.test.aliyun.com 攻击者就可以拿着img-oss.test.aliyun.com/xxx.html 找对应的场景发给公司的员工,打开后cookie可能就被“借”走做一些羞羞的事情。  
# 0x02 漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7aZYqL4NU2bEnmoJS5FIK5Ciciav3OYTOuJtiaA4ibOATOOyLDd8zv9icQfyiaNANmVy52lERx3Gwdc2Yw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7aZYqL4NU2bEnmoJS5FIK5lgr4ibETKRicUOLkTt2XfnnqqhXPmyG5mZKfl1icAWxDXicDIUfuXDp62g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7aZYqL4NU2bEnmoJS5FIK5fthiaQZOrRabxswl7T86xA5YKkFwZCdKCQm29iakFnpbec42C2gOZt9A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7aZYqL4NU2bEnmoJS5FIK5Oy0xeeAKrib1boaAA6exiczSD424h5oBINgqsSJulQLE9vxFc5f62ztQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7aZYqL4NU2bEnmoJS5FIK5nibEYNZYPiasK9QAGNtVpjI5liaw93OTbP5aIGibVZRwEeRF4Y1lCicP7jw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7aZYqL4NU2bEnmoJS5FIK5bfaYGwdRLEibBk1GGtJGPMku6YwIicRiaicff5x4AiawNxM49j6eByugYeg/640?wx_fmt=png&from=appmsg "")  
  
  
访问HTML地址时  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7aZYqL4NU2bEnmoJS5FIK5EWc7O2mV8CBujib34R5oIGKQlibSKH1wm318lQrhwlWYGfPy5rm7364w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7aZYqL4NU2bEnmoJS5FIK5RplV2lxuRDeuDN3icT7YFA4bU6pQWJsZUqgBXvCPtLlaegdLgqo5CRQ/640?wx_fmt=png&from=appmsg "")  
  
获取Cookie  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7aZYqL4NU2bEnmoJS5FIK5ZJ4Pv93SwZNCn96jFibjYmYyw16CibCZcYGurGMNHyiaxypDSJjib925VA/640?wx_fmt=png&from=appmsg "")  
  
# 0x03 解决方案  
  
后端校验文件后缀类型  
,  
我的建议最好设置白名单  
,  
而不是黑名单  
# 0x04 彩蛋-SSI服务器端指令  
```
shtml用的是SSI指令，SSI是为WEB服务器提供的一套命令，这些命令只要直接嵌入到HTML文档的注释内容之中即可。
<!--#include file="/home/www/xxxxx/index.html"--> //可以用来读文件
<!--#exec cmd="ifconfig"--> //可以用来执行命令
<!--#include virtual="/includes/header.html" --> //也是读文件 与FILE不同他支持绝对路径和../来跳转到父目录 而file只能读取当前目录下的
```  
# 0x05最后  
  
需要加入知识星球的可以后台回复“星球”，里面可以学习更多漏洞相关的知识。  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**关注领取资源：**  
  
  
回复“app" 获取  app渗透和app抓包教程  
  
  
回复“渗透字典" 获取 针对一些字典重新划分处理，收集了几个密码管理字典生成器用来扩展更多字典的仓库。  
  
  
回复“书籍" 获取 网络安全相关经典书籍电子版pdf  
  
  
**压缩包解压密码：HackTwo**  
  
# 最后必看  
  
  
本工具仅面向合法授权的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。  
  
  
为避免被恶意使用，本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。  
  
  
在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标进行扫描。  
  
  
如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。  
  
  
本工具来源于网络，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
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
  
  
