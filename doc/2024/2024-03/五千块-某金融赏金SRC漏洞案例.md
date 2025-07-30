#  五千块-某金融赏金SRC漏洞案例   
 迪哥讲事   2024-03-16 22:30  
  
## 前言  
  
  
近年来，金融SRC一直是小伙伴们觉得难啃的骨头，由于防护设备比较健全，不能直接使用xray、goby等工具进行梭哈，但是SRC的预算还是每年都在增长的，我们总不能让甲方爸爸花不出去钱把，今天分享一个五千块的金融SRC真实案例，希望大家能和我一样不用体力挖洞。  
  
## JWT跨服务中继攻击案例  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/byXNVsHKA4qgaus8zY6Dcjf4Gg8mUX77xvWlWdLfZr81ZBCgsHKfeWGKp5QmvdWU8vzzp8dcceaXB874wM0O6g/640?wx_fmt=png "")  
  
对目标信息收集后，某安信hengter上拿下来资产，  
尝试几  
次  
弱  
口令  
还是无法登录  
后台。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/byXNVsHKA4qgaus8zY6Dcjf4Gg8mUX77eETvUAMQ6d3LXcj653RfdbqtIIP5pru5LCiaLu57qjOWjicewqCxibpicw/640?wx_fmt=png "")  
  
这系统总感觉有一丝眼熟，但是还需要稍微判断一下，既然眼熟就复制一下后端接口查询github。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/byXNVsHKA4qgaus8zY6Dcjf4Gg8mUX77icptcic6xXvf9SMYcQDPbAtUsK87niaPlND3HwXSPj7uc9eLy4helTa7g/640?wx_fmt=png "")  
  
github搜索code效果不太理想。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/byXNVsHKA4qgaus8zY6Dcjf4Gg8mUX77uNQndVtgWuq8EzhO93jcEk7IC9uEId4xQqvEDSkjKicd9qV6Nud3t5A/640?wx_fmt=png "")  
  
尝试搜索title特征，找到开源企业开发平台。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/byXNVsHKA4qgaus8zY6Dcjf4Gg8mUX77GptUlNgHdA3NohdicwMADNh2XGiabqrQA5ES1nuvtn2yuaMrQjw2sqyQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/byXNVsHKA4qgaus8zY6Dcjf4Gg8mUX77o8Ksn3P4e8XdibEtHP9PgmWxeMWAwslzxpxMvMdFicemlH5ov8VWqKCw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/byXNVsHKA4qgaus8zY6Dcjf4Gg8mUX7786t8WtqIAIjXFQkXlyocDxP16NF9Pf8xIJdbesBBd9nonWfyxv44FA/640?wx_fmt=png "")  
  
既然这篇文章是教大家赚钱的，那代码审计这种体力活，我肯定是干不出来的。这么成熟的系统几十万行看下来脑子瘀血也不一定憋出一个漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/byXNVsHKA4qgaus8zY6Dcjf4Gg8mUX77yt9DkWAWEZXPKtpot9nH6xsMco9ZNb3rrBjVLvvWOj2ibOdrWibLiaH0A/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/W9sKSsP9X9G0iba5gLc15pjDIKjHZb3HnqkBVhbEMOia2LLD1icycAUozM8OoCfQbQkkqVY5scHChY2fkHial6ERoA/640?wx_fmt=png "")  
  
跨服务中继攻击拿下网站后台管理员权限  
  
先试一下Readme提供的默认密码admin/admin登录目标网站，登录失败。  
  
直接用默认密码登录开源测试环境管理员账号，  
```
https://saber.bladex.vip/#/login
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/byXNVsHKA4qgaus8zY6Dcjf4Gg8mUX77uOWMWW3rQrZS8LTgthLBchCSibUTIpziaKQicgueOeva613fjQKmdFtkg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/byXNVsHKA4qgaus8zY6Dcjf4Gg8mUX77hpQzW35jzQndeXKsTn2umcw885Rx4sicn7aGv8tGhvKl6qwcZHwsGHQ/640?wx_fmt=png "")  
  
复制测试环境管理员登录返回Auth认证通过数据包，对目标系统管理员账户进行替换。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/byXNVsHKA4qgaus8zY6Dcjf4Gg8mUX77mz03ALopLamxxfCmbG1MWxssWlKEUeHgYHujVq9ttT9ibnXFYGfsic7w/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/byXNVsHKA4qgaus8zY6Dcjf4Gg8mUX77J9Vkqqk1Qx6icDibWXVp2tgNXrAsqkGkwhtTyicxt4hnic4teErERWm91w/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/byXNVsHKA4qgaus8zY6Dcjf4Gg8mUX77KuXibwDza6jjyS5ZVVTP6vg8WEJG6lNmibs5VJG2EfUeAOPV1QEU9zNg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/W9sKSsP9X9G0iba5gLc15pjDIKjHZb3HnqkBVhbEMOia2LLD1icycAUozM8OoCfQbQkkqVY5scHChY2fkHial6ERoA/640?wx_fmt=png "")  
  
总结  
  
实战过程中遇到很多开源系统，可以通过此思路进行默认密钥尝试。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/byXNVsHKA4qgaus8zY6Dcjf4Gg8mUX77Ow2hDEuKXJPo0HApy36hzmic3DDThX00ckTibziciaufrtUq9LjmOkDbNw/640?wx_fmt=png "")  
  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款前面有同学问我有没优惠券，这里发放100张100元的优惠券,用完今年不再发放  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj7N5nMaJbtnMPVw96ZcVbWfp6SGDicUaGZyrWOM67xP8Ot3ftyqOybMqbj1005WvMNbDJO0hOWkCaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
