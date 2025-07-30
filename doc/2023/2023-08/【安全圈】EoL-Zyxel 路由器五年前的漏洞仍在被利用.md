#  【安全圈】EoL-Zyxel 路由器五年前的漏洞仍在被利用   
 安全圈   2023-08-11 19:01  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/aBHpjnrGylgSxa9I02IBd3bgLEhwfJCeRibw3LEjMujeAhD2CvyiaVCZJVHGHODbkPx3pViaX0sAibZsDun6sicUzdQ/640?wx_fmt=jpeg "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
    
  
Bleeping Computer 网站消息，Gafgyt 恶意软件正积极利用 Zyxel P660HN-T1A 路由器五年前曝出的漏洞，每天发动数千次网络攻击活动。据悉，漏洞被追踪为 CVE-2017-18368，是路由器设备远程系统日志转发功能中存在的严重性未验证命令注入漏洞（CVSS v3：9.8），Zyxel 已于 2017 年修补了该漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljZvLUkmSfH9wcibyGRbPbEuruknKN4r3AhJB9AYsMJ49oPbkBgyZdxqVO28l08kVNtCnJgKaTtZIg/640?wx_fmt=jpeg "")  
  
早在 2019 年，Zyxel 就强调当时的新变种 Gafgyt 可能会利用该漏洞发动网络攻击，敦促仍在使用旧固件版本的用户尽快升级到最新版本，以保护其设备免遭接管。然而自 2023 年 7 月初以来，Fortinet 仍能够监测到平均每天 7100 次的攻击活动，且攻击数量持续至今。  
  
Fortinet 发布警报表示截止到 2023 年 8 月 7 日，FortiGuard 实验室持续监测到利用 CVE-2017-18368 漏洞的攻击活动，并在过去一个月中阻止了超过数千个独特 IPS 设备的攻击企图。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyljZvLUkmSfH9wcibyGRbPbEug6ibtibtkiaILpU27EKGvDP2hNtDr90uOmcZtwFYJnEHgYMudzgeCee4Q/640?wx_fmt=jpeg "1691721876_64d5a094b3c06f786d645.png!small")  
  
1691721876_64d5a094b3c06f786d645.png!small  
  
试图利用 Zyxel 路由器中的 CVE-2017-18368 漏洞（来源：Fortinet ）  
  
Fortinet 指出虽然目前还尚不清楚观察到的攻击活动中有哪一部分成功感染了设备，但自 7 月份以来，攻击活动一直保持稳定。值得一提的是，CISA 近期发布了 CVE-2017-18368 在野外被利用的情况，并将该漏洞添加到其已知利用漏洞目录中，要求联邦机构在 2023 年 8 月 28 日前修补 Zyxel 漏洞。  
  
为应对漏洞利用的爆发，Zyxel 又更新了安全公告，提醒客户 CVE-2017-18363 只影响运行 7.3.15.0 v001/3.40(ULM.0)b31 或更旧固件版本的设备，运行 2017 年为修复漏洞而推出的最新固件版本 3.40(BYF.11) 的 P660HN-T1A 路由器不受影响。  
  
此外，Zyxel 表示 P660HN-T1A 在几年前就已达到报废年限。因此，强烈建议用户将其更换为更新一代的产品，以获得最佳保护。  
  
路由器感染恶意软件常见迹象包括连接不稳定、设备过热、配置突然改变、反应迟钝、非典型网络流量、开放新端口和意外重启，如果怀疑自己的设备受到网络恶意软件的攻击，用户可以执行出厂重置，将设备固件更新到最新版本，更改默认的管理员用户凭据，并禁用远程管理面板，只从内部网络管理设备。  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljZvLUkmSfH9wcibyGRbPbEuhCHYiaz89LRfjYsomlLcf46yeE278Lwo0yuicVb5MEFXj240JsGFuDxw/640?wx_fmt=png "")  
[【安全圈】58集团被曝倒卖毕业生简历：单份报价30到2000元不等](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652041688&idx=1&sn=2d4999ea17049831dec14b1006adbcf3&chksm=f36fdd98c418548e001c541e5e757371b7b4b7106fc84c918d06a41a1d63a242e41f104135b2&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljZvLUkmSfH9wcibyGRbPbEuGNibEVibWPczRVz6bSkia7EjCbFhmQQVvicaGI2vot3JgZE2RdoRytHn5w/640?wx_fmt=png "")  
[【安全圈】2家商业银行因涉及数据治理问题 被罚超400万](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652041688&idx=2&sn=c7ece50a0b6ad4ae6519178ffe61df42&chksm=f36fdd98c418548e6b45be5c56d98e47bd5a20a57e678a699d09d74a258731a4e9f24418e907&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljZvLUkmSfH9wcibyGRbPbEuasU4fSMarQF7T1jk1drx0zZgVQibrziaYnb5icKJ6ubmTU3yr8WEe8VAg/640?wx_fmt=png "")  
[【安全圈】随着攻击者瞄准零日漏洞，勒索软件受害者的数量激增](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652041688&idx=3&sn=5a2dd4ffb7924c1e5051017a7b5ed70e&chksm=f36fdd98c418548e67c6867febe9a485cb42ace42e9c557aaaac9be55fe1b31ef48ad89a04d5&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGyljZvLUkmSfH9wcibyGRbPbEuRXv1efnkFcTwPZ7xyN3sicBiclDhBA3HaMC4sPMxmlwQk8GHe73voriaA/640?wx_fmt=png "")  
[【安全圈】英国选举委员会遭严重数据泄漏：数百万选民信息曝光](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652041688&idx=4&sn=f5054aaca82a06c5bc64035b04171af9&chksm=f36fdd98c418548ef2558a703f3c498f3fd7cf857993c5585a8266a1959cfea91dd95fea577f&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
