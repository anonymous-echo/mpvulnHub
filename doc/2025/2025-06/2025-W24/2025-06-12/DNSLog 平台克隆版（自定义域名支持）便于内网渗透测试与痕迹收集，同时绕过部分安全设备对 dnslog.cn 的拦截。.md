#  DNSLog 平台克隆版（自定义域名支持）便于内网渗透测试与痕迹收集，同时绕过部分安全设备对 dnslog.cn 的拦截。  
Secur1ty0  夜组安全   2025-06-12 00:01  
  
免责声明  
  
由于传播、利用本公众号夜组安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号夜组安全及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
**所有工具安全性自测！！！VX：**  
**baobeiaini_ya**  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把  
**夜组安全**  
“**设为星标**  
”，  
否则可能就看不到了啦！  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WrOMH4AFgkSfEFMOvvFuVKmDYdQjwJ9ekMm4jiasmWhBicHJngFY1USGOZfd3Xg4k3iamUOT5DcodvA/640?wx_fmt=png&from=appmsg "")  
  
## 工具介绍  
  
🧪 DNSLog 平台克隆版（自定义域名支持）  
  
本项目是对 dnslog.cn 平台的简洁克隆，支持自定义域名部署，便于内网渗透测试与痕迹收集，同时绕过部分安全设备对 dnslog.cn  
 的拦截。  
>   
> ✅ 适合集成在各类漏洞验证框架或红队测试中使用  
  
## 🚀 特性  
- 支持临时 DNS 记录收集  
  
- 支持 SQLite 存储记录  
  
- 支持前端 DNS 查询追踪  
  
- 支持自定义域名后缀  
  
- 启动即用，无需依赖复杂后端服务  
  
## 🌐 域名配置说明  
1. 新增A记录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2X5ibtZvIIPS7pibiaTKOLkZJ07YpKn9JQMnvL2HNKgYeGt8slUaTrxpQr4pOsALfvqR9NibSwZzxjiauw/640?wx_fmt=png&from=appmsg "")  
1. 自定义dns服务器  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2X5ibtZvIIPS7pibiaTKOLkZJ0n9bJice2PP2UtPxMuOqw0GemtzWGAKhiaMkA48YkQJXu2FAkE7XYezCA/640?wx_fmt=png&from=appmsg "")  
1. 修改dns服务器为自定义服务器  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2X5ibtZvIIPS7pibiaTKOLkZJ0Iq15EDIptJWouDTBMyPnTMpBxnRdnycJBY1CwdQGRSgphbP9dicukOw/640?wx_fmt=png&from=appmsg "")  
## 📦 启动 DNS 服务  
1. 编辑 db.php  
，设置你绑定的域名后缀：  
  
```
// SQLite 数据库文件路径$db_file = '../data/domain.db';// Dnslog平台域名$domain_suffix = "example.cn";
```  
1. 启动 DNS 服务：  
  
```
php dnsServer.php &
```  
1. 访问 Web 页面：  
  
```
http://<your-server-ip>/index.php
```  
## 📝 更新日志（Changelog）  
  
<table><thead><tr><th style="color: rgb(66, 75, 93);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">日期</span></section></th><th style="color: rgb(66, 75, 93);font-size: 14px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">更新内容</span></section></th></tr></thead><tbody><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">2025-06-06</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">✅ 优化 SQLite 写入机制，避免并发冲突</span></section></td></tr><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf=""><br/></span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">✅ 支持 DNS 查询记录展示最近 5 条</span></section></td></tr><tr style="color: rgb(66, 75, 93);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf=""><br/></span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">✅ 增加 SQLite 文件备份与数据库清理机制，减轻读写压力</span></section></td></tr></tbody></table>  
  
  
## 工具获取  
  
  
  
点击关注下方名片  
进入公众号  
  
回复关键字【  
250612  
】获取  
下载链接  
  
  
## 往期精彩  
  
  
往期推荐  
  
[社会工程学密码生成器APP，利用个人信息生成密码的工具](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494507&idx=1&sn=d31a49fbc2febe095fb78304a35dbc6d&chksm=c36baf93f41c2685aafd12b6b2ff239b1b8ba5b43b8af5e98a3e2bd7280d7edc825c59d68203&scene=21#wechat_redirect)  
  
  
[后渗透信息/密码/凭证收集工具](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494483&idx=1&sn=8d58bd631fc216aa23299dc03216381f&chksm=c36bafabf41c26bdcb7b7048a5a8144105cc2290c459d0329273221b74eb76d444fa87347f50&scene=21#wechat_redirect)  
  
  
[Mitmproxy GUI用于解决渗透测试加解密难题，让你的burp像测试明文这么简单 更新v1.0.2](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494478&idx=1&sn=77dff746a51379718bcb3bf80e9219e2&chksm=c36bafb6f41c26a0fab3c14abdd7ca202823a23d0ed0ef7e198f70893b183d9dc85959ec6588&scene=21#wechat_redirect)  
  
  
[phpmyadmin 弱口令探测工具](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494477&idx=1&sn=acecaa45e35b79c1ae31bcbb181a3eba&chksm=c36bafb5f41c26a345a4417ee5cfa9f87f419205ab400654f8826d22552e99729ae7c085f10f&scene=21#wechat_redirect)  
  
  
[兄弟们怎么评价？《我还是那一句话 系统运行好好的，不要搞破坏，做点正事，你40岁后还搞这些吗？》](http://mp.weixin.qq.com/s?__biz=Mzk0ODM0NDIxNQ==&mid=2247494449&idx=1&sn=38e483f3a621a4f85b68e8f51d881654&chksm=c36bafc9f41c26df4aa63ffb634db589754a19a43aa2d9d64116f6cd69907aa983a428a473a2&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAmMqjhMehrtxRQaYnbrvafmXHe0AwWLr2mdZxcg9wia7gVTfBbpfT6kR2xkjzsZ6bTTu5YCbytuoshPcddfsNg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&random=0.8399406679299557&tp=webp "")  
  
