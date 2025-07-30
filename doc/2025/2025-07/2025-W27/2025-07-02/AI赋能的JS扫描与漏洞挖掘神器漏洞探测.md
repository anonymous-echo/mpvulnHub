> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247492919&idx=1&sn=efd3fdb2c449e02f690a3f69145b8532

#  AI赋能的JS扫描与漏洞挖掘神器|漏洞探测  
Rotor-Goddess  渗透安全HackTwo   2025-07-02 16:01  
  
0x01 工具介绍  
  
  
**面对传统工具速度慢、路径挖掘不全、分析繁琐等问题，一款名为“转子女神”的新型工具横空出世。它结合AI智能分析与自动化路径拼接，极大提升了信息收集效率，助力安全从业者快速锁定潜在漏洞。本文将深入解析“转子女神”的核心功能与使用技巧，带你领略这款工具如何在渗透测试中大放异彩，助你事半功倍！**  
  
**注意：**  
现在只对常读和星标的公众号才展示大图推送，建议大家把  
**渗透安全HackTwo**  
"**设为****星标⭐️**  
"  
**否****则可能就看不到了啦！**  
  
**下载地址在末尾#渗透安全HackTwo**  
  
0x02   
功能简介  
  
  
工具特点  
  
- **智能路径勘探**  
：通过精准的正则匹配，快速扫描并提取网页中的敏感路径和接口，自动拼接动态变量（如“/” + x + “/user/admin”），确保数据全面且准确。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7sU7sAATuLIUItyKNW2DKOj3DS1bXfzGN5RccodBZg2QRsFFEmuARd7Ra2M4Y2Mkg3sRJOJGoaoQ/640?wx_fmt=png&from=appmsg "")  
  
- **JS深度分析**  
：自动扫描JS文件，提取隐藏的API接口和参数，结合AI风险评估，挖掘潜在漏洞，如SQL注入、未授权访问等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7sU7sAATuLIUItyKNW2DKOmKV22Gr4fHib8pLEl8JhFsQMaYlTnHVfnZhggKU1LkXFTzImCsEkLkw/640?wx_fmt=png&from=appmsg "")  
  
- **高效爬虫与响应分析**  
：支持批量URL扫描，自动抓取响应状态、页面长度及ico hash值，并生成黑暗引擎查询语法，提升效率。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7sU7sAATuLIUItyKNW2DKOevgUf3TNIyYwWe2OqAJeHbEn7KVeyI8qCJrq4N7Rdy3EjJwSfPG4kQ/640?wx_fmt=png&from=appmsg "")  
- **灵活配置与扩展**  
：提供自定义拼接规则（--url）、证书绕过（--cer）、超时设置（--time）及请求头配置，适配复杂场景。  
  
- **AI驱动的漏洞提示**  
：通过AI对话机制，分析JS代码中的潜在风险，智能推荐漏洞测试方向，如ID fuzzing或鉴权问题。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7sU7sAATuLIUItyKNW2DKOc9191PAl2VicD0CoialNF9C4Liae30IrH0WJBhIy6vfbLKAvJiczMQjTrQ/640?wx_fmt=png&from=appmsg "")  
- **日志与结果管理**  
：自动记录扫描URL及参数，生成详细日志，方便后续分析与复查，输出结果直观清晰。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7sU7sAATuLIUItyKNW2DKOv0drq0zWSTRkWFqFaJlroUwRF00Nficjibc4lia8xcZlR3lMzMyMib4Yhg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7sU7sAATuLIUItyKNW2DKOacZESe5m9G4CLHVDto7tPZ3LSE96A76WV5ibqXl9BIlDb0o1npZCXwg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7sU7sAATuLIUItyKNW2DKOia5R4ia2Wn9YgmeiaW972BX2jKUNf4DjXnhC5rsgb2Pa40Qr6ogp3J0Fw/640?wx_fmt=png&from=appmsg "")  
- **批量处理与自动化**  
：支持批量URL文件扫描，结合AI自动化问话机制，减少手动操作，提升大规模测试效率。  
  
- **用户友好体验**  
：工具操作简单，扫描结果一目了然，几分钟即可完成复杂信息收集，适合挂后台运行，效率极高。  
  
  
  
  
0x03更新说明  

```
暂无
```

  
0x04 使用介绍  
  
📦用法  
  
**绕过证书验证（--cer）**  
  
 在URL后添加  

```
--cer
```

  
参数，即可绕过SSL证书验证，适用于目标站点证书不信任的场景。  
  
  
**示例**  
：  

```


```

  

```
roorgoddess --url https://example.com --cer
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7sU7sAATuLIUItyKNW2DKOdOV2NPg5KfQdraEwhCt2cChuCbmmOFm3gv3yGj5HPyeO6L35icLQK6A/640?wx_fmt=png&from=appmsg "")  
  
**自定义URL拼接（--url）**  
  
 对于需要特定拼接规则的站点（如  

```
/#/
```

  
路径），使用  

```
--url
```

  
参数自定义拼接逻辑，确保路径请求准确无误。  
  
  
**示例**  
：  

```
roorgoddess --url https://example.com/#/
```

  
工具将根据指定规则拼接路径并返回正确响应。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7sU7sAATuLIUItyKNW2DKO3LND1wMeiaXiaPNN9KZSvQMb4GC8X0E3G5bibiakfCBvnpYYozA3otKAWw/640?wx_fmt=png&from=appmsg "")  
  
**设置请求超时（--time）**  
  
 通过  

```
--time=x
```

  
设置请求超时时间（单位：秒），避免因目标站点响应过慢导致扫描卡顿。  
  
  
**示例**  
：  

```


```

  

```
roorgoddess --url https://example.com --time=5
```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7sU7sAATuLIUItyKNW2DKOvX4kiawKJfN82a76Tib1gubvAcQ3CfwbSWL9F6fJbr8UzNWerL9LWfVg/640?wx_fmt=png&from=appmsg "")  
  
**批量URL扫描（url_batch）**  
  
 支持批量扫描多个URL，只需将目标URL列表保存为  

```
.txt
```

  
文件，每行一个URL，然后运行工具即可自动扫描，无需逐个手动输入。  
  
  
**示例**  
：  
  
创建  

```
urls.txt
```

  
，内容如下：  

```
https://example1.com
https://example2.com
```

  
运行命令：  

```


```

  

```
roorgoddess --url_batch urls.txt
```

  
**自定义请求头（headers）**  
  
 支持自定义HTTP请求头，修改User-Agent、Cookie等信息，适配复杂场景。格式保持标准，仅需更新对应字段数据。  
  
  
**示例**  
：  

```


```

  

```
roorgoddess --url https://example.com --headers &#34;User-Agent: Mozilla/5.0&#34;
```

  
**AI问话设置**  
  
 工具支持自定义AI问话机制，用于优化JS代码分析和漏洞提示。用户可修改AI问话模板，但需注意避免破坏路径提取功能。若删除问话配置，工具会自动生成默认问话机制。  
  
  
**示例**  
：修改AI问话模板后，运行  

```


```

  

```
roorgoddess --url https://example.com
```

  
以应用新设置。  
### 使用注意事项  
- **操作简便**  
：所有参数直接在命令行中配置，工具会自动处理并输出结果，适合快速部署和后台运行。  
  
- **日志查看**  
：扫描结果和URL记录会自动保存至日志文件，方便后续分析。  
  
- **AI优化**  
：建议多尝试不同AI问话模板，以提升自动化分析效果，但谨慎修改核心提取函数。  
  
  
  
  
**0x05 内部VIP星球介绍-V1.4（福利）**  
  
        如果你想学习更多**渗透测试技术/应急溯源/免杀/挖洞赚取漏洞赏金/红队打点/HW漏洞库**  
欢迎加入我们**内部星球**  
可获得内部工具字典和享受内部资源和  
内部交流群，**每1-2天更新1day/0day漏洞刷分上分****(2025POC更新至4000+)**  
**，**  
包含网上一些**付费****工具及BurpSuite自动化漏****洞探测插件，AI代审工具等等**  
。shadon\Quake\  
Fofa高级会员，CTFShow等各种账号会员共享。详情直接点击下方链接进入了解，觉得价格高的师傅可后台回复"   
**星球**  
 "有优惠券名额有限先到先得！全网资源  
最新  
最丰富！**（🤙截止目前已有1900+多位师傅选择加入❗️早加入早享受）**  
  
****  
  
**👉****点击了解加入-->>内部VIP知识星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
****  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250703获取下载**  
  
# 最后必看-免责声明  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
# 往期推荐  
  
  
**1.内部VIP知识星球福利介绍V1.4（AI自动化工具）**  
  
**2.CS4.8-CobaltStrike4.8汉化+插件版**  
  
**3.最新BurpSuite2025.2.1专业版（新增AI模块）**  
  
**4. 最新xray1.9.11高级版下载Windows/Linux**  
  
**5. 最新HCL AppScan Standard**  
  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
[全面资产收集流程及方法解析 万字长文窥探信息收集|挖洞技巧](https://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247491574&idx=1&sn=48d865c82a228bd135a035419c765e94&scene=21#wechat_redirect)  
  
  
