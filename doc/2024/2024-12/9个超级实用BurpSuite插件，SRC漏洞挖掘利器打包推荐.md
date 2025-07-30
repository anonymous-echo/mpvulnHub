#  9个超级实用BurpSuite插件，SRC漏洞挖掘利器打包推荐   
Mstir  星悦安全   2024-12-05 04:52  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
  
  
part 01  
  
一、前言  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DW3j9hNYCMJVseXY6McdprBe3flnjV1nkg9wLWFDt7Eheic43k4VD2AdbuVRRxuXrfNmjAeicCL4YFq8NbSx1kDg/640?&wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
BETTER   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CKzJTYjhW8oibRgUu6aia0OJRr2cjkUVdf8kVR2uaibLJSFVbVa1kDmlLQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
工具打包下载地址在文末，不想看介绍直接拉到底下查看即可  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fHwBpeeZQkz05RHr4N0taQB5vTwLfcM2e4gIOLDc6cXZicKkGWQLWkAF6Ob28ETm4iaRZKovaNGXnUX8r7rJ3ib3A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jW0cyQc5LAE8XqrBDVuOHhCCXiaCH0PCdQaG4MiaA4flIcPy6RCI1CeelQqc6zficMAUCibrgINN3Gib1bE3r8TP8AA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
前段时间自己在做项目的时候，需要用到一些漏洞扫描工具，以及一些被动扫描的工具，其中BurpSuite中的几个插件起到了关键性的作用，其实在实际攻防演练，或者渗透中一些漏洞出现的概率还是挺高的，比如Shiro反序列化，fastjson反序列化，还有一些逻辑漏洞，下述的一些插件可以方便地进行检测.  
  
  
于是我和团队里的师傅，一起整理了这几个BurpSuite插件，一共有以下几个插件.  
1. BypassPro - 权限绕过自动化bypass的burpsuite插件  
  
1. burpFakeIP - 用于伪造ip地址进行测试的Burp Suite插件  
  
1. HaE 3.0 - 实现对HTTP消息（包含WebSocket）精细化的标记和提取  
  
1. OneScan - 是用于递归目录扫描的BurpSuite插件  
  
1. ShiroScan - 主要用于框架、无dnslog key检测  
  
1. SpringSpider - Spring Actuator端点的BurpSuite被动扫描插件  
  
1. ThinkphpGUI - Thinkphp漏洞利用工具，支持各版本TP漏洞检测  
  
1. Turbo-Intruder - 用于发送大量 HTTP 请求并分析结果  
  
1. Xia_Yue - Xia_Yue（瞎越）主要用于测试越权、未授权  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X4K2loV6ggicQLkSRWXjR0vcQZibMwOdOqDQubJzjpEfdgTnxMdIrgrKvyBuxr6BWYJfCOxOIlibibWiaXiaT8rP3H5Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
part 02  
  
二、工具介绍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DW3j9hNYCMJVseXY6McdprBe3flnjV1nkg9wLWFDt7Eheic43k4VD2AdbuVRRxuXrfNmjAeicCL4YFq8NbSx1kDg/640?&wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
BETTER   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jnib104Mh5XHzc7zhusNyJItFgK94QBbzz7ncbtJV7FCVtIKxIwOloF0f0z2PB01m0iaLUTceO736f7fJL6UETCg/640?from=appmsg&wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
SIMPLE STYLE  
  
1.BypassPro  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fHwBpeeZQkz05RHr4N0taQB5vTwLfcM2e4gIOLDc6cXZicKkGWQLWkAF6Ob28ETm4iaRZKovaNGXnUX8r7rJ3ib3A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jW0cyQc5LAE8XqrBDVuOHhCCXiaCH0PCdQaG4MiaA4flIcPy6RCI1CeelQqc6zficMAUCibrgINN3Gib1bE3r8TP8AA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
功能：权限绕过的自动化bypass的burpsuite插件。此项目是基于p0desta师傅的项目 AutoBypass403-BurpSuite 进行二开的。用于权限绕过，403bypass等的自动化bypass的Burpsuite插件。感谢p0desta师傅的开源，本二开项目已经过p0desta师傅本人允许开源。  
  
  
被动扫描：勾选上之后，proxy 流量中出现403 301 404 302 的时候去自动bypass 主动扫描：取消勾选之后，可以在proxy 流量中选择一些右键发送到BypassPro 去自动fuzz 当状态码是200，415，405则会进行回显，页面相似度80%以下进行回显  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CXoCNxvJjnMiaUVgNYiaxhibicibvqibHNRPpOoBXOoGzghPfBicWIDqTWKCXA/640?wx_fmt=png&from=appmsg "")  
  
主动扫描：右键发送  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CBazo2Nk3t18AFqvst8GZsSSoRpFU713MDu6GcKSoEiaoTiaUlgcOKXIg/640?wx_fmt=png&from=appmsg "")  
  
注意事项：  
该工具会一定程度上触发waf,所以当目标站点有waf 请关闭被动扫描。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X4K2loV6ggicQLkSRWXjR0vcQZibMwOdOqDQubJzjpEfdgTnxMdIrgrKvyBuxr6BWYJfCOxOIlibibWiaXiaT8rP3H5Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jnib104Mh5XHzc7zhusNyJItFgK94QBbzz7ncbtJV7FCVtIKxIwOloF0f0z2PB01m0iaLUTceO736f7fJL6UETCg/640?from=appmsg&wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
SIMPLE STYLE  
  
2.burpFakeIP  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fHwBpeeZQkz05RHr4N0taQB5vTwLfcM2e4gIOLDc6cXZicKkGWQLWkAF6Ob28ETm4iaRZKovaNGXnUX8r7rJ3ib3A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jW0cyQc5LAE8XqrBDVuOHhCCXiaCH0PCdQaG4MiaA4flIcPy6RCI1CeelQqc6zficMAUCibrgINN3Gib1bE3r8TP8AA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
### 0x01 伪造指定ip  
  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
‍  
  
‍在Repeater模块右键选择fakeIp菜单,然后点击inputIP功能,然后输入指定的ip：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CibtrlZGp38STJV2D9jiawoQeRkRWMNKUibFmkCg5cwPB3ibsIpjSO7iafZA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CTY6Ek9ZJA2ZFicSTMH66shkggRiclnCsgP0UpTqITpKRxyU4TgdWiclLQ/640?wx_fmt=png&from=appmsg "")  
  
程序会自动添加所有可伪造得字段到请求头中。  
### 0x02 伪造本地ip  
  
  
在Repeater模块右键选择fakeIp菜单,然后点击127.0.0.1功能：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CBbvN4e2fibNNdicOjrS8JAc7Q5YoegoZEOibHnMy6Vic3MqezlQxM2XXhQ/640?wx_fmt=png&from=appmsg "")  
### 0x03 伪造随机ip  
  
  
在Repeater模块右键选择fakeIp菜单,然后点击randomIP功能：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CsDiceCq2eeq74DKW3RECENcL0Uz9vr4CRg7skgWjsxgPe0ZWicVcmVsA/640?wx_fmt=png&from=appmsg "")  
### 0x04 随机ip爆破  
  
  
伪造随机ip爆破是本插件最核心的功能。  
  
将数据包发送到Intruder模块,在Positions中切换Attack type为Pitchfork模式,选择好有效的伪造字段,以及需要爆破的字段:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CsXNGZTjlRYcc3uCpicIp4hXhY6cwWo2LS6hHDb182A9J1LbyibV0qiaBw/640?wx_fmt=png&from=appmsg "")  
  
按照箭头顺序将Payload来源设置为Extensin-generated,并设置负载伪fakeIpPayloads,然后设置第二个变量。 ![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CewvOE8f4yw5RQnqGgWpJMN3gdw2yR5LBrLweWuagFe1zUCZq2Iicygg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0Cvc8tia5gagiajl70CTWQ7M2ZDmJ6cSzJibaoeIXTVfg0PE7GSsXTicWSFA/640?wx_fmt=png&from=appmsg "")  
  
点击Start attack开始爆破.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CSAd26bBXH2aNMmgCLAibwzmf1pZicBiaDtnohBPSyKlOpIW8dQEibTU04A/640?wx_fmt=png&from=appmsg "")  
  
如上图,实现每次爆破都使用不同的伪ip进行,避免被ban  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X4K2loV6ggicQLkSRWXjR0vcQZibMwOdOqDQubJzjpEfdgTnxMdIrgrKvyBuxr6BWYJfCOxOIlibibWiaXiaT8rP3H5Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jnib104Mh5XHzc7zhusNyJItFgK94QBbzz7ncbtJV7FCVtIKxIwOloF0f0z2PB01m0iaLUTceO736f7fJL6UETCg/640?from=appmsg&wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
SIMPLE STYLE  
  
3.HaE  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fHwBpeeZQkz05RHr4N0taQB5vTwLfcM2e4gIOLDc6cXZicKkGWQLWkAF6Ob28ETm4iaRZKovaNGXnUX8r7rJ3ib3A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jW0cyQc5LAE8XqrBDVuOHhCCXiaCH0PCdQaG4MiaA4flIcPy6RCI1CeelQqc6zficMAUCibrgINN3Gib1bE3r8TP8AA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
1.功能  
：通过对HTTP报文的颜色高亮、注释和提取，帮助使用者获取有意义的信息，  
聚焦高价值报文  
。  
  
**2.界面：清晰可视的界面设计，以及简洁的界面交互，帮助使用者更轻松的了解和配置项目，避免多按钮式的复杂体验。**  
  
**3.**  
查询**：将HTTP报文的高亮、注释和提取到的相关信息**  
集中在一个数据面板**，可以一键查询、提取信息，从而提高测试和梳理效率。**  
  
4.  
算法**：内置高亮颜色的升级算法，当出现相同颜色时**  
会自动向上升级一个颜色**进行标记，**  
避免**屠龙者终成恶龙**  
场景  
。  
  
**5.**  
管理**：支持对数据的一键导出、导入，以**  
自定义.hae文件的方式**进行项目数据存储，**  
便于存储和共享项目数据**。**  
  
**6.**  
实战**：官方规则库和规则字段作用功能，都是**  
基于实战化场景总结输出**的，**  
以此提高数据的有效性、精准性发现**。**  
  
**7.智能：融入人工智能（AI）大模型API，对匹配的数据进行优化处理，提高数据式漏洞挖掘效率。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CySsVbwoxOjIs3zm8812l36ibyGbYdqolxeicW3VC0WJDydT8p1OHsTlQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CbSHqMhaNDxdafCe5U9iaAZ9wBpybscmSZx8bYtBv6F0DaFjys6IXEUw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0ChOPZK8osK7HLfqMoGuRj3m0lyibFPQbxJxZuwL3gCE56j3XPse725EQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0Cs2icnDd5GLf1JCcv79ZdwnqgxN12GaticxAnBJnsqSwDOhPMwgENFlxA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X4K2loV6ggicQLkSRWXjR0vcQZibMwOdOqDQubJzjpEfdgTnxMdIrgrKvyBuxr6BWYJfCOxOIlibibWiaXiaT8rP3H5Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jnib104Mh5XHzc7zhusNyJItFgK94QBbzz7ncbtJV7FCVtIKxIwOloF0f0z2PB01m0iaLUTceO736f7fJL6UETCg/640?from=appmsg&wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
SIMPLE STYLE  
  
4.OneScan  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fHwBpeeZQkz05RHr4N0taQB5vTwLfcM2e4gIOLDc6cXZicKkGWQLWkAF6Ob28ETm4iaRZKovaNGXnUX8r7rJ3ib3A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jW0cyQc5LAE8XqrBDVuOHhCCXiaCH0PCdQaG4MiaA4flIcPy6RCI1CeelQqc6zficMAUCibrgINN3Gib1bE3r8TP8AA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
主动扫描  
  
  
可以从BurpSuite其它位置发送到OneScan主动扫描  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CvaG6sOS57ia4zg2xfPcCOLSvcLo5dfdwcciaSAv26W0CkzwI5u6zibuSQ/640?wx_fmt=png&from=appmsg "")  
  
可以使用已配置的字典发送到OneScan主动扫描（存在1个以上的字典配置才会出现该菜单）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0C71zXicrrWYCjrZiauEaTEHxUnMwvIzDibxHd7lBcb7316RT0JOnpmmS3g/640?wx_fmt=png&from=appmsg "")  
### 辅助面板  
  
  
提取请求和响应包中  
JSON格式的字段，插件1.0.0版本新增Fingerprint指纹信息展示  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CVzXmQls6DkwRTkVfXqJxuWWrkocrTypibkHiaB1Yib5r2WJriaibgjOUGTQ/640?wx_fmt=png&from=appmsg "")  
### 动态变量  
  
  
目前支持的动态变量如下（以目标：)  
```
http://www.xxxxxx.com:81/path/to/index.html 为例，日期和时间以：2030-08-09 07:08:09 为例）：

{{host}} - 请求头中的Host（格式：www.xxxxxx.com:81）
{{domain}} - 请求头中不包含端口号的Host（格式：www.xxxxxx.com）
{{domain.main}} - 主域名（格式：xxxxxx.com；如果是IP地址或无效格式，会自动跳过这条Payload）
{{domain.name}} - 主域名的名称（格式：xxxxxx；如果是IP地址或无效格式，会自动跳过这条Payload）
{{protocol}} - 请求头中的协议（格式：http）
{{timestamp}} - Unix时间戳（单位：秒）
{{random.ip}} - 随机IPv4值
{{random.local-ip}} - 随机内网IPv4值
{{random.ua}} - 随机UserAgent值，随机源可配置
{{subdomain}} - 子域名动态变量（格式：www；只有主域名时：`xxxxxx.com` => `xxxxxx`）
{{webroot}} - 一级目录动态变量（格式：path；不存在一级目录时，会自动跳过这条Payload）
{{date.yyyy}} - 日期：年（格式：2030）
{{date.MM}} - 日期：月（格式：08）
{{date.dd}} - 日期：日（格式：09）
{{date.yy}} - 日期：年（格式：30）
{{date.M}} - 日期：月（格式：8）
{{date.d}} - 日期：日（格式：9）
{{time.HH}} - 时间：小时（格式：07）
{{time.mm}} - 时间：分钟（格式：08）
{{time.ss}} - 时间：秒（格式：09）
{{time.H}} - 时间：小时（格式：7）
{{time.m}} - 时间：分钟（格式：8）
{{time.s}} - 时间：秒（格式：9）
```  
  
Databoard数据看板  
  
  
插件数据看板说明如下  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CTtEvQmmhR6UeNbTCfetxLae0FbOjvmf73ROTMa7uNBn66RyNHCpHSg/640?wx_fmt=png&from=appmsg "")  
- Listen Proxy Message 开关被动扫描（默认禁用），代理的请求包都会经过OneScan（建议配置白名单后启用）  
  
- Exclude Header 开关排除请求头（默认禁用），根据 Request -> Exclude header 里的配置，排除请求头中对应的值  
  
- Replace Header 开关请求头替换（默认启用），使用 Request -> Header 中配置的请求头请求数据  
  
- DirScan 开关递归扫描（默认启用），对目标进行递归扫描  
  
- Payload Processing 开关 Payload Processing 功能（默认启用）  
  
- Filter 设置数据过滤规则  
  
- Import url 导入 Url 目标进行扫描  
  
- Stop 停止正在扫描的任务  
  
- Actions 操作菜单（列表鼠标右键菜单的所有功能）  
  
#### 过滤规则配置  
  
  
点击主面板的Filter按钮，打开设置过滤规则对话框（插件0.5.2版本新增功能）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0Cc7CHuaR2DiaR21ohFgaDg1wStJe3ToQ1BcppT8gFxarBsqVTK3Hrl7w/640?wx_fmt=png&from=appmsg "")  
- Select column 选择要过滤的列  
  
- Add filter 为选中列添加过滤条件  
  
- Clear 清除选中列的所有过滤规则  
  
- Reset 重置所有过滤规则  
  
- Cancel 取消本次的所有变更  
  
- OK 使配置的规则生效  
  
#### 临时过滤规则  
  
  
通过右键菜单，点击“临时过滤选中数据”添加临时过滤规则：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CibQazh4WCkmANjEibbQmjeTP9u07pyHCL9icW79TM0QRkwhgD1nllyibBQ/640?wx_fmt=png&from=appmsg "")  
  
只支持临时添加相同值的过滤（复杂的规则，请点击 Filter 按钮处理），例如选中了 Status 是 400 和 503 的两条数据，生成的临时过滤规则示例如下：  
```
Status != 400 && Status != 503
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X4K2loV6ggicQLkSRWXjR0vcQZibMwOdOqDQubJzjpEfdgTnxMdIrgrKvyBuxr6BWYJfCOxOIlibibWiaXiaT8rP3H5Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jnib104Mh5XHzc7zhusNyJItFgK94QBbzz7ncbtJV7FCVtIKxIwOloF0f0z2PB01m0iaLUTceO736f7fJL6UETCg/640?from=appmsg&wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
SIMPLE STYLE  
  
5.ShiroScan  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fHwBpeeZQkz05RHr4N0taQB5vTwLfcM2e4gIOLDc6cXZicKkGWQLWkAF6Ob28ETm4iaRZKovaNGXnUX8r7rJ3ib3A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jW0cyQc5LAE8XqrBDVuOHhCCXiaCH0PCdQaG4MiaA4flIcPy6RCI1CeelQqc6zficMAUCibrgINN3Gib1bE3r8TP8AA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
将ShiroScan.jar导入burp，该插件是被动扫描，扫描成功的结果会输出到图形界面中  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0Cqyd8M7IFaPpibFRj2awQdlCWGibOzHX8ibFictzfS305WC9t6kf0nADx7Q/640?wx_fmt=png&from=appmsg "")  
  
同时在burp的issue里也会输出相应的详情信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CiaUPxBwBpeaXv9BtJ1ovdbGxOpKNncAGq4cEZevT5mvvCzibDxZs7GlQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X4K2loV6ggicQLkSRWXjR0vcQZibMwOdOqDQubJzjpEfdgTnxMdIrgrKvyBuxr6BWYJfCOxOIlibibWiaXiaT8rP3H5Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jnib104Mh5XHzc7zhusNyJItFgK94QBbzz7ncbtJV7FCVtIKxIwOloF0f0z2PB01m0iaLUTceO736f7fJL6UETCg/640?from=appmsg&wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
SIMPLE STYLE  
  
6.SpringSpider  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fHwBpeeZQkz05RHr4N0taQB5vTwLfcM2e4gIOLDc6cXZicKkGWQLWkAF6Ob28ETm4iaRZKovaNGXnUX8r7rJ3ib3A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jW0cyQc5LAE8XqrBDVuOHhCCXiaCH0PCdQaG4MiaA4flIcPy6RCI1CeelQqc6zficMAUCibrgINN3Gib1bE3r8TP8AA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
该插件安装完成后，将无需特殊设置，自动启用被动扫描，扫描发现的端点将会生成漏洞条目出现在BurpSuite首页的Issue activity中。另外，若要优化扫描过程中的参数，则需要根据需要，修改插件设置，插件设置位于BurpSuite的SpringSpider选项卡。本插件具有如下设置项：  
  
#### Enable  
  
  
该复选框为修改该插件的启用状态，当该复选框选中时插件才会执行被动扫描。当取消选中时，插件将不会再接受新的扫描任务，在当前正在执行的扫描任务结束后将会停止扫描。  
#### Dir Scan Deeper  
  
  
该设置项为修改插件的目录扫描深度，设置范围为1~∞，默认建议值为3，假设当前目录扫描深度设置为3，在用户访问目标「http://test.com/backend/api/admin/user/」时，将会拆分为「http://test.com/」、「http://test.com/backend/」、「http://test.com/backend/api/」分别扫描，该参数请尽量控制在1~5以内，以避免产生过大的请求流量。  
#### Use Bypass  
  
  
该设置项为修改启用的Bypass字符列表，默认启用;、.，当正常请求无果后，将会尝试在路径中插入Bypass字符尝试进行绕过，例如在启用;字符后，对「http://test.com/api/actuator/env」的绕过URL则是「http://test.com/api/;/actuator/;/env」  
#### Scan Point  
  
  
该设置项为修改启动扫描的端点，为了避免请求频率过大，目前支持启用的端点有「/actuator/env」、「/actuator」、「/env」，建议全部启用。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X4K2loV6ggicQLkSRWXjR0vcQZibMwOdOqDQubJzjpEfdgTnxMdIrgrKvyBuxr6BWYJfCOxOIlibibWiaXiaT8rP3H5Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jnib104Mh5XHzc7zhusNyJItFgK94QBbzz7ncbtJV7FCVtIKxIwOloF0f0z2PB01m0iaLUTceO736f7fJL6UETCg/640?from=appmsg&wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
SIMPLE STYLE  
  
7.ThinkphpGUl  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fHwBpeeZQkz05RHr4N0taQB5vTwLfcM2e4gIOLDc6cXZicKkGWQLWkAF6Ob28ETm4iaRZKovaNGXnUX8r7rJ3ib3A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jW0cyQc5LAE8XqrBDVuOHhCCXiaCH0PCdQaG4MiaA4flIcPy6RCI1CeelQqc6zficMAUCibrgINN3Gib1bE3r8TP8AA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**Thinkphp(GUI)漏洞利用工具，支持各版本TP漏洞检测，命令执行，getshell.**  
  
**JFormDesigner可视化编写，没有javafx可视化好用（建议学javafx）**  
  
**检测不到的payload欢迎提交payload至issues。**  
  
**V1.3**  
  
**新增：ThinkPHP 6.x 日志泄漏。**  
  
**修复：ThinkPHP 3.x,5.x日志泄漏识别准确度。**  
  
**V1.2**  
  
**新增：刚爆出的 ThinkPHP 3.x 日志包含RCE，getshell，命令执行**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CqAJ31EjicRkiaOHfYgm8zJg5bEtfc1g42p6cShRV9dHbpATp1FcG55MA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X4K2loV6ggicQLkSRWXjR0vcQZibMwOdOqDQubJzjpEfdgTnxMdIrgrKvyBuxr6BWYJfCOxOIlibibWiaXiaT8rP3H5Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jnib104Mh5XHzc7zhusNyJItFgK94QBbzz7ncbtJV7FCVtIKxIwOloF0f0z2PB01m0iaLUTceO736f7fJL6UETCg/640?from=appmsg&wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
SIMPLE STYLE  
  
8.Turbo-lntruder  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fHwBpeeZQkz05RHr4N0taQB5vTwLfcM2e4gIOLDc6cXZicKkGWQLWkAF6Ob28ETm4iaRZKovaNGXnUX8r7rJ3ib3A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jW0cyQc5LAE8XqrBDVuOHhCCXiaCH0PCdQaG4MiaA4flIcPy6RCI1CeelQqc6zficMAUCibrgINN3Gib1bE3r8TP8AA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
以网站目录扫描为例，对于要扫描的网站，可以在请求中选中要 fuzz (模糊测试)的点，下图中是 login.php 的地方，然后右键，选择 Send to turbo intruder  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CAs4qro1LYEDLZB3qCuibtsFTgWevXp9rtN7tL7tKajTtwHrduhgLp6Q/640?wx_fmt=png&from=appmsg "")  
  
在新打开的窗口中会自动加载 default.py 的代码，该代码可以在 github 上下载  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CYIAX0EbTonjKkQlSacJ28icj8uibn9vb1a5ZnrgUfqKkdKpZiaARsMibUw/640?wx_fmt=png&from=appmsg "")  
  
  
这个窗口分为两部分，上面的是要进行 fuzz 的请求内容，选中的插入点会用一个 %s 来代替，表示接下来会在这个点上插入字典。  
  
  
窗口的下面部分为自定义的 python 代码，用于生成字典并指导 Turbo Intruder 如何进行 fuzz。稍后再讲解代码的作用，我们需要修改的是13 行处字典的路径，修改成我们本地的目录字典路径，最好是英文的路径：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0C3wN5RerNIaomSXDgNMpgLBzHlN2eliaiaHXuGS7Sn0ZreJQ5vWd90ORA/640?wx_fmt=png&from=appmsg "")  
  
接着点击 Attack 按钮开始目录扫描：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CwhZkvTovWK8DiaPtJkxMicQpQicB3834p3mB6nfSWqaAJ49XXUalsh1Pw/640?wx_fmt=png&from=appmsg "")  
  
运行情况如上图，可以看到一共发送了 28 万个请求，一共使用了 58 秒， 每秒发送了4892 个请求。  
  
  
点击其中的一条请求，可以看到之前 %s 的地方已经被字典的内容替换了，上图中替换的内容是 /robots.txt  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X4K2loV6ggicQLkSRWXjR0vcQZibMwOdOqDQubJzjpEfdgTnxMdIrgrKvyBuxr6BWYJfCOxOIlibibWiaXiaT8rP3H5Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/jnib104Mh5XHzc7zhusNyJItFgK94QBbzz7ncbtJV7FCVtIKxIwOloF0f0z2PB01m0iaLUTceO736f7fJL6UETCg/640?from=appmsg&wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
SIMPLE STYLE  
  
9.Turbo-lntruder  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fHwBpeeZQkz05RHr4N0taQB5vTwLfcM2e4gIOLDc6cXZicKkGWQLWkAF6Ob28ETm4iaRZKovaNGXnUX8r7rJ3ib3A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jW0cyQc5LAE8XqrBDVuOHhCCXiaCH0PCdQaG4MiaA4flIcPy6RCI1CeelQqc6zficMAUCibrgINN3Gib1bE3r8TP8AA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
### 注意  
  
- 默认使用jdk1.8编译  
  
- 在最新版的burp2.x中jdk为1x,会导致插件不可用,请下载jdk16版本试试,若还不行，请自行下载源码使用当前电脑的jdk1x进行编译,谢谢。  
  
### 插件描述  
  
- 返回 ✔️ 表示大小和原始数据大小一致  
  
- 返回 ==> 数字 表示和原始数据包相差的大小  
  
### 插件截图  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dC6C2sOcW7Lfyu9dCQ9n0CDmjViaFb1YRgrmiadicWw3VQp6H7hCxSibEIqb94AOfIQPKdAib4nCavutw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X4K2loV6ggicQLkSRWXjR0vcQZibMwOdOqDQubJzjpEfdgTnxMdIrgrKvyBuxr6BWYJfCOxOIlibibWiaXiaT8rP3H5Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fHwBpeeZQkz05RHr4N0taQB5vTwLfcM2e4gIOLDc6cXZicKkGWQLWkAF6Ob28ETm4iaRZKovaNGXnUX8r7rJ3ib3A/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jW0cyQc5LAE8XqrBDVuOHhCCXiaCH0PCdQaG4MiaA4flIcPy6RCI1CeelQqc6zficMAUCibrgINN3Gib1bE3r8TP8AA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
差不多就介绍到这里啦，如果需要我们帮助，可以在后台私信我们，也会广泛采取师傅们的建议。如有其他  
需求想法的师傅们，可以后台私信，我们会考虑师傅们的建议，添加、完善更多的插件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/X4K2loV6ggicQLkSRWXjR0vcQZibMwOdOqDQubJzjpEfdgTnxMdIrgrKvyBuxr6BWYJfCOxOIlibibWiaXiaT8rP3H5Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**关注下方公众号回复 burp 即可获取插件**  
  
  
  
下方二维  
码添加好友，回复关键词   
**星悦安全**  
进群  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8CGA5xDtuNnCSVGd0ibW86zZaJ6tr5ib17xnMbupUibq24HQEl4gRoptsVgCBSNnwBEGmSn3a4ftXVzQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![](https://mmbiz.qpic.cn/mmbiz_png/pPVXCo8Wd8AOzYX7kxefGbGGZg3g1ltkN30q9hceg23PiczgUqMT0EE9w0fLK9uw1eKWwQX9TljXQe1OQeHRZ2Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
  
