#  深度剖析JSONP注入漏洞：JavaScript回调函数引发的会话弹窗劫持  
tangkaixing  开心网安   2025-06-12 00:58  
  
**免责声明**  
  
由于传播、利用本公众号开心网安所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号开心网安  
及作者不为**此**  
承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉，谢谢！  
  
# 1 概述  
  
在Web应用安全领域，JSONP（JSON with Padding）因其跨域特性被广泛使用，但也常成为攻击入口。本文通过分析某企业登录系统的高危漏洞案例，揭示**未过滤的JSONP回调函数**  
如何导致完整会话Cookie泄露。该漏洞利用难度低但危害极大，通过篡改AJAX响应即可窃取用户会话，实现完全身份冒充。  
  
# 2 正文  
  
## 2.1 漏洞挖掘思路  
  
在对某JSP平台登录模块进行黑盒测试时，发现关键接口：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uLpuFLYKHdW8KR3R7B7Zku3mj98x6x57Gic60sCiapribibMiaDGW5tyVSjX7EibCdfzZJrIPgft791hKK62r9PdS3EA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uLpuFLYKHdW8KR3R7B7Zku3mj98x6x57AEMbj4t6nS0LjXhaog6ia7DQcwibmW4rtaibIx8TXjgl5cBNoC0RX4NSQ/640?wx_fmt=png&from=appmsg "")  
```
POST /sp/checkCode!isShow.ajax?loginName=xxx HTTP/1.1POST /sp/smsVerify!sendSmsVerifyCode.ajax HTTP/1.1
```  
  
响应为标准的JSON结构：  
```
{"success":true,"datas":{"isNeetCheckCode":true}}{"success":true}
```  
  
但当深入审查前端代码时，发现致命隐患：  
  
典型的高危函数滥用：使用eval()/Function()解析动态数据  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uLpuFLYKHdW8KR3R7B7Zku3mj98x6x572TLcibHKbal4yr9IT8v5ric9z1PYibg5cgfUgCiaC4s3Br7ynIH2eTJ5QA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uLpuFLYKHdW8KR3R7B7Zku3mj98x6x57KvzI1IfMIeF4ymyDKs6tvFdgNvtf5XsSWj4ZxG80T5lq8AhOECR1RA/640?wx_fmt=png&from=appmsg "")  
  
```
var responseData = eval("(" + textStr + ")");
```  
  
此处使用eval()直接解析响应文本，为**回调函数注入**  
埋下伏笔。  
  
## 2.2 JavaScript审计关键点  
  
  
漏洞链核心问题  
：  
- **动态执行风险**  
：  
eval()  
函数无条件执行任意JS代码  
- **缺失输出过滤**  
：服务端未校验  
Content-Type  
头（应为  
application/json  
）  
- **回调函数暴露**  
：攻击者可劫持Object.assign等原生函数  
## 2.3 漏洞攻击链分析  
  
通过Burp Suite拦截响应并注入恶意JS：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uLpuFLYKHdW8KR3R7B7Zku3mj98x6x574raDORctyfN7RKaibGFvBHmIt01Pg0KicIWHtuwcYe5pdkAcfP6lGIYw/640?wx_fmt=png&from=appmsg "")  
  
```
HTTP/1.1 200 OK  Content-Type: text/javascript  // 恶意修改为JS类型Object.assign(window,   alert('SESSION:'+document.cookie),   {"success":true,"datas":{"isNeetCheckCode":true}})Object.assign(window, alert('SESSION:'+document.cookie), {"success":true,})
```  
  
  
触发流程：  
1. eval()  
执行注入代码，调用  
Object.assign()  
1. 执行  
alert()  
泄露完整Cookie（包含JSESSIONID）  
1. 伪造的JSON结构绕过逻辑检查，验证码组件正常渲染  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uLpuFLYKHdW8KR3R7B7Zku3mj98x6x57TZTA4tAZwQtkawqegSbn3VPTniaacjmoKeXBYB4bMKH4h72uJkWyz5w/640?wx_fmt=png&from=appmsg "")  
  
  
在用户无感知情况下弹出会话信息，实现“无交互劫持”（下图是我画的示意图）：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uLpuFLYKHdW8KR3R7B7Zku3mj98x6x57vmM2pX0opCKWGpaWYZ61ORpHo7v7ReZicplT9wSAsG6vjcmoxuLZKBQ/640?wx_fmt=png&from=appmsg "")  
  
# 3 总结  
  
#### 1. JavaScript常见高危函数  
  
在渗透测试中，我们重点关注以下JavaScript函数，因为它们可能导致代码执行：  
- **eval()**  
：直接执行字符串中的JS代码，是最高危的函数。  
- **Function()构造函数**  
：通过  
new Function('arg', 'alert(arg)')  
方式创建函数，同样能执行动态代码。  
- **setTimeout()/setInterval()**  
：如果第一个参数是字符串，则会执行。  
- **document.write()/innerHTML**  
：可能导致XSS，但当插入点位于script标签内时，可以执行JS。  
- **JSON.parse()**  
：虽然相对安全，但若解析后的对象没有正确处理，仍可能通过原型链污染或后续不安全操作导致漏洞。  
#### 2. 浏览器全局检索  
  
**全局搜索：**  
 eval(、Function(、setTimeout(、innerHTML  
#### 3. 渗透测试中挖掘JS漏洞，需聚焦四个核心维度如下：  
```
graph LR  A[JS漏洞挖掘] --> B[动态执行点]  A --> C[数据流通道]  A --> D[原生函数劫持]  A --> E[上下文逃逸]
```  
# 4 祝福  
  
愿诸位安全从业者永葆对细节的敏锐洞察，在代码的海洋中精准捕获每一处暗流。愿你们的防御体系如星辰般稳固，让每一次漏洞挖掘都成为系统进化的契机。长风破浪会有时，直挂云帆济沧海——共筑网络安全长城；  
当你在万千行代码中捕获到一个漏洞时，记住这不仅是技术胜利，更是对数字世界的守护。剑未佩妥出门已是江湖，愿你的渗透之刃始终斩向黑暗。**攻防之道，存乎一心；安全之路，永无止境！**  
 🔥  
  
  
先知社区也发布此文章，欢迎给我看官浏览观看学习交流  
  
https://xz.aliyun.com/news/18212  
  
  
  
  
