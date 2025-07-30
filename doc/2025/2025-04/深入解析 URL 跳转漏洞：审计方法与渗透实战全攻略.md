#  深入解析 URL 跳转漏洞：审计方法与渗透实战全攻略   
原创 火力猫  季升安全   2025-04-16 11:30  
  
# 🔍 URL跳转漏洞审计与渗透分析手册  
## 🧠 一、漏洞原理概述  
  
**URL跳转漏洞**  
 发生在服务端根据用户可控输入进行跳转，却**未对跳转目标地址进行有效验证**  
。  
### 🔗 典型攻击场景：  
```
https://example.com/go?url=https://evil.com
```  
  
若后端直接使用：  
```
response.sendRedirect(url);
```  
  
攻击者即可构造合法页面诱导用户跳转到恶意地址。  
## 🧪 二、常见跳转方式与源码审计点  
  
<table><thead><tr style="box-sizing: border-box;"><th style="box-sizing: border-box;"><span cid="n39" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">跳转方式</span></span></span></th><th style="box-sizing: border-box;"><span cid="n40" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">所属层</span></span></span></th><th style="box-sizing: border-box;"><span cid="n41" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">示例代码</span></span></span></th></tr></thead><tbody><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n43" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">ModelAndView(&#34;redirect:&#34;)</span></code></span></span></td><td style="box-sizing: border-box;"><span cid="n44" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">Spring MVC</span></span></span></td><td style="box-sizing: border-box;"><span cid="n45" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">new ModelAndView(&#34;redirect:&#34; + url)</span></code></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n47" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">return &#34;redirect:&#34; + url</span></code></span></span></td><td style="box-sizing: border-box;"><span cid="n48" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">Spring MVC</span></span></span></td><td style="box-sizing: border-box;"><span cid="n49" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">return &#34;redirect:&#34; + url</span></code></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n51" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">sendRedirect(url)</span></code></span></span></td><td style="box-sizing: border-box;"><span cid="n52" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">Servlet</span></span></span></td><td style="box-sizing: border-box;"><span cid="n53" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">response.sendRedirect(url)</span></code></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n55" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">setHeader(&#34;Location&#34;, url)</span></code></span></span></td><td style="box-sizing: border-box;"><span cid="n56" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">Servlet</span></span></span></td><td style="box-sizing: border-box;"><span cid="n57" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">response.setHeader(&#34;Location&#34;, url)</span></code></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n59" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">RedirectAttributes</span></code></span></span></td><td style="box-sizing: border-box;"><span cid="n60" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">Spring MVC</span></span></span></td><td style="box-sizing: border-box;"><span cid="n61" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">return &#34;redirect:&#34; + url</span></code></span></span></td></tr></tbody></table>  
### 🧬 示例：sendRedirect  
```
@RequestMapping("/go")public void go(@RequestParam String url, HttpServletResponse response) throws IOException {    response.sendRedirect(url); // ⚠️ 高危}
```  
### 🛡️ 防御建议：  
- 加白名单验证：  
```
if (!url.startsWith("/")) throw new IllegalArgumentException("非法跳转");
```  
  
  
- 或使用映射：  
```
if ("home".equals(urlKey)) return "redirect:/home";
```  
  
  
## 🕵️ 三、黑盒渗透实战技巧  
### 🎯 参数枚举策略：  
  
尝试以下参数名：  
```
?redirect=?url=?next=?returnTo=?dest=?continue=?target=
```  
### 🧪 实战 payload 构造：  
  
<table><thead><tr style="box-sizing: border-box;"><th style="box-sizing: border-box;"><span cid="n103" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">类型</span></span></span></th><th style="box-sizing: border-box;"><span cid="n104" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">示例 Payload</span></span></span></th><th style="box-sizing: border-box;"><span cid="n105" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">用途说明</span></span></span></th></tr></thead><tbody><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n107" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">标准 URL</span></span></span></td><td style="box-sizing: border-box;"><span cid="n108" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">https://evil.com</span></code></span></span></td><td style="box-sizing: border-box;"><span cid="n109" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">直接跳转测试</span></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n111" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">协议相对路径</span></span></span></td><td style="box-sizing: border-box;"><span cid="n112" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">//evil.com</span></code></span></span></td><td style="box-sizing: border-box;"><span cid="n113" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">绕过协议限制</span></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n115" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">编码绕过</span></span></span></td><td style="box-sizing: border-box;"><span cid="n116" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">%2f%2fevil.com</span></code></span></span></td><td style="box-sizing: border-box;"><span cid="n117" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">Bypass 路径限制</span></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n119" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">子域钓鱼</span></span></span></td><td style="box-sizing: border-box;"><span cid="n120" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">https://example.com.evil.com</span></code></span></span></td><td style="box-sizing: border-box;"><span cid="n121" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">欺骗用户混淆</span></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n123" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">内嵌@欺骗</span></span></span></td><td style="box-sizing: border-box;"><span cid="n124" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">https://example.com@evil.com</span></code></span></span></td><td style="box-sizing: border-box;"><span cid="n125" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">用户以为是 example.com</span></span></span></td></tr></tbody></table>### 🧰 Burp Suite 实用插件：  
- **Autorize**  
：测试跳转是否绕过权限控制  
  
- **Turbo Intruder**  
：批量 fuzz 跳转参数  
  
- **Redirect Tracker**  
：观察跳转链  
  
- Logger++：记录跳转响应变化  
  
🎣应用实例：  
  
👉[一次 OAuth 登录背后的隐患：被忽略的 URL 跳转漏洞](https://mp.weixin.qq.com/s?__biz=MzkxNjY5MDc4Ng==&mid=2247484660&idx=1&sn=a1b3e936aca842abd6567cf38e04b6ff&scene=21#wechat_redirect)  
  
  
### 📌 渗透案例：  
```
GET /login?next=https://evil.com HTTP/1.1Host: secure.example.com
```  
  
若返回：  
```
HTTP/1.1 302 FoundLocation: https://evil.com
```  
  
即为漏洞点，可用于社工钓鱼、OAuth 劫持、权限绕过。  
  
详细介绍👉[URL 跳转漏洞利用方式详解：不仅仅是钓鱼这么简单！](https://mp.weixin.qq.com/s?__biz=MzkxNjY5MDc4Ng==&mid=2247484668&idx=1&sn=8013ce12f108e76a3ed07407e72569b6&scene=21#wechat_redirect)  
  
## 🛡️ 四、安全加固建议（推荐措施）  
1. ✅ **跳转目标白名单**  
```
List<String> whitelist = List.of("/home", "/dashboard");if (!whitelist.contains(url)) throw new SecurityException("非法跳转！");
```  
  
  
1. ✅ **使用 URL 签名机制**  
  
1. 为跳转参数添加 HMAC 校验  
  
1. 防止用户伪造外部跳转地址  
  
1. ✅ **中转确认页**  
  
1. 用户跳转前显示提示页面，引导确认  
  
1. 提高用户可感知性  
  
1. ✅ **避免用户直接控制 URL**  
  
1. 可通过枚举跳转目标、绑定 ID 的方式替代动态 URL  
  
#####   
  
  
  
  
