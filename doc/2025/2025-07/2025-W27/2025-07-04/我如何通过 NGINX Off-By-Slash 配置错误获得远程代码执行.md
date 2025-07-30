> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjYyMzkwOA==&mid=2247531579&idx=1&sn=8aeb22f983426b00e76b8eb31fada17a

#  我如何通过 NGINX Off-By-Slash 配置错误获得远程代码执行  
 Ots安全   2025-07-03 04:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
我如何完全控制一个敏感组织的服务器  
  
晚上好。今天我要分享我发现的一个漏洞。该漏洞是由 NGINX 的一个配置错误引起的，最终导致了远程代码执行 (RCE)，让我完全控制了服务器。  
  
为了保护组织的身份，我对场景的某些部分进行了稍微修改。  
  
让我们直入主题吧。  
  
最初的发现  
  
在测试目标时，我注意到了一些奇怪的事情。有些路径返回了有效的响应，尽管这些路径本身在技术上是不正确的。  
  
例如，服务器有这样的路径：  
  

```
GET /static/main.js
```

  
  
但是当我删除斜线并发送时：  
  

```
GET /staticmain.js
```

  
  
服务器返回了完全相同的响应。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tac3BohH8PyCmIokH2LMq6gL8G3usgYOt7TlhSWwmEEXRWQr9Fuu0MsJCPb0jWsqsmp6JSCad0mATg/640?wx_fmt=png&from=appmsg "")  
  
这种行为很不寻常。于是我开始思考并探究其原因。  
  
经过一些研究和测试，我意识到这是由于 NGINX 设置中的配置错误造成的。  
  
了解根本原因  
  
那么实际问题是什么？  
  
问题出在 nginx.conf 文件上。这导致服务器错误地解释和处理路径。  
  
事情是这样的：  
  
服务器将“/staticmain.js”视为“/static/main.js”。  
  
发生这种情况的原因是，一旦服务器检测到“/static”，它就会自动在其后面添加一个斜杠，将其变成“/static/”。  
  
此行为是由 NGINX 中的 alias 指令引起的。每当 `static/` 被定义为别名时，NGINX 都会添加一个斜杠，并按如下方式解释路径：  
  

```
/static/ → /static/main.js
```

  
  
将这种不当行为转化为严重漏洞  
  
这为称为**off-by-slash**的漏洞打开了大门，该漏洞允许通过绕过预期的路径结构来访问敏感文件。  
  
让我解释一下这是如何被滥用的。  
  
以下是存在漏洞的 NGINX 配置示例：  
  

```
location /static {
    alias /var/www/static/;
}
```

  
  
如配置中所示，‘static’被定义为没有尾部斜杠的别名。  
  
但是，NGINX 在处理别名时会自动添加斜杠。因此，任何以 `static/` 开头的路径在后端都会变成 `/static/`。  
  
这意味着如果我发送了“/staticmain.js/”，服务器会将其解释为“/static/main.js/”。  
  
这正是漏洞得以存在的根本原因。服务器接受的路径没有斜杠，但别名逻辑却添加了一个斜杠，导致路径解析错误。  
  
我如何利用此漏洞获得 RCE 和完全访问权限  
  
一旦我了解了服务器如何处理路径规范化，我意识到我可以逃离目标文件夹并访问内部文件。  
  
如何？  
  
由于在“static/”后面添加了一个斜杠，我可以注入“/..”并脱离目标目录。  
  
由于 NGINX 在别名重写后执行了规范化，这使我能够访问敏感的内部文件。  
  
因此我开始使用这种格式对路径进行模糊测试：  
  

```
static../FUZZ/
```

  
  
不是：  
  

```
static/../FUZZ/
```

  
  
因为如前所述，在“static/”后面会自动添加一个斜线。  
  
关键发现  
  
经过一些模糊测试后，我得到了一些结果。其中大多数都是无害的配置文件，没有任何敏感信息。  
  
但其中一个文件的回应非常有趣：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48tac3BohH8PyCmIokH2LMq6gLpp236rxX3ETh5zoiba7VTFZW0MYhlYuFJiarXgBzLpx0R5l2iaVmygG6w/640?wx_fmt=png&from=appmsg "")  
  
它以明文形式暴露了管理员用户名和密码。  
  
那时，我非常兴奋，并尝试使用该组织主登录门户上的凭据 - 但没有成功。  
  
经过多次尝试失败后，我认为这些凭证仅适用于内部系统。  
  
但我并没有就此止步。我搜索了与该组织相关的任何内部登录门户，并尽可能地测试了凭据。  
  
最终，通过 Google Dorking，我找到了其中一个登录门户。  
  
我输入了管理员凭据...并且它成功了。  
  
全面服务器入侵  
  
在管理面板内，我发现了一个命令 shell。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tac3BohH8PyCmIokH2LMq6gLn8hSvq9115W2T9NnFjdKliaKCHGjJSp698wrpiabZfibDHBXicLsyvewQw/640?wx_fmt=jpeg&from=appmsg "")  
  
连同其他一些有趣的选项，该 shell 是完全服务器控制的最终证明（；  
  
补救措施  
  
修复此漏洞的方法：  
  
1. **正确配置 NGINX 别名**，并使用尾部斜杠：  
  

```
nginx
   location /static/ {
       alias /var/www/static/;
   }
```

  
  
这个案例展示了一个简单的配置疏忽如何导致整个系统的崩溃。  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
