#  哔哩哔哩网页端疑似曝出存储型XSS漏洞   
 夜组科技圈   2025-01-16 00:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GLyX5CgG8A01kogJM8ZEPSB6WyWpaoNuJ3d3CaEltibOFtcOBqTp2FxXUCuyKBmPhY8M52LvuOf9wibg3C5u6n3Q/640?wx_fmt=png&from=appmsg "")  
  
  
公众号现在只对常读和星标的才展示大图推送，  
  
建议大家把  
**夜组科技圈**  
设为  
**星标**  
，接收一手资讯！  
  
## 漏洞描述  
  
哔哩哔哩网页端疑似曝出存储型XSS漏洞。  
  
目前攻击范围仅存在类魂游戏玩家之间，根据视频展示，攻击发生于视频加载后，可以猜测是加载网页的过程加载并执行了攻击脚本。由于代码直接注入了b站网页，因此攻击脚本自然也可以带上b站的cookie调用b站api（从后端视角来看，这些请求完全是由客户端正常发起的），从而可以进行删视频等操作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GLyX5CgG8A3crgrGBtKfaA83zjAb0Jx4yf8AjAOCiaggovkrMxguQhKiaIgsWs9iaaDicPqCma74vdafl80hoTPLUg/640?wx_fmt=png&from=appmsg "")  
  
image  
  
普通终端用户无法有效抵御，建议暂时改用客户端直到漏洞被修复。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GLyX5CgG8A3crgrGBtKfaA83zjAb0Jx4icSV0rbqyjrh3VViaIWPqG3EJxXnFqFPjG7hEaXttZF9YrKBJ8b28AkQ/640?wx_fmt=png&from=appmsg "")  
  
来源：视频《为什么我建议别用B站网页端了（攻击指定b站账号）》  
  
https://www.bilibili.com/video/BV1TqcueYEhG/  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**点它，分享点赞在看都在这里**  
  
