#  XXL-job漏洞综合利用工具   
pureqh  夜组科技圈   2025-01-21 00:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GLyX5CgG8A01kogJM8ZEPSB6WyWpaoNuJ3d3CaEltibOFtcOBqTp2FxXUCuyKBmPhY8M52LvuOf9wibg3C5u6n3Q/640?wx_fmt=png&from=appmsg "")  
  
  
公众号现在只对常读和星标的才展示大图推送，  
  
建议大家把  
**夜组科技圈**  
设为  
**星标**  
，接收一手资讯！  
  
## 工具介绍  
  
xxl-job-attack，xxl-job漏洞综合利用工具  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GLyX5CgG8A36xuic2JM1SXtdQJY04G9DHqD4KvPEC1s3Fibj2Bicus8DuaeZn594AUib5pYu5549dWVTvSicWibPZGfA/640?wx_fmt=png&from=appmsg "")  
  
## 检测漏洞  
  
1、默认口令  
  
2、api接口未授权Hessian反序列化  
  
3、Executor未授权命令执行  
  
4、默认accessToken身份绕过  
## 关于内存马  
  
1、内存马使用了xslt，由于测试直接打入内存马有时会失败，所以选择直接打入agent内存马  
  
2、如需自定义可替换resources下的ser文件，其中agent.ser为agent内存马、xslt.ser会落地为/tmp/2.xslt  
  
3、内容为使用exec执行/tmp/agent.jar、exp.ser则是加载/tmp/2.xslt  
  
4、默认注入vagent内存马，连接信息冰蝎:http://ip:port/xxl-job-admin/api/luckydayb,其他类型内存马类似， 将favicon改为luckyday即可  
  
5、由于agent发送文件较大，所以可能导致包发不过去，建议多试几次或者将超时时间延长  
  
6、由于Hessian反序列化基本上都是直接发二进制包，所以理论上讲其他的Hessian反序列化漏洞也可以打  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GLyX5CgG8A36xuic2JM1SXtdQJY04G9DHqD4KvPEC1s3Fibj2Bicus8DuaeZn594AUib5pYu5549dWVTvSicWibPZGfA/640?wx_fmt=png&from=appmsg "")  
  
## 工具下载  
  
https://github.com/pureqh/xxl-job-attack/tree/main  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**点它，分享点赞在看都在这里**  
  
