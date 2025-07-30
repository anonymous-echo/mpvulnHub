#  某科云连ERP系统存在任意文件读取漏洞   
原创 xiaokp7  xiaokpSec   2024-12-17 05:35  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**免责声明**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HVNK6rZ71oofHnCicjcYq2y5pSeBUgibJg8K4djZgn6iaWb6NGmqxIhX2oPlRmGe6Yk0xBODwnibFF8XCjxhEV3K7w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
文章所涉及内容，仅供安全研究与教学之用，由于传播、利用本文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
**漏洞分析**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/4yJaCArQwpACMJuBxI11jPgvHCxQZFQxPrt5iaQRibgGl0aIzFo4hDCYcFuyViag6zhuqNEjjeasfMEAy1rkaOahw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
  
由于未对用户查看或下载的文件做限制，恶意用户就能够查看或下载任意的文件，可以是源代码文件、敏感文件等、如脚本代码、服务及系统配置文件等，攻击者可用得到的代码进一步代码审计，得到更多可利用漏洞。  
  
漏洞位于  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/HVNK6rZ71oofHnCicjcYq2y5pSeBUgibJg8K4djZgn6iaWb6NGmqxIhX2oPlRmGe6Yk0xBODwnibFF8XCjxhEV3K7w/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
```
```  
  
  
通过获取请求中的userFile和downloadFile参数，直接拼接读取组合后文件路径内容  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1k5x73IiaGYc8ecAFOtibUkcapaRFpZcBQhdhwibewxxsFMT9AA8NaHJMl22PL4IEroDDwyOtq0J5o4IBBM10yzeQ/640?wx_fmt=png&from=appmsg "")  
  
不过该路由是后台的需要绕过一哈权限，查看web.xml,定位拦截器类  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1k5x73IiaGYc8ecAFOtibUkcapaRFpZcBQQwMUXoGjK9xH0Mzc7Aiacyv4TrAkxrIs5Mia0rYY71vpLhyPumlfDNYA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1k5x73IiaGYc8ecAFOtibUkcapaRFpZcBQYhDjJibO82AcqTVVSkV25OibiaVJibewwxAqxn2x6IXmyNeyby20cETXbQ/640?wx_fmt=png&from=appmsg "")  
  
当url中包含admin!login.action即可绕过身份验证。因此可绕过身份认证读取任意文件内容  
  
![](https://mmbiz.qpic.cn/mmbiz_png/1k5x73IiaGYc8ecAFOtibUkcapaRFpZcBQ65BC2iaY9qjg04ibAXLG9bibuezjlqRH8T26iaJ7y3tnBUSf6D9XVaStCQ/640?wx_fmt=png&from=appmsg "")  
  
关注公众号回复“1217”获取poc。  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**点它，分享点赞在看都在这里**  
  
  
