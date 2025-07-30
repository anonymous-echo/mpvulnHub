#  Tomcat 弱密码检测与漏洞利用工具   
ZapcoMan  夜组科技圈   2025-01-23 02:53  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GLyX5CgG8A01kogJM8ZEPSB6WyWpaoNuJ3d3CaEltibOFtcOBqTp2FxXUCuyKBmPhY8M52LvuOf9wibg3C5u6n3Q/640?wx_fmt=png&from=appmsg "")  
  
  
公众号现在只对常读和星标的才展示大图推送，  
  
建议大家把  
**夜组科技圈**  
设为  
**星标**  
，接收一手资讯！  
  
## 工具介绍  
  
TomcatScan  
 是一个用于检测 Tomcat 服务器漏洞的工具，支持以下主要功能：  
- 检测 CVE-2017-12615 和 CNVD-2020-10487 漏洞。  
  
- 进行弱口令检测。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GLyX5CgG8A0l3ZNuXw2IMqQ6SpJy58OPSXYGDSdPicn9jn8ibkbu1fibk28Wo6nrD6FGl3Od8eXl2JqzqROT1XxKg/640?wx_fmt=png&from=appmsg "")  
## 主要功能  
### 1. CVE-2017-12615 漏洞检测  
- 工具支持三种利用方式：  
  
PUT /1.jsp/  
  
PUT /1.jsp%20  
  
PUT /1.jsp::$DATA  
  
- 成功上传后，工具会尝试访问并执行上传的 JSP 文件，判断是否能远程执行代码。  
  
- 对每种利用方式的结果分别记录成功或失败状态。  
  
### 2. CNVD-2020-10487 (AJP 协议本地文件包含漏洞)  
- 工具利用 AJP 协议进行本地文件包含（LFI）攻击，默认读取 WEB-INF/web.xml 文件，但文件路径和判断条件可以通过配置文件灵活调整。  
  
- 支持对目标文件中的关键字（例如 "Welcome"）进行自定义判断，确定文件读取成功与否。  
  
- 检测到文件包含成功后，详细记录成功的 URL 和读取到的敏感文件路径。  
  
### 2. 弱口令检测  
- 支持通过用户名与密码组合进行弱口令暴力破解。  
  
- 若登录成功，工具会自动尝试上传 WebShell 文件，提供远程管理和代码执行能力。  
  
- 登录成功以及 WebShell 上传的结果都会详细记录在日志文件中。  
  
### 3. 后台部署 WAR 包 getshell  
- 在弱口令破解成功后，工具会尝试通过 Tomcat 管理后台上传 WAR  
 包，以获取远程代码执行权限。  
  
- 部署的 WAR  
 包会自动在服务器上解压并生成 JSP Shell 文件，访问该文件后便可以获取 Shell 权限。  
  
- 支持通过配置文件自定义Shell   
文件的内容。  
  
## 使用方法  
1. 准备包含URL、用户名和密码的文本文件，分别命名为urls.txt  
、user.txt  
和passwd.txt  
。  
  
1. urls.txt  
保存格式：https://127.0.0.1/  或者 https://127.0.0.1/manager/html 脚本会自行判断检测  
  
1. 在config.yaml  
中配置文件路径和其他设置。  
  
1. 运行脚本，将会在success.txt  
文件中记录成功利用漏洞信息。  
  
```
  python TomcatScanPro.py

```  
## 工具下载  
  
https://github.com/ZapcoMan/TomcatScan  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
**点它，分享点赞在看都在这里**  
  
