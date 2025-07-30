#  Tomcat自动化漏洞扫描利用工具   
 黑白之道   2025-03-30 20:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
**工具介绍**  
  
Tomcat自动化漏洞扫描利用工具，支持批量弱口令检测、后台部署war包getshell、CVE-2017-12615 文件上传、CVE-2020-1938/CNVD-2020-10487 文件包含。  
  
  
**支持功能**  
### 1、CVE-2017-12615 漏洞检测  
- ### 工具支持三种利用方式：  
  
```
PUT /1.jsp/
PUT /1.jsp%20
PUT /1.jsp::$DATA
```  
- 成功上传后，工具会尝试访问并执行上传的 JSP 文件，判断是否能远程执行代码。  
  
- 对每种利用方式的结果分别记录成功或失败状态。  
  
###   
### 2. CNVD-2020-10487 (AJP 协议本地文件包含漏洞)  
- 工具利用 AJP 协议进行本地文件包含（LFI）攻击，默认读取 WEB-INF/web.xml 文件，但文件路径和判断条件可以通过配置文件灵活调整。  
  
- 支持对目标文件中的关键字（例如 "Welcome"）进行自定义判断，确定文件读取成功与否。  
  
- 检测到文件包含成功后，详细记录成功的 URL 和读取到的敏感文件路径。  
  
###   
### 3、弱口令检测  
- 支持通过用户名与密码组合进行弱口令暴力破解。  
  
- 若登录成功，工具会自动尝试上传 WebShell 文件，提供远程管理和代码执行能力。  
  
- 登录成功以及 WebShell 上传的结果都会详细记录在日志文件中。  
  
###   
### 4、后台部署 WAR 包 getshell  
- 在弱口令破解成功后，工具会尝试通过 Tomcat 管理后台上传 WAR  
 包，以获取远程代码执行权限。  
  
- 部署的 WAR  
 包会自动在服务器上解压并生成 JSP Shell 文件，访问该文件后便可以获取 Shell 权限。  
  
- 支持通过配置文件自定义Shell   
文件的内容。  
  
**使用方法**  
  
1、环境安装，通过以下命令安装所需模块：  
```
pip install -r requirements.txt
```  
  
2、准备包含URL、用户名和密码的文本文件，分别命名为urls.txt  
、user.txt  
和passwd.txt  
。  
  
3、urls.txt  
保存格式：  
https://127.0.0.1/  
 或者   
https://127.0.0.1/manager/html  
 脚本会自行判断检测  
  
4、在config.yaml  
中配置文件路径和其他设置。  
  
5、运行脚本，将会在success.txt  
文件中记录成功利用漏洞信息。  
```
python TomcatScanPro.py
```  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/79gZQNibQ6ueMSY2QaM4sK3BkulHMtibAw0s0yIibP0gyH8IU6PZlKd9uQ76rFVb9luoBE8kKqW2bZyVZytZdlJxg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**下载地址**  
  
**https://github.com/lizhianyuguangming/TomcatScanPro**  
  
> **文章来源：Hack分享吧**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
