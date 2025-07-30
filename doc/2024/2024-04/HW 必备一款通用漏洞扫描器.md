#  HW 必备|一款通用漏洞扫描器   
 黑白之道   2024-04-13 08:43  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
# CVS  
### 介绍  
  
CVS与Nessus和Nuclei等许多产品一样，可用于扫描各种网络漏洞，但它更现代，具有免等待的OOB测试策略、高级漏洞PoC IDE和强大的  
VDSL  
（漏洞域特定语言）引擎，使您能够能够快速轻松地扫描几乎所有漏洞。  
### 特征  
- 强大的   
PoC  
 脚本语言 - VDSL（领域特定语言）  
  
- 先进的仿真的 PoC 开发和调试环境 - CVS PoC IDE  
  
- 更现代化，消耗等待OOB服务器  
  
- 高速、高性能的漏洞扫描引擎  
  
- 与几乎所有 Nuclei 的辅助函数功能兼容，因此您可以轻松将 Nuclei 模板转换为 CVS PoC  
  
- 轻松提取森罗空间测绘引擎扫描的网络服务和指纹信息  
  
- 轻量级、单一二进制文件、跨平台且无其他依赖关系  
  
- 输出格式支持-JSON  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic3Fw8BG2rIGicBqukYL03eTgAjax6qNheGvF6pf03JD2SMU3QulCYoWH6iaNO8sqNnMpRK5FIibZZ2Jw/640?wx_fmt=png&from=appmsg&wxfrom=13 "")  
### 用法  
  
CVS由三部分组成：**CVS扫描器**  
、**PoC IDE**  
和**OOB服务器**  
。CVS扫描器用于读取森罗空间测绘引擎生成的扫描目标信息，并加载PoC进行漏洞扫描。  
  
PoC IDE用于编写和调试漏洞脚本以及生成PoC文件。OOB服务器用于反向连接平台，如一些没有回显的漏洞，以确认漏洞的存在。  
###   
### 编写PoC  
  
命令行运行IDE  
```
ide.exe
```  
  
浏览器打开http://127.0.0.1:777/  
即可看到PoC开发环境，该IDE提供了PoC的编写、调试和保存等功能，并支持代码补全和智能提示，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/GzdTGmQpRic3Fw8BG2rIGicBqukYL03eTgFyWLuBMxvVGK6x99Diao1g3PRZsoKPoWtibeYc05T6uF5F4vPwIXJABQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
上图右上角分别为运行、保存、刷新按钮，按钮用于调试PoC脚本，运行该脚本脚本类似golang，cvs结构体在CVS扫描器中会自动根据target.json生成，无需实现，只需在调试时方便测试，自行声明。  
###   
### 架设OOB服务器  
  
OOB全称  
Out-of-Band  
，有很多漏洞测试时并不直接回显任何信息，需要在公网架设一个OOB服务器来接收漏洞是否测试成功的结果。通常OOB服务器会接收漏洞测试所触发的dns 、http、ldap、rmi、ftp等连接请求，将结果返回给CVS扫描器。  
1. 首先将oob-server上传到公网可访问的服务器上  
  
1. 运行oob-server会自动生成一个名为cfg.yml的配置文件  
  
1. 修改配置文件：domain为  
dns服务器  
要解析的根域名，token为CVS扫描器连接OOB服务器的认证token，external_ip为该服务器的公网ip，ssl为CVS扫描器连接OOB服务器是否启用ssl，若为true则需要上传pem格式的tls证书server.crt和私钥server.key  
  
```
domain: example.com
token: clt5j6r4uu422g7i8rrg
external_ip: 3.1.1.1
ssl: false
log_level: info
```  
  
4. 放开服务器的80、53、33333端口访问，并将OOB服务器设置为NS解析服务器，如阿里云上的域名可以参考链接进行配置  
### 开启CVS扫描器  
  
CVS扫描器下面有poc、lib、db三个目录和一个配置文件cfg.yml。poc目录为PoC货架目录，子目录以服务协议配置。lib目录为用户自定义的VDSL库文件货架目录。db目录用于主板无回显漏洞详细信息的数据库文件。  
  
配置文件cfg.yml如下：  
```
oob_url: http://3.1.1.1
oob_dns: example.com
oob_server: "http://3.1.1.1:33333/events/"
oob_token: "clt5j6r4uu422g7i8rrg"
threads: 36
log_level: error
```  
  
上面oob_url为OOB服务器的外网地址，用于http协议的反连。oob_dns为dns的根域名，用于dns协议的反连。oob_server为接收反连信息的长连接通信url。  
oob_token对应OOB服务器上的认证token。threads为CVS扫描器的并发线程数。  
  
配置好上面配置后，将森罗网络空间测绘引擎生成的target.json↓过来，执行cvs即可开始  
扫描漏洞  
。  
  
CVS 命令行选项  
：  
```
Usage of cvs:
  -i string
       扫描的目标输入文件路径（默认为森罗输出的“target.json”）
  -o string
       扫描结果输出文件路径（默认为“result.json”）
```  
  
### 项目地址  
  
  
https://github.com/Safe3/CVS  
  
> **文章来源：Hack之道**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
