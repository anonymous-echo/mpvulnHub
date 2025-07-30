#  SimpleIAST- 基于污点追踪的灰盒漏洞扫描工具。   
keven1z  夜组安全   2025-01-17 00:01  
  
免责声明  
  
由于传播、利用本公众号夜组安全所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号夜组安全及作者不为此承担任何责任，一旦造成后果请自行承担！如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
**所有工具安全性自测！！！VX：**  
**baobeiaini_ya**  
  
朋友们现在只对常读和星标的公众号才展示大图推送，建议大家把  
**夜组安全**  
“**设为星标**  
”，  
否则可能就看不到了啦！  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2WrOMH4AFgkSfEFMOvvFuVKmDYdQjwJ9ekMm4jiasmWhBicHJngFY1USGOZfd3Xg4k3iamUOT5DcodvA/640?wx_fmt=png&from=appmsg "")  
  
## 工具介绍  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icZ1W9s2Jp2V7wg7fgmgoibAuBVTk5n82tGwrGibWbp9p0Qz49lwicsorLBD47icqkiazD65cy49ibVaf1oAjiagzb7cXw/640?wx_fmt=png&from=appmsg "")  
  
simpleIAST是一种交互式应用程序安全测试工具。  
## 开始部署  
### 1. clone项目  
```
git clone https://github.com/keven1z/simpleIAST.git

```  
### 2. docker运行  
```
cd ./simpleIAST/docker/
docker-compose up -d

```  
### 3. 访问  
  
访问地址: http://[your_ip]:8443/
默认用户名: admin
默认密码: 123456  
>   
> 前端端口:  8443  
> 后端端口: 81  
> 数据库端口: 33060  
> redis端口: 63790  
  
## Agent启动  
>   
> 将iast-agent.jar和iast-engine.jar 放在同一目录  
  
### 跟随应用启动运行  
```
java -javaagent:iast-agent.jar -jar [app.jar] # 

```  
### 应用启动完成attach方式运行  
```
# attach方式安装agent
java -jar iast-engine.jar -m install -p [pid] 
# attach方式卸载agent
java -jar iast-engine.jar -m uninstall -p [pid] 

```  
## 兼容  
### 支持中间件  
- Tomcat  
  
- Springboot  
  
- Jetty  
  
- Weblogic  
  
- glassfish  
  
- WildFly  
  
- TongWeb  
  
- Resin  
  
- Undertow  
  
### 支持JDK  
- jdk 1.8  
  
- jdk 11  
  
## 支持漏洞  
- SQL注入  
  
- 反序列化漏洞  
  
- SSRF  
  
- URL跳转漏洞  
  
- XXE  
  
- 命令注入  
  
- 文件上传  
  
- XSS  
  
- Spring EL表达式注入  
  
- 数据库弱口令  
  
- XPATH注入  
  
- 硬编码漏洞  
  
  
  
## 工具获取  
  
  
  
点击关注下方名片  
进入公众号  
  
回复关键字【  
250117  
】获取  
下载链接  
  
  
## 往期精彩 一款微信小程序源码包信息收集工具，根据已有项目改编 专注于软件供应链安全，具备专业的软件成分分析（SCA）、漏洞检测、专业漏洞库。 Zentao-GetShell | 禅道认证绕过后台命令执行Getshell   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAmMqjhMehrtxRQaYnbrvafmXHe0AwWLr2mdZxcg9wia7gVTfBbpfT6kR2xkjzsZ6bTTu5YCbytuoshPcddfsNg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&random=0.8399406679299557&tp=webp "")  
  
