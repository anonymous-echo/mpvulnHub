> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkxNzY5MTg1Ng==&mid=2247489947&idx=2&sn=e6a1f5fc0876c99510cae96989056453

#  一款以Web与全版本服务漏洞检测为核心的辅助性主、被动扫描工具  
菜狗  富贵安全   2025-07-10 04:30  
  
### 以 Web 和完整版服务漏洞检测为核心的辅助主动和被动扫描工具。|一款以 Web 与全版本服务漏洞检测为核心的辅助性主  
### 优势  
### 1、集成 WAF 检测、指纹信息和插件扫描  
### 2、能够解析 Json、XML 和伪静态参数等复杂格式的参数 （Beta）  
### 3、为扫描记录和其他数据提供基于 SQLite3 的存储支持  
### 4、具有跨平台支持的基于 Python3 的开源解决方案  
### 通过 Pypi 安装  

```
pip install z0scan
z0

```

### 通过 GitHub 克隆安装  

```
git clone https://github.com/JiuZero/z0scan
cd z0scan
pip install -r requirements.txt
python3 z0.py

```

### 被动扫描的默认配置（将浏览器流量转发到端口 5920）  

```
z0 scan -s 127.0.0.1:5920

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5lJqSJ7RficfY6z4DlJrbrXqDKJYMdx1J7u5OvbKI0djn68kYSMcLLWuypvNAk4XAIwibiauaHK80FQA/640?wx_fmt=png&from=appmsg "")  
### 推荐的常见用法  

```
z0 scan -s 127.0.0.1:5920 --risk 0,1,2,3 --level 2 --disable cmdi,unauth

```

### 主动扫描  

```
# Initiate active detection from Burp/Yakit request traffic (recommended)
z0 scan -s 127.0.0.1:5920

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5lJqSJ7RficfY6z4DlJrbrXq36elPr3KtYP1SyjQiaXibEA81iciayhh9ia9um1XZUcHvXdvc6g8RvbGqVQ/640?wx_fmt=png&from=appmsg "")  

```
# Direct detection
z0 scan -u https://example.com/?id=1
# Batch detection from URL list
z0 scan -f urls.txt

```

  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/veA9QmcJk5lJqSJ7RficfY6z4DlJrbrXqbpyhmX76XL41JvD2AVB0qiboiaMkTgvoga5wicCSl8t51QnjPCYGcKWKA/640?wx_fmt=png&from=appmsg "")  
  
- PerFile  每文件  
  
Plugin Name  插件名称Description  描述Risk  风险sqli-boolSQL Boolean-based Blind InjectionSQL 基于布尔值的盲注2sqli-timeSQL Time-based Blind InjectionSQL 基于时间的盲注2sqli-error  sqli-错误SQL Error-based InjectionSQL 基于错误的注入2codei-aspASP Code Execution  ASP 代码执行3codei-phpPHP Code Execution  PHP 代码执行3cmdiCommand Execution  命令执行3other-objectdeseDeserialization Parameter Analysis反序列化参数分析3sensi-js  森西-JSJS Sensitive Information LeakJS 敏感信息泄露0sensi-jsonpJsonp Sensitive Information Leakjsonp 敏感信息泄露1sensi-php-realpathPHP Real Path DisclosurePHP 实际路径泄漏0redirect  重定向Redirect  重定向1sensi-webpack  森西-webpackwebpack Source Code Leakwebpack 源代码泄露1other-webdav-passivePassive webdav Service Discovery被动 webdav 服务发现1xpathi-error  XPathi 错误Error-based XPATH Injection基于误差的 XPATH 注入2trave-path  遍历路径Path Traversal  路径遍历2sensi-backup_1Backup File Detection (File-based)备份文件检测（基于文件）1sensi-viewstate  sensi-view 状态Unencrypted VIEWSTATE Discovery未加密的 VIEWSTATE 发现0xss  XSS （英语）XSS Scanning Based on JS Semantics基于 JS 语义的 XSS 扫描1crlf_1CRLF Vulnerability DetectionCRLF 漏洞检测2cors-passive  CORS-被动CORS Vulnerability Detection (Passive Analysis)CORS 漏洞检测（被动分析）2unauth  未身份验证Unauthorized Access  未经授权的访问2leakpwd-page-passive  leakpwd-page-被动Weak Password on Admin Login Page管理员登录页面上的弱密码2sensi-editfile  sensi-edit 文件Editor Backup File Leak编辑器备份文件泄漏1sensi-sourcecodeSource Code Leak  源代码泄漏1captcha-bypass  CAPTCHA-BYPASS 验证码CAPTCHA Bypass  CAPTCHA 绕过0sensi-retirejsOutdated JS Component Detection过时的 JS 组件检测-1sstiSSTI Vulnerability DetectionSSTI 漏洞检测3- PerFolder  PerFolder 文件夹  
  
Plugin Name  插件名称Description  描述Risk  风险sensi-backup_2Backup File Scanning (Directory-based)备份文件扫描（基于目录）1trave-list_2Directory Listing  目录列表2sensi-file  sensi 文件Sensitive File Leakage (including phpinfo, .git, etc.)敏感文件泄露（包括 phpinfo、.git 等）/upload-oss  上传-OSSOSS Bucket Arbitrary File UploadOSS Bucket 任意文件上传2sensi-frontpageFrontPage Configuration Information LeakFrontPage 配置信息泄漏1- PerServer  PerServer 服务器  
  
Plugin Name  插件名称Description  描述Risk  风险sensi-errorpageError Page Sensitive Information Leak错误页面敏感信息泄露0xss-net  XSS-网络.NET Universal XSS  .NET 通用 XSS1other-dns-zonetransfer  其他 DNS 区域传输DNS Zone Transfer VulnerabilityDNS 区域传输漏洞1xss-flash  XSS-闪存Flash Universal XSS  Flash 通用 XSS1other-idea-parse  其他 Idea-解析Idea Directory Parsing  Idea 目录解析1other-xst  其他-XSTXST Vulnerability DetectionXST 漏洞检测-1other-webdav-activeActive webdav Service Discovery主动 webdav 服务发现1upload-put  上传-放置PUT-based Arbitrary File Upload基于 PUT 的任意文件上传3sensi-backup_3  森西-backup_3Backup File Detection (Domain-based)备份文件检测（基于域）1cors-active  CORS-主动CORS Vulnerability Detection (Active Discovery)CORS 漏洞检测 （主动发现）2crlf_3CRLF Line Injection VulnerabilityCRLF 行注入漏洞2other-hostiHost Header Injection Attack Detection主机标头注入攻击检测1other-oss-takeover  other-oss-takeover （其他 oss-接管）OSS Bucket Takeover VulnerabilityOSS Bucket Takeover 漏洞3sensi-iis-shortnameIIS Short Filename VulnerabilityIIS 短文件名漏洞0other-clickjacking  其他点击劫持Clickjacking Vulnerability点击劫持漏洞-1other-baseline  其他基线Service Version Disclosure服务版本披露-1other-smuggling  其他走私Request Smuggling Vulnerability请求走私漏洞3trave-list_3Directory Listing  目录列表2  
  
后台回复  
20250710  
获取链接  
  
