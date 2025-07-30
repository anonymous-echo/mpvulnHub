#  工具集：TsojanScan【BurpSuite漏洞探测插件】   
wolven Chan  风铃Sec   2024-12-27 05:30  
  
### 工具介绍  
  
TsojanScan 提供了多种扫描模块，支持主动和被动的漏洞探测，优化了扫描性能和兼容性，是一个强大的渗透测试工具。本着市面上各大漏洞探测插件的功能比较单一，TsojanScan 在已有框架的基础上修改并增加常用的漏洞探测POC，会以最少的数据包请求来准确检测各漏洞存在与否，你只需要这一个足矣。  
  
**漏洞扫描功能**  
：包括了对 Nacos 漏洞（CVE-2021-29441、QVD-2023-6271）的被动扫描，Fastjson 参数扫描，Spring Boot、Druid、Swagger 等相关漏洞的主动扫描，ThinkPHP 多语言 RCE 漏洞扫描，Ueditor 文件上传漏洞扫描等。  
  
**更新和修复**  
：修复了与 Burp Suite Pro 2024 版本的兼容问题，优化了发包逻辑，提高插件稳定性。更新了 DNSLog 平台，推荐使用 Ceye 或 Xssx1，解决了 DNSLog 连接的稳定性问题。还解决了 Weblogic 弱口令误报等 bug。  
  
**功能优化与增强**  
：优化了 SQL 注入的扫描策略和参数探测，减少了无用的探测进程，增加了自定义目录扫描（如 ThinkPHP 和 Weblogic）。同时，新增了黑名单功能，支持手动添加域名以避免重复扫描，提高了扫描效率。  
  
**平台支持和配置功能**  
：支持更多 DNSLog 平台的集成，并允许用户根据网络环境选择最佳的日志平台。增加了自定义延时功能，使得每个请求之间可以设置延迟，减少对目标系统的干扰。  
  
**其他改进**  
：包括对扫描结果窗口、配置文件管理的改进，减少插件资源占用，以及增强对不同版本 Weblogic、Spring、Fastjson、Shiro 等的漏洞检测能力。  
## 使用：  
#### 加载插件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HkIjj3EEBM9iaPAn0ZRibXnr1mXyia60FdLIkNKnvQtXgbDJks4HBHeA7mMyooQjJDQKJNcRPv4gWYUA/640?wx_fmt=png&from=appmsg "")  
#### 功能介绍  
#### （1）面板  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HkIjj3EEBM9iaPAn0ZRibXnr15hegoukzL7CUtYkC8JjxPLrCt7KutrJWSF7dFnZMtALCnchsS34nfQ/640?wx_fmt=png&from=appmsg "")  
  
自定义黑名单，插件不扫描黑名单的url列表，进行Reg匹配优先级第一。  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HkIjj3EEBM9iaPAn0ZRibXnr19DcWic5Tib0KmuqOd5NMedhfQnS0wj73KapxzSuBQ9jiawhkDhtnYHPkQ/640?wx_fmt=png&from=appmsg "")  
  
#### 主动探测  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HkIjj3EEBM9iaPAn0ZRibXnr13ytsJHVQ2ExfNelJnxW7Cic19CLxtHO5cQPYdmQeRUCX7uFaFiaUsaKg/640?wx_fmt=png&from=appmsg "")  
#### 扫描  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qGTEdaLg0HkIjj3EEBM9iaPAn0ZRibXnr19Zfy8dWz3Grj5wkNclSSiaMHwasmyM0OaKPXuOqcPUjIB3x8CYGicAWQ/640?wx_fmt=png&from=appmsg "")  
##### 项目地址：  
```
```  
  
  
