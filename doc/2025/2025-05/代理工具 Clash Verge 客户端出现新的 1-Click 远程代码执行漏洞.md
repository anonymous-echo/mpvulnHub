#  代理工具 Clash Verge 客户端出现新的 1-Click 远程代码执行漏洞   
原创 JunYi  毅心安全   2025-05-22 16:01  
  
   
  
# 代理工具 Clash Verge 客户端出现新的 1-Click 远程代码执行漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/kzkqdAEDfXehmEVEFaA1ooA3B17dFL6TGp2uRl1z5OhkWBmKTjQWuicicZPrv0icqrxsiaEIPA8zo4iaABZUZUrSQ4A/640?wx_fmt=gif "null")  
  
  
代理工具 Clash Verge 客户端出现新的 1-Click 远程代码执行漏洞，访问特制的恶意网页即可触发本地文件写入，进一步利用各种软件的插件加载机制将文件写入扩展至 REC 漏洞。  
  
该漏洞影响 Clash Verge 最新版 (v2.2.4 alpha)，漏洞原因则是 Clash Verge Rev 的默认配置问题，在默认配置下，客户端会在本地 127.0.0.1:9097 开启一个未经验证的 API 服务接口，该接口还存在 CORS 跨域资源共享问题。  
  
当用户运行并打开特制的恶意网站时，网站代码可以和这个 API 通信并修改 Clash 核心的配置文件，通过配置文件中的特定字段绕过路径检查实现本地写入，再利用插件机制部署插件后实现后阶段的 RCE。  
### 临时修复方法：  
  
1、打开 Clash Verge 点击设置、Clash 设置、外部控制、添加密码验证。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kzkqdAEDfXehmEVEFaA1ooA3B17dFL6TceGGjcYazceeYZg92PgAXIdwM6BOxnM32FOWhNvic7Zwyv1maSf3fUQ/640?from=appmsg "null")  
  
  
   
  
  
