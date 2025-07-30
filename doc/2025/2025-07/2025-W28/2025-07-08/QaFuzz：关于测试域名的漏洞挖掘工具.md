> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2NTkwODU3Ng==&mid=2247515396&idx=1&sn=cd3c577b9492d4197fee6394c426a21a

#  QaFuzz：关于测试域名的漏洞挖掘工具  
 东方隐侠安全团队   2025-07-08 17:22  
  
### 引言工具地址：https://github.com/darkfiv/QaFuzz作者：东方隐侠安全团队 DarkFi5在挖掘某SRC的过程中，我发现了一种适用于该SRC的通用挖掘思路。随笔记录下来，希望能为师傅们带来一些收获和灵感。  
## 背景  
  
在对某SRC进行挖掘时，发现其域名为  

```
aaa.bbb.com
```

  
。通过工具 
```
findsomething
```

  
 进行被动信息收集，发现了类似 
```
aaa.test.bbb.com
```

  
 的域名。相信挖过SRC的师傅们都知道，许多企业会将测试环境的域名开放到公网。虽然这些测试域名在实际的安全运营场景中通常是不允许公开的，但业务的不规范以及特殊需求（如联合调试、Bug测试等）往往导致这些测试域名暴露在外。  
  
测试环境通常是企业安全体系中最薄弱的环节。因为测试应用往往缺乏严格的安全审核，导致其成为攻击者的重点目标。找到这些测试资产，通常能带来意想不到的收获，甚至挖掘出高危漏洞！  
## 思路解析  
  
基于这种特殊的业务场景，我挖到了大量漏洞，虽然多数是中低危，但也偶尔发现高危漏洞。积累起来后，也是一笔相对客观的收入。下面是我开发这款工具的核心思路，希望能给师傅们带来收获、灵感！  
### 测试域名的常见特征  
  
经过日常测试经验总结，发现测试域名通常具有以下特征：  
  
1、域名格式  
 测试域名通常包含类似 
```
stage
```

  
、
```
test
```

  
、
```
dev
```

  
 等关键字。例如：  
- 原域名：
```
www.baidu.com
```

  
  
- 测试域名：
```
www.stage.baidu.com
```

  
、
```
www.test.baidu.com
```

  
、
```
www.dev.baidu.com
```

  
  
2、DNS解析结果  
 测试域名解析出的 IP 地址通常为外网地址，而非内网地址（内网 IP 无法直接访问）。  
  
3、响应状态码  
 测试域名的 API 或目录访问状态码通常不为 
```
403
```

  
。如果状态码为 
```
403
```

  
，则可能是运维对该路径从外网做了访问限制。  
### 自动化挖掘流程  
  
基于上述特征，可以通过以下步骤进行自动化挖掘：  
1. 生成测试域名  
 根据已知域名，添加自定义测试关键字（如 
```
qa
```

  
、
```
test
```

  
、
```
dev
```

  
 等），生成可能的测试域名。  
  
1. DNS解析验证  
 对生成的测试域名进行 DNS 解析，判断解析出的 IP 是否为外网地址。若解析超时或失败，说明域名指向内网。  
  
1. 请求测试目录  
 在满足外网 IP 条件的情况下，使用与原域名相同的目录路径进行请求，判断响应状态码是否不为 
```
403
```

  
。  
  
1. 联动漏洞扫描工具  
 若测试域名存在且响应状态码符合条件，则联动其他工具（如 
```
Onescan
```

  
、
```
Apikit
```

  
 等）对其进行漏洞扫描。例如：  
  
1. 扫描未授权访问（如 Swagger 文档、Spring Boot 环境配置等）。  
  
1. 挖掘测试域名中潜在漏洞，逻辑漏洞为主。  
  
## 工具实战：QaFuzz  
  
为了满足上述漏洞挖掘场景的需求，我开发这款自动化工具——  
QaFuzz  
，专门用于测试域名的挖掘。以下是工具的使用流程：  
### 1. 配置测试关键字  
  
首先，根据目标 SRC 的域名习惯，配置测试关键字（如
```
qa
```

  
、
```
test
```

  
、
```
dev
```

  
 等）。例如：  
- 原域名：
```
www.baidu.com
```

  
  
- 自动生成测试域名：
```
www.qa.baidu.com
```

  
、
```
www.test.baidu.com
```

  
 等。  
  
### 2. 被动信息收集  
  
通过
```
site:xxx.com
```

  
 检索隐藏资产。例如，发现某登录系统，流量如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4icYKM8qlnjOkqqBZViakKMzyWcgxPHWgQbYTs981WgD9ySJu2dsibXnibyhHrft0WExF73mIwDjQzRw/640?wx_fmt=png&from=appmsg "")  
  
  
右键发送流量到  
QaFuzz  
 模块：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4icYKM8qlnjOkqqBZViakKMzExBThjuE2TTqtojfPerzPlOmmYmFbNUqxacCnOD8VlDplBoYG094rw/640?wx_fmt=png&from=appmsg "")  
  
### 3. 测试结果  
  
工具会自动解析域名、判断是否符合外网条件，并进行目录请求测试。如下图所示：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4icYKM8qlnjOkqqBZViakKMzmFlxFwXzuaRIBDSZYakVxHUqgkgkaRtp51vtQyjxibKyibB7c1jGpKzQ/640?wx_fmt=png&from=appmsg "")  
  
### 4. 联动漏洞扫描工具  
  
将工具发现的外网测试资产请求发送至其他工具（如
```
Onescan
```

  
、
```
Apikit
```

  
），进行进一步的漏洞扫描：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4icYKM8qlnjOkqqBZViakKMzDUribRu9DmfpDKRticnGZBUapzODGWEhHicxKATnIh3WOt306CLUufDAA/640?wx_fmt=png&from=appmsg "")  
  
  
OneScan成功发现漏洞如下：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4icYKM8qlnjOkqqBZViakKMzPNIrib93V3db2Ctq8AjbYAw8ic8GMvprg1LPQiaTFeFbJ1A8uX1S4GVvA/640?wx_fmt=png&from=appmsg "")  
  
  
例如，通过 Swagger 文档挖掘接口信息，从而发现更多潜在漏洞，这里笔者也是通过swagger进一步探测，发现了包括但不限于无回显ssrf、批量用户信息泄漏等，后面再跟大家分享吧！  
## 总结  
  
测试域名的挖掘只是测试资产的一部分，其背后可能隐藏着更多暴露点。例如：  
- 测试环境的默认账号密码  
  
- 内部调试工具的公开访问  
  
- 未授权的接口或敏感信息泄露  
  
希望这篇文章能启发大家，在挖掘 SRC 时放开思维，深入探索这些测试资产。让漏洞无处遁形！  
  
  
如果你有类似的经验或工具开发思路，欢迎分享交流，共同提升挖掘效率！  
  
项目地址：  
  
QaFuzz：https://github.com/darkfiv/QaFuzz  
  
OneScan：https://github.com/vaycore/OneScan  
  
APIKit：https://github.com/API-Security/APIKit  
###   
###   
  
关注东方隐侠安全团队 一起打造网安江湖  
  
        
  东方隐侠安全团队，一支专业的网络安全团队，将持续为您分享红蓝对抗、病毒研究、安全运营、应急响应等网络安全知识，提供一流网络安全服务，敬请关注！  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH7zgibKsqKmX3H4AatvwPeXFsrHGpp0RsxLJpzgd0cyiaPH2HDnfv4GMdxf0lkGjAibiaBtFcLmnm2ZkA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
  
  
公众号｜东方隐侠安全团队  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4laNHWaR5yOd2VbInJbO4h3daHtdT7pcSk7zONRMDyl2cht3U4dbbyiaLmMA5DpBBlTgspa3agKyw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
  
  
请添加团队微信号  
｜东方隐侠安全团队  
  
用于拉少侠们进团队交流群  
  
