#  漏洞挖掘 | Swagger UI 目录枚举小总结   
白帽子左一  白帽子左一   2024-12-19 04:00  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**来****Track安全社区投稿~**  
  
**赢千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
# 通过 Swagger UI 目录枚举挖掘漏洞  
## 前言  
  
Swagger UI 被广泛用于可视化和交互式操作 API，但开发人员经常错误配置它，或无意间暴露了敏感的端点。通过掌握 Swagger UI 目录枚举，发现许多高影响力的漏洞，而这些漏洞常常被他人忽视。本文将分享一些方法、发现以及一些技巧。  
## 什么是 Swagger UI?  
  
对于不熟悉的人来说，Swagger UI 是一个开源的 API 文档工具，帮助开发人员设计、构建并记录 REST API。它通常会暴露一些端点以便测试和调试使用。虽然对开发人员来说十分便利，但 **错误配置的 Swagger UI 可能泄露敏感信息**，比如隐藏的目录、端点或参数。  
  
以下是应该关注的点：  
  
许多 **敏感端点** 往往被意外暴露。  
  
Swagger UI 可能泄露 **内部 API** 或配置。  
  
它可以帮助你 **绘制应用程序的攻击面**。  
  
测试起来很简单，但一旦配置错误，很难保证安全。  
## Swagger UI 枚举技巧  
  
以下是一些专业级别的目录提取和枚举方法，这些方法基于真实发现和实际漏洞案例：  
### 1. 定位 Swagger UI 文件  
  
首先，识别 Swagger 文件所在的位置。以下是一些常见的 Swagger UI URL，可以重点检查：  
```
https://example.com/swagger.json  
https://example.com/swagger/v1/swagger.json  
https://example.com/api/swagger.json  
https://example.com/api-docs  
https://example.com/swagger-ui.html
```  
  
使用 **Gau、Wayback Machine** 或 **Google Dorks** 工具：  
  
inurl:swagger.json site:example.com  
  
intitle:"Swagger UI" inurl:/api-docs  
### 2. 分析 Swagger JSON 文件  
  
获取 swagger.json 文件后，下载并搜索其中的目录和端点。重点查找：  
  
**隐藏路径**（例如：/admin、/internal、/debug、/v2/api）  
  
**已废弃的端点**  
  
**敏感参数**（例如：API 密钥、令牌）  
  
**示例：**  
```
"paths": {  
    "/admin/debug": {  
        "get": {  
            "description": "Access debug info"  
        }  
    },  
    "/internal/config": {  
        "post": {  
            "description": "Post internal configurations"  
        }  
    }  
}
```  
### 3. 检测错误配置  
  
在绘制出目录结构后，针对以下漏洞进行测试：  
  
**身份验证缺失**：例如 /admin 或 /internal 路径无需凭证即可访问。  
  
**敏感数据暴露**：目录暴露了内部配置、调试日志或凭据。  
  
**IDOR（越权漏洞）**：检查是否存在可操控的对象 ID 或与用户相关的端点。  
## 4. 自动化目录枚举  
  
为了提高速度和效率，可以通过自动化工具进行测试：  
  
使用 **工具**（如 ffuf）或 **自定义脚本** 对从 Swagger 文件中提取的目录进行暴力枚举。示例：  
```
cat swagger.json | jq -r '.paths | keys[]' | ffuf -u https://example.com/FUZZ
```  
  
结合 **Burp Suite** 进行更深入的 API 分析。  
## 真实案例发现  
  
以下是通过 Swagger 枚举发现的一些漏洞：  
  
  
1.**未保护的管理员端点**：访问 /admin/debug 泄露了服务器日志。  
  
2.**敏感数据暴露**：Swagger JSON 在查询参数中泄露了硬编码的 API 密钥。  
  
3.**隐藏 API**：一个已废弃的 /internal/config 端点导致了权限提升。  
  
  
这些问题通常被传统扫描器忽略，因为它们未深入分析 Swagger 文件。  
## 最大化 Swagger 枚举的技巧  
  
  
1.**始终检查** /swagger.json **和** /api-docs **中暴露的端点。**  
  
2.**在自动化之前进行手动分析**。这有助于捕捉微妙的错误配置。  
  
3.**查找过时或废弃的端点**。开发人员往往会忘记删除它们。  
  
4.**彻底测试所有参数**，寻找注入漏洞、身份验证问题或 IDOR。  
  
5.**提交报告时附上明确的 POC**，展示枚举步骤及其影响。  
  
## Swagger UI 错误配置的影响  
  
Swagger UI 配置错误可能导致以下 **严重的安全风险**：  
  
**信息泄露**：敏感目录、凭据和服务器信息的泄露。  
  
**未经授权的访问**：无需身份验证即可访问内部或管理员 API。  
  
**权限提升**：隐藏端点允许执行关键操作。  
  
**服务中断**：调试 API 暴露服务器漏洞。  
## 总结  
  
Swagger UI 对开发者来说是一个强大的工具，但一旦配置错误，也可能成为“双刃剑”。通过对 Swagger 文件的深入枚举，你可以发现隐藏的目录和端点，这些往往会导致高影响力的漏洞。  
## Swagger UI 列表  
  
一份 **独特的 Swagger UI 目录列表**，可以直接在漏洞挖掘中使用。地址：https://github.com/hackersatty/Bug-Bounty/blob/Directory-Enumeration/swagger-directory-enumeration。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSG2ic5t1C5Pwoe0psBRqjOwaHPSeJGFqnlcialGTebQfPQSJEibYMr9h3HmHMZu0XByx0aBmmzKcgWog/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前沿漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，即可加入。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFIJlRFYoItlJDrScxuTPmfnqibC1ApJ2OKh5sF41qicCo5AvQ4icuG8kbqQxZ5HVypvJ8jZDzsmD37Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
