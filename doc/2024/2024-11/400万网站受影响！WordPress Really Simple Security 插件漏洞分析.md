#  400万网站受影响！WordPress Really Simple Security 插件漏洞分析   
云梦DC  云梦安全   2024-11-20 01:05  
  
近日，WordPress 插件**Really Simple Security**  
（原名 Really Simple SSL）被披露存在一个高危的认证绕过漏洞。该漏洞可能导致攻击者远程获得受影响网站的管理权限，危害极大。本篇文章将对漏洞细节、影响范围、修复情况及防护措施进行全面分析。![](https://mmbiz.qpic.cn/mmbiz_png/ndxZsFvkmpxiaKyI98MJklzBBWSGT8MAicmSuPZcKrZYh134OtlntbJtycHxTzWfPWZGr88P9JaESgyLZsmrGdyA/640?wx_fmt=png&from=appmsg "")  
  
#### 漏洞概述  
  
CVE-2024-10924 是 Really Simple Security 插件的认证绕过漏洞，漏洞评分高达**9.8（CVSS）**  
，属于严重级别。漏洞利用了插件的check_login_and_get_user  
 函数中的错误处理，允许攻击者在启用双因素认证（2FA）的情况下，冒充任意用户（包括管理员）登录受影响的网站。![](https://mmbiz.qpic.cn/mmbiz_png/ndxZsFvkmpxiaKyI98MJklzBBWSGT8MAicmSuPZcKrZYh134OtlntbJtycHxTzWfPWZGr88P9JaESgyLZsmrGdyA/640?wx_fmt=png&from=appmsg "")  
  
  
此漏洞影响了插件**9.0.0 至 9.1.1.1 版本**  
，包括免费和付费版本，波及超过**400万 WordPress 网站**  
。Wordfence 安全研究员 István Márton 警告称，该漏洞非常容易被脚本化，从而引发针对 WordPress 网站的大规模自动化攻击。  
#### 漏洞细节分析  
  
**Really Simple Security 插件的核心功能是增强 WordPress 网站的安全性**  
，包括启用 HTTPS、提供双因素认证等。然而，该漏洞的成因却来自插件对 2FA 认证逻辑的错误处理。  
  
具体来说，漏洞位于check_login_and_get_user  
 函数，该函数负责验证用户的身份。然而，由于逻辑缺陷，攻击者可以通过构造恶意请求绕过身份验证。例如：  
- **函数中未正确处理认证失败的情况**  
，直接返回了管理员凭据；  
  
- **缺乏对认证数据完整性的验证**  
，导致攻击者可以伪造凭据。  
  
这种设计缺陷使得攻击者可以直接冒充管理员登录，获得对网站的完全控制权限。  
##### 利用场景  
  
插件的 REST API 暴露了skip_onboarding  
 接口，允许未经验证的用户提交登录请求。通过构造包含伪造参数的 POST 请求，攻击者可以利用该接口跳过 2FA 验证并获取登录状态。  
##### PoC 请求示例  
```
POST /wp-json/reallysimplessl/v1/two_fa/skip_onboarding HTTP/1.1 Host: kubernetes.docker.internal User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:132.0) Gecko/20100101 Firefox/132.0 Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8 Accept-Language: en-US,en;q=0.5 Accept-Encoding: gzip, deflate, br Content-Type: application/json; Connection: keep-alive Content-Length: 90 { "user_id":1, "login_nonce": "231231231", "redirect_to": "/wp-admin/" }

```  
##### 请求参数解析  
- **user_id**  
：目标用户的 ID（例如，管理员账户通常为1  
）。  
  
- **login_nonce**  
：伪造的登录令牌，插件未验证该值的真实性。  
  
- **redirect_to**  
：登录成功后的重定向目标地址，此处指向/wp-admin/  
 管理后台。  
  
poc：https://github.com/FoKiiin/CVE-2024-10924  
  
  
