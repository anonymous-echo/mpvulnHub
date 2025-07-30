#  URL 跳转漏洞利用方式详解：不仅仅是钓鱼这么简单！   
原创 火力猫  季升安全   2025-04-16 09:38  
  
# 🚨 URL 跳转漏洞的危害与利用方式全解析  
## ☠️ 一、危害等级：中到高危  
  
<table><thead><tr style="box-sizing: border-box;"><th style="box-sizing: border-box;"><span cid="n8" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">类型</span></span></span></th><th style="box-sizing: border-box;"><span cid="n9" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">描述</span></span></span></th><th style="box-sizing: border-box;"><span cid="n10" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">危害等级</span></span></span></th></tr></thead><tbody><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n12" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">用户钓鱼</span></span></span></td><td style="box-sizing: border-box;"><span cid="n13" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">用户以为点了正常链接，实则跳转恶意网站</span></span></span></td><td style="box-sizing: border-box;"><span cid="n14" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">⭐⭐⭐</span></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n16" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">凭证盗取</span></span></span></td><td style="box-sizing: border-box;"><span cid="n17" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">配合 OAuth 可劫持登录凭证</span></span></span></td><td style="box-sizing: border-box;"><span cid="n18" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">⭐⭐⭐</span></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n20" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">权限绕过</span></span></span></td><td style="box-sizing: border-box;"><span cid="n21" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">在某些系统中可跳过登录、校验流程</span></span></span></td><td style="box-sizing: border-box;"><span cid="n22" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">⭐⭐</span></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n24" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">安全绕过</span></span></span></td><td style="box-sizing: border-box;"><span cid="n25" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">绕过 referer / 路由校验 / CSP 限制</span></span></span></td><td style="box-sizing: border-box;"><span cid="n26" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">⭐⭐</span></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n28" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">SSRF 辅助</span></span></span></td><td style="box-sizing: border-box;"><span cid="n29" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">用作跳板转发请求</span></span></span></td><td style="box-sizing: border-box;"><span cid="n30" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">⭐</span></span></span></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;"><span cid="n32" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">Cookie 误导</span></span></span></td><td style="box-sizing: border-box;"><span cid="n33" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">诱导域名混淆，伪造可信站点获取 Cookie</span></span></span></td><td style="box-sizing: border-box;"><span cid="n34" mdtype="table_cell" style="box-sizing: border-box;"><span md-inline="plain" style="box-sizing: border-box;"><span leaf="">⭐⭐</span></span></span></td></tr></tbody></table>## 🧠 二、典型利用场景  
### 🎣 1. 钓鱼攻击（Phishing）  
>   
> 利用目标网站的可信域名欺骗用户点击，跳转至恶意网站。  
  
#### 实例：  
```
https://secure.bank.com/login?redirect=https://evil.com/phish.html
```  
- 用户看到的是可信银行域名；  
  
- 一点击就跳转到钓鱼站；  
  
- **用于社工邮件极具欺骗性**  
。  
  
### 🔓 2. OAuth 绕回攻击（Token Theft）  
>   
> 配合 OAuth 登录系统窃取访问令牌。  
  
#### 攻击链：  
1. 正常流程中，OAuth 重定向参数（如 redirect_uri  
）未验证来源；  
  
1. 攻击者注册恶意站点作为 redirect_uri；  
  
1. 用户授权后，令牌被回传至攻击者控制的域名。  
  
#### 实例：  
```
https://auth.site.com/oauth?redirect_uri=https://evil.com/callback
```  
### ⛔ 3. 登录绕过 / 权限绕过  
>   
> 在某些系统，登录成功后使用跳转重定向回原地址。  
  
#### 示例：  
```
GET /login?next=https://admin.example.com
```  
  
如果没有校验登录态，攻击者可以用这个跳转绕过正常验证逻辑，进入高权限区域。  
### 🛡️ 4. 绕过 Referer 校验 / 路由限制  
>   
> 某些系统只允许从特定页面跳转，URL 跳转漏洞可**中转访问受限接口**  
。  
  
- 例如：支付页面要求必须从购物车页进入；  
  
- 攻击者用跳转漏洞构造伪 Referer，实现功能滥用。  
  
### 🔁 5. CSRF + 跳转链  
>   
> 构造恶意跳转链诱导用户访问恶意接口（结合 CSRF）。  
  
- https://trusted.com/jump?url=https://evil.com/csrf  
  
- 结合自动表单提交、图像加载等，绕过安全机制。  
  
## 🔐 三、防御思路总结  
  
<table><thead><tr><th style="color: rgb(0, 0, 0);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">措施</span></section></th><th style="color: rgb(0, 0, 0);font-size: 16px;line-height: 1.5em;letter-spacing: 0em;text-align: left;font-weight: bold;background: none 0% 0% / auto no-repeat scroll padding-box border-box rgb(240, 240, 240);height: auto;border-style: solid;border-width: 1px;border-color: rgba(204, 204, 204, 0.4);border-radius: 0px;padding: 5px 10px;min-width: 85px;"><section><span leaf="">建议说明</span></section></th></tr></thead><tbody><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">✅ 跳转白名单</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">仅允许跳转到预定义路径（如 </span><code><span leaf="">/home</span></code><span leaf="">、</span><code><span leaf="">/profile</span></code><span leaf="">）</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">✅ 中转确认页</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">提示用户即将离开当前站点</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">✅ URL 签名机制</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">用 HMAC 对跳转参数签名验证防止伪造</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(248, 248, 248);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">✅ 拒绝外部域名跳转</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">禁止以 </span><code><span leaf="">http</span></code><span leaf="">、</span><code><span leaf="">//</span></code><span leaf="">、</span><code><span leaf="">https</span></code><span leaf=""> 开头的跳转参数</span></section></td></tr><tr style="color: rgb(0, 0, 0);background-attachment: scroll;background-clip: border-box;background-color: rgb(255, 255, 255);background-image: none;background-origin: padding-box;background-position-x: 0%;background-position-y: 0%;background-repeat: no-repeat;background-size: auto;width: auto;height: auto;"><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">✅ 加强日志记录</span></section></td><td style="padding-top: 5px;padding-right: 10px;padding-bottom: 5px;padding-left: 10px;min-width: 85px;border-top-style: solid;border-bottom-style: solid;border-left-style: solid;border-right-style: solid;border-top-width: 1px;border-bottom-width: 1px;border-left-width: 1px;border-right-width: 1px;border-top-color: rgba(204, 204, 204, 0.4);border-bottom-color: rgba(204, 204, 204, 0.4);border-left-color: rgba(204, 204, 204, 0.4);border-right-color: rgba(204, 204, 204, 0.4);border-top-left-radius: 0px;border-top-right-radius: 0px;border-bottom-right-radius: 0px;border-bottom-left-radius: 0px;"><section><span leaf="">对所有跳转记录日志，便于审计取证</span></section></td></tr></tbody></table>  
## 🧪 四、实战渗透建议  
- **锁定接口**  
：扫描参数名为 redirect  
、next  
、url  
 的接口  
  
- **组合攻击**  
：搭配 OAuth、SSRF、SSO、CSRF 更容易出效果  
  
- **内网实战**  
：企业系统、管理后台、SSO 单点登录系统更容易出问题  
  
- 实战实例：[一次 OAuth 登录背后的隐患：被忽略的 URL 跳转漏洞](https://mp.weixin.qq.com/s?__biz=MzkxNjY5MDc4Ng==&mid=2247484660&idx=1&sn=a1b3e936aca842abd6567cf38e04b6ff&scene=21#wechat_redirect)  
  
  
  
  
  
