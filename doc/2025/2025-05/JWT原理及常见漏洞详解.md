#  JWT原理及常见漏洞详解   
小话安全  小话安全   2025-05-22 11:11  
  
一、JWT原理  
  
JSON Web Token（JWT）是一种开放标准（RFC 7519），用于在各方之间安全地传输信息。它通常用于身份验证（Authentication）和授权（Authorization），特别是在分布式系统和无状态服务中。以下是其核心原理和组成部分的详细介绍：  
### 1. JWT 的组成  
  
JWT 由三部分组成，以点号 .  
 分隔，形式为：Header.Payload.Signature  
。  
#### (1) Header（头部）  
- **作用**  
：描述 JWT 的元数据，如签名算法和令牌类型。  
  
- **内容**  
：一个 JSON 对象，通常包含两个字段：  
  
- alg  
：签名算法（如 HMAC SHA256、RSA 等）。  
  
- typ  
：令牌类型（固定为 JWT  
）。  
  
- **示例**  
：  
  
json  
  
- ```
```  
  
- **编码**  
：Base64Url 编码后形成 Header 部分。  
  
#### (2) Payload（负载）  
- **作用**  
：携带实际的数据（如用户身份、权限等），称为“声明”（Claims）。  
  
- **内容**  
：分为三类声明：  
  
- iss  
（签发者）、exp  
（过期时间）、sub  
（主题）、aud  
（受众）等。  
  
- **注册声明（Registered Claims）**  
：预定义的标准化字段（非强制但建议使用），例如：  
  
- **公共声明（Public Claims）**  
：自定义字段，但需避免与已有声明冲突。  
  
- **私有声明（Private Claims）**  
：服务间协商的自定义字段。  
  
- **示例**  
：  
  
json  
  
- ```
```  
  
- **编码**  
：Base64Url 编码后形成 Payload 部分。  
  
#### (3) Signature（签名）  
- **作用**  
：验证令牌的完整性和来源的真实性，防止数据篡改。  
  
- **生成方式**  
：将 Header 和 Payload 的 Base64Url 编码结果用 .  
 连接，再使用 Header 中指定的算法和密钥（Secret）进行签名。  
  
- **示例**  
（HMAC SHA256 算法）：  
  
js  
  
- ```
```  
  
- **验证方式**  
：接收方用相同算法和密钥重新计算签名，与 JWT 中的签名比对。  
  
### 2. JWT 的工作流程  
1. **用户登录**  
：客户端发送凭证（如用户名密码）到认证服务器。  
  
1. **生成 JWT**  
：服务器验证凭证后，生成 JWT 并返回给客户端。  
  
1. **客户端存储**  
：客户端（如浏览器）将 JWT 保存在本地（如 LocalStorage 或 Cookie）。  
  
1. **发送 JWT**  
：客户端在后续请求的 Authorization  
 头中附带 JWT（格式：Bearer <token>  
）。  
  
1. **服务器验证**  
：服务器验证 JWT 的签名和有效期，并处理请求。  
  
### 3. JWT 的核心特性  
- **无状态（Stateless）**  
：服务端无需存储会话信息，所有数据包含在令牌中。  
  
- **自包含（Self-contained）**  
：Payload 可直接解析出用户信息，减少数据库查询。  
  
- **跨域支持**  
：适用于分布式系统和跨域场景（如单点登录 SSO）。  
  
- **安全性**  
：通过签名防篡改，但需结合 HTTPS 防止令牌泄露。  
  
### 4. 安全性注意事项  
1. **密钥保护**  
：签名密钥（Secret）必须严格保密，泄露将导致令牌可被伪造。  
  
1. **敏感数据**  
：Payload 仅 Base64 编码，非加密！**切勿存储密码等敏感信息**  
。  
  
1. **有效期控制**  
：设置合理的 exp  
 过期时间，避免长期有效的令牌。  
  
1. **HTTPS 传输**  
：防止令牌在传输过程中被窃取（如中间人攻击）。  
  
1. **算法选择**  
：避免使用弱算法（如 none  
 或 HS256  
 密钥过短）。  
  
### 5. JWT 的常见应用场景  
- 用户身份认证（替代 Session-Cookie 模式）。  
  
- API 接口鉴权（如 OAuth 2.0 的 Bearer Token）。  
  
- 服务间安全通信（微服务架构）。  
  
- 单点登录（SSO）系统。  
  
### 6. JWT 的优缺点  
<table><thead><tr><th style="color: rgb(64, 64, 64);padding: 10px 10px 10px 0px;border-bottom: 1.11111px solid rgb(187, 187, 187);border-top: none;font-weight: 600;font-size: 15px;line-height: 1.72;border-right-color: rgb(187, 187, 187);border-left-color: rgb(187, 187, 187);text-align: left;"><strong><span leaf=""><span textstyle="" style="font-size: 15px;">优点</span></span></strong></th><th style="color: rgb(64, 64, 64);padding: 10px;border-bottom: 1.11111px solid rgb(187, 187, 187);border-top: none;font-weight: 600;font-size: 15px;line-height: 1.72;border-right-color: rgb(187, 187, 187);border-left-color: rgb(187, 187, 187);text-align: left;"><strong><span leaf=""><span textstyle="" style="font-size: 15px;">缺点</span></span></strong></th></tr></thead><tbody><tr><td style="padding: 10px 10px 10px 0px;border-bottom: 1.11111px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section style="margin-top: 0px;margin-bottom: 0px;"><span leaf=""><span textstyle="" style="font-size: 15px;">无状态，适合分布式系统</span></span></section></td><td style="padding: 10px;border-bottom: 1.11111px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section style="margin-top: 0px;margin-bottom: 0px;"><span leaf=""><span textstyle="" style="font-size: 15px;">令牌一旦签发，无法直接废止（需依赖短有效期或黑名单）</span></span></section></td></tr><tr><td style="padding: 10px 10px 10px 0px;border-bottom: 1.11111px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section style="margin-top: 0px;margin-bottom: 0px;"><span leaf=""><span textstyle="" style="font-size: 15px;">减少数据库查询（自包含数据）</span></span></section></td><td style="padding: 10px;border-bottom: 1.11111px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section style="margin-top: 0px;margin-bottom: 0px;"><span leaf=""><span textstyle="" style="font-size: 15px;">Payload 数据过大可能影响性能</span></span></section></td></tr><tr><td style="padding: 10px 10px 10px 0px;border-bottom: 1.11111px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section style="margin-top: 0px;margin-bottom: 0px;"><span leaf=""><span textstyle="" style="font-size: 15px;">跨语言、跨平台支持</span></span></section></td><td style="padding: 10px;border-bottom: 1.11111px solid rgb(229, 229, 229);font-size: 15px;line-height: 1.72;border-top-color: rgb(229, 229, 229);border-right-color: rgb(229, 229, 229);border-left-color: rgb(229, 229, 229);min-width: 100px;max-width: max(30vw, 320px);"><section style="margin-top: 0px;margin-bottom: 0px;"><span leaf=""><span textstyle="" style="font-size: 15px;">需自行处理安全性细节（如密钥管理）</span></span></section></td></tr></tbody></table>### 7. 示例 JWT  
```
```  
  
解码后：  
- **Header**  
：{"alg":"HS256","typ":"JWT"}  
  
- **Payload**  
：{"sub":"1234567890","name":"John Doe","iat":1516239022}  
  
二、JWT常见漏洞  
### 1. 算法篡改（Algorithm None Attack）  
- **漏洞原理**  
：  
  
JWT 头部中的 alg  
 字段指定签名算法，若服务器未严格验证算法类型，攻击者可篡改为 none  
（表示无签名），绕过签名验证。  
  
- **攻击方式**  
：  
  
修改 Header 中的 alg  
 为 none  
，删除 Signature 部分，构造未签名的令牌。  
  
json  
  
- ```
```  
  
- **防御方法**  
：  
  
- 服务器端强制校验 alg  
 字段，禁止使用 none  
 算法。  
  
- 使用安全的签名算法（如 HS256  
、RS256  
），避免接受客户端指定的算法。  
  
### 2. 弱密钥（Weak Secret Key）  
- **漏洞原理**  
：  
  
使用简单密钥（如 secret  
、password  
）或短密钥进行签名，易被暴力破解或字典攻击。  
  
- **攻击方式**  
：  
  
攻击者通过穷举或已知密钥列表破解密钥，伪造有效签名。  
  
- **防御方法**  
：  
  
- 使用强密钥（长度 ≥ 32 字节，随机生成）。  
  
- 定期更换密钥。  
  
- 对密钥进行安全存储（如密钥管理系统）。  
  
### 3. 敏感信息泄露（Information Leakage）  
- **漏洞原理**  
：  
  
JWT 的 Payload 仅进行 Base64 编码（非加密），若存储敏感数据（如密码、密钥），可被中间人攻击或客户端解码泄露。  
  
- **攻击示例**  
：  
  
json  
  
- ```
```  
  
- **防御方法**  
：  
  
- **绝不存储敏感信息**  
（如密码、密钥）在 Payload 中。  
  
- 使用 HTTPS 加密传输。  
  
- 必要时对 Payload 加密（如 JWE）。  
  
### 4. 签名未验证（Ignored Signature Verification）  
- **漏洞原理**  
：  
  
服务器未正确验证 JWT 签名，直接信任 Payload 中的数据。  
  
- **攻击方式**  
：  
  
攻击者篡改 Payload（如将 "role": "user"  
 改为 "role": "admin"  
），服务器未校验签名则接受非法请求。  
  
- **防御方法**  
：  
  
- **始终验证签名**  
，拒绝无效或未签名的令牌。  
  
- 使用标准库（如 jsonwebtoken  
）而非自行实现签名验证逻辑。  
  
### 5. 密钥混淆攻击（Key Confusion Attack）  
- **漏洞原理**  
：  
  
当服务端支持多种算法（如 HS256  
 和 RS256  
）时，攻击者可能将非对称算法（RS256）的公钥作为对称算法（HS256）的密钥进行签名。  
  
- **攻击方式**  
：  
  
- 假设服务端使用 RS256（私钥签名，公钥验证）。  
  
- 攻击者将 alg  
 改为 HS256，并用公钥作为 HMAC 的密钥生成签名。  
  
- 服务端误用公钥以 HS256 验证签名，导致通过校验。  
  
- **防御方法**  
：  
  
- 严格限制支持的算法类型（如仅允许 RS256  
）。  
  
- 密钥分离：不同算法使用不同密钥。  
  
### 6. 令牌泄露（Token Leakage）  
- **漏洞原理**  
：  
  
JWT 被窃取后，攻击者可利用其进行身份冒充（因服务端无状态，无法主动废止令牌）。  
  
- **泄露途径**  
：  
  
- XSS 攻击窃取 LocalStorage 中的令牌。  
  
- 中间人攻击（未使用 HTTPS）。  
  
- 客户端日志、缓存泄露。  
  
- **防御方法**  
：  
  
- 使用 HttpOnly  
 + Secure  
 的 Cookie 存储令牌（防 XSS）。  
  
- 设置较短的令牌有效期（exp  
）。  
  
- 结合黑名单机制（如 Redis 记录已注销令牌）。  
  
### 7. 无效的密钥管理（Poor Key Management）  
- **漏洞原理**  
：  
  
密钥硬编码在代码中、使用默认密钥（如 secret  
）或密钥轮换策略缺失。  
  
- **攻击方式**  
：  
  
攻击者通过代码泄露、逆向工程获取密钥，伪造任意令牌。  
  
- **防御方法**  
：  
  
- 密钥存储在安全环境（如环境变量、密钥管理系统）。  
  
- 禁止使用默认密钥。  
  
- 定期轮换密钥并兼容旧密钥过渡。  
  
### 8. 未设置过期时间（Missing Expiration Claim）  
- **漏洞原理**  
：  
  
JWT 未设置 exp  
（过期时间）或 nbf  
（生效时间），导致长期有效。  
  
- **攻击方式**  
：  
  
攻击者窃取令牌后无限期使用。  
  
- **防御方法**  
：  
  
- 强制设置较短的 exp  
（如 15 分钟）。  
  
- 结合 Refresh Token 机制续签令牌。  
  
### 9. 头部注入（Header Injection）  
- **漏洞原理**  
：  
  
篡改 JWT 头部参数（如 kid  
、jku  
、x5u  
）指向攻击者控制的密钥或证书。  
  
- **kid 攻击**  
：kid  
（Key ID）用于指定密钥，若未校验来源，攻击者可指向恶意密钥。  
  
- **jku 攻击**  
：jku  
（JWK Set URL）指定远程公钥地址，攻击者可伪造 URL 提供恶意公钥。  
  
- **防御方法**  
：  
  
- 校验 kid  
 的合法性（如仅允许白名单内的 Key ID）。  
  
- 禁用动态 jku  
 或限制域名（如仅允许可信 URL）。  
  
### 10. 其他漏洞  
- **空加密算法（Empty Encryption）**  
：  
  
某些库可能接受 alg  
 为 none  
 的加密令牌（如 JWE），需禁用空加密。  
  
- **CSRF 攻击**  
：  
  
若通过 Cookie 存储 JWT，需配置 SameSite  
 属性防范 CSRF。  
  
- **令牌压缩问题**  
：  
  
部分实现可能因压缩（如 DEFLATE  
）导致敏感信息泄露（如 BREACH 攻击），建议禁用压缩。  
  
### 防御最佳实践  
1. **使用标准库**  
（如 jsonwebtoken  
、java-jwt  
），避免自行实现。  
  
1. **强制校验算法**  
，禁用 none  
 和弱算法。  
  
1. **限制令牌有效期**  
，结合 Refresh Token。  
  
1. **密钥管理**  
：强密钥、定期轮换、安全存储。  
  
1. **敏感数据不存储**  
在 Payload 中。  
  
1. **启用 HTTPS**  
，防止中间人攻击。  
  
1. **安全存储令牌**  
：优先使用 HttpOnly  
 + Secure  
 Cookie。  
  
1. **审计和监控**  
：记录令牌使用情况，检测异常行为。  
  
三、例题  
  
例题1  
  
打开题目提示where is flag？  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0LTz7Lex94Xn7xGwLyMIElEPpetSnKu27eHUp28snCdS4TaFR1w6qvo5Qj1tBFNNvfqLGQIYBoazWQuF4qcmNg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0LTz7Lex94Xn7xGwLyMIElEPpetSnKu2vn3J79wHLsyuLRpjOZrRqkgJxpDhouboS7urA5Wcc5xxZGF0hwWCiaA/640?wx_fmt=png&from=appmsg "")  
  
  
查看jwt  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0LTz7Lex94Xn7xGwLyMIElEPpetSnKu2eq413cGyiciaD9Uic6MBS3CIGQia7jpjmwWsliaSywLWLckqbx225wOOtrA/640?wx_fmt=png&from=appmsg "")  
  
没有签名部分，只有 jwt 的前两部分 header 和   
payload  
  
[{\"iss\":\"admin\",\"iat\":1747818302,\"exp\":1747825502,\"nbf\":1747818302,\"sub\":\"user\",\"jti\":\"9866d74eed9b349d33dbe98c23ae12f3\"}]  
  
iss  
: 签发者是admin  
  
- iat/nbf: 签发时间是1695185318   
  
- exp: 过期时间是1695192518  
  
- sub: 面向用户user  
  
- jti:   
JWT  
唯一标识符  
  
把None改成HS256，把user改成admin，重新进行base64编码，访问路径为/admin/，最终获得flag。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0LTz7Lex94VjREL0E5ibld1OzbyG2AURh5OuTsMfuhxiafPcN7hjC46S2zGyLEOyZf4UVIRKb7HwgwfuoibCkAdng/640?wx_fmt=png&from=appmsg "")  
  
这里要注意访问的是/admin/而不是/admin因为访问/admin表示访问admin.php而访问/admin/表示访问的是admin目录下默认的index.php  
  
例题2  
  
某些服务端未校验JWT签名，可以尝试修改payload或者直接删除signature再次请求查看是否有效。  
  
alg字段改为none，sub改为admin，对每一段分别用base64进行加密，然后用.拼接起来，**注意最后一个点不能少**  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0LTz7Lex94VjREL0E5ibld1OzbyG2AURh5vb19H0nFwJibuicNp3JPIPPGBplSAQ8CrZJ5vBFBT3kWWBO3a8icZODA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0LTz7Lex94VjREL0E5ibld1OzbyG2AURhVpK6NX741bvDtricey7R8Wtfj0pfWwwS23tglZWTI6PTzdPDq8tLd2w/640?wx_fmt=png&from=appmsg "")  
  
  
