#  Kindeditor编辑器漏洞挖掘   
原创 锐鉴安全  锐鉴安全   2025-06-05 11:38  
  
声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。  
  
关注公众号，设置为星标，  
不定期有宠粉福利  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP4ricRiaXQ6WVVlTAgCW8HUbC2rHkicA2rpDNEPAGyiatRibqB9LN5NyHcqLCmbibM1siaumqF5Yu6UtSsYA/640?wx_fmt=png "")  
  
  
在edu src信息收集完，发现某证书站的投稿模块。    
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP6nLus9xqINY4ohxzzNGmuvvlHyQdYYLVhfERku6G7hw6k4LzibDFPLqfSdyjbQjibFf0Ip9dlPF0iag/640?wx_fmt=png&from=appmsg "")  
  
  
点击？发现富文本编辑器的情况及版本信息。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP6nLus9xqINY4ohxzzNGmuvHiaMgJ9huCXyCic7LIBWVIsIETib9KA8PCSEjNDPvZAIsZbw7SvyV69icw/640?wx_fmt=png&from=appmsg "")  
  
  
查了下版本对应的漏洞情况，存在任意文件上传漏洞，使用poc测试了下，貌似已被修复，无法利用。pco如下，各位师傅后续遇到可以进行探测，只有在存在以下路径的情况下才可利用。在本案例中使用的jsp版本不存在。  
  
   
  
是否存在有必要验证文件upload_json.*，常见判断路径如下：  
  
kindeditor/asp/upload_json.asp?dir=file  
  
kindeditor/asp.net/upload_json.ashx?dir=file  
  
kindeditor/jsp/upload_json.jsp?dir=file  
  
kindeditor/php/upload_json.php?dir=file  
  
     
  
进一步对前端的编辑器进行测试。直接输入相关的xss语句，在前端已被转义，无法进行利用。  
  
经过尝试每个功能，发现此处可以插入html语句功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP6nLus9xqINY4ohxzzNGmuvh7hHNQsficsppkvIC4ML0VeVKr6ichxUzoOOU9luVGYb4Mhf1lU43k8g/640?wx_fmt=png&from=appmsg "")  
  
点击后，在文本框中输入xss语句。  
```
<a ref=javascript:alert(1)>a</a>。
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP6nLus9xqINY4ohxzzNGmuvA32CxaiceZBceWqWRTEK8iaooYZpBetCBvwWib08zn1Zgwwhv3zfKnODg/640?wx_fmt=png&from=appmsg "")  
  
  
完后点击恢复。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP6nLus9xqINY4ohxzzNGmuvg4venSbQe4aD7AGdqd8RlNkk2B67TohuictC6BE1v0eRJAiaCLBmZSWQ/640?wx_fmt=png&from=appmsg "")  
  
  
已成功插入至文本编辑器中，出现了点击url。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP6nLus9xqINY4ohxzzNGmuvQtE31zyr6bo2TCPe0artnuG8UNR83y2p73maK1EdJxjX99EZJib1dGw/640?wx_fmt=png&from=appmsg "")  
  
直接点击，无法触发。但此时发现编辑器中有个预览功能，此功能主要用于对插入的内容进行预览。预览时成功xss弹窗。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RLTNmn7FBP6nLus9xqINY4ohxzzNGmuvj18JjoNuo3x4icNRAUZpX2k3uvAZjvgrTcO4uibsyicuex9tQbVo0ajIA/640?wx_fmt=png&from=appmsg "")  
  
  
