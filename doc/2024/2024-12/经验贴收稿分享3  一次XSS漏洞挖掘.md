#  经验贴收稿分享3 | 一次XSS漏洞挖掘   
原创 崔西  励行安全   2024-12-01 11:22  
  
官网：  
https://hall.***.edu.cn/********/guidePage?id=004B1DE1-267B-47E7-848B-3F5CBC9F4038  
  
账号：21********  
  
密码：20****  
  
点击办理  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UN9bb0CZZJOsSxr5TNibsiaxGx7hgictnBK4eW2DGh3fwFzIia9rkVxmbhMls9V8iazjjeYDgsosLe9V5d4e9f0jibSA/640?wx_fmt=png&from=appmsg "")  
  
2.上传图像文件，并抓包  
  
思路：这里有一个上传功能，按经验丢到重发器，看看会不会爆上传路径  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UN9bb0CZZJOsSxr5TNibsiaxGx7hgictnBK1qjY6xOibUQGzaIBYb7K5Hv3XrWf0nyZ5jw8P580mRZKnFVxMreKAPA/640?wx_fmt=png&from=appmsg "")  
  
3.放到重发器里，发现爆路径了，这个时候想扩大一点危害，想试试xss脚本，已知xss脚本需要在html的支持下解析，那我们就将文件名后缀改为.html，在文件包里嵌入xss代码，点击重发，可见返回包里爆出路径  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UN9bb0CZZJOsSxr5TNibsiaxGx7hgictnBKBOS7bO8czic5Eq98NM4qSCOUhOX0RRsWqJU2GyQBQ9ticdrsaGobypfw/640?wx_fmt=png&from=appmsg "")  
  
4.访问该路径，弹出xss  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UN9bb0CZZJOsSxr5TNibsiaxGx7hgictnBKdzichTf6rxbjY9SctFEN4kFYarnJwZgxTWHF9H0zIC2AZAOBepicyZtg/640?wx_fmt=png&from=appmsg "")  
  
  
