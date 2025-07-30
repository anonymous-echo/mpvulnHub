#  Ollama未授权访问漏洞【实现AI自由】   
 sec0nd安全   2025-03-03 21:41  
  
**0.1 漏洞成因**  
Ollama 默认部署时监听于 127.0.0.1，仅允许本地访问，从而在初始配置下保证了较高的安全性。然而部分用户为了方便从公网访问，会将监听地址修改为 0.0.0.0。在这种修改之后，如果未额外配置身份认证或访问控制机制，Ollama 的管理接口就会暴露于公网，导致攻击者只需访问服务端口（默认 11434）即可调用敏感功能接口，进而读取、下载或删除私有模型文件，或滥用模型推理资源等。此外，老版本 Ollama 的部分实现在处理用户提供的数据时缺乏严格校验，进一步加剧了漏洞影响。例如 Ollama 0.1.34 版本之前的 /api/pull 接口存在路径遍历漏洞（CVE-2024-37032），攻击者可利用特制请求覆盖服务器文件并进而执行任意代码。在缺乏认证的前提下，这类漏洞更加容易被远程利用。  
**0.2 漏洞利用**  
  
结合FOFA获取互联网上的未授权访问的Ollama机器，通过工具实现AI自由。  
  
项目地址：https://github.com/b3nguang/Ollama-Scan  
  
## 0.2.1 fofa_Ollama.py  
  
使用fofa_Ollama.py批量获取未授权地址，并打印出模型。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TMwBibc8FlgZ5UBcGlmNiaT1nubtUhg9VvPOuibKcOU7sQMeNTOqriciaHcDgTZqd9gxIkx6Psb954PWjLPibxp03icvw/640?wx_fmt=png&from=appmsg "")  
  
运行完成之后会在当前目录下生成一个txt文件【当前年月日小时分.txt】。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TMwBibc8FlgZ5UBcGlmNiaT1nubtUhg9VvEPDFSuIRNiauUI0iaxAria2vq2wMURkI68Mw8MORBhiaFlePuYCcb4F47A/640?wx_fmt=png&from=appmsg "")  
  
其中包含了可调用的模型以及时间。  
  
## 0.2.2 命令行调用模型  
运行main.py脚本，输入未授权服务器地址。  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TMwBibc8FlgZ5UBcGlmNiaT1nubtUhg9VvdLfOU45gjpx9ibnSyibXMQDSIyJwZRiaqqfKpubUXglKhwMjhNT20eklQ/640?wx_fmt=png&from=appmsg "")  
  
获取可用模型。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TMwBibc8FlgZ5UBcGlmNiaT1nubtUhg9VveE6v670ibmZtYjdFuxqYQBpUUQ7Na17Mkm8zGI38xriczN6pGeQz4wfA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TMwBibc8FlgZ5UBcGlmNiaT1nubtUhg9Vvibov7WaSRXL51aoZaCxqJZVYOliaIGYpadyHH7jjUjPGfAiaCU2yjzbsQ/640?wx_fmt=png&from=appmsg "")  
  
## 0.2.2 可视化调用模型  
  
  
程序地址：https://cherry-ai.com/  
  
填入刚刚FOFA输出的未授权访问地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TMwBibc8FlgZ5UBcGlmNiaT1nubtUhg9Vvu4MvRCdfAfic0H0fW8uOLvPv9fSqD1EPzHmQAtv9vtXxklZ7tnMsClw/640?wx_fmt=png&from=appmsg "")  
  
选择对应模型，然后检查对应模型是否正常。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TMwBibc8FlgZ5UBcGlmNiaT1nubtUhg9VvBzpcQLfIQ3ic0T5XNZ8JDxRujaroNkqibAyXPXOv61s7stQrrZC7xibUA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TMwBibc8FlgZ5UBcGlmNiaT1nubtUhg9Vviccc3dEX0XpX5qlhaB6icgnye6asia2Q00Tx7RSKd7MZVTW7G84KFT2iag/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TMwBibc8FlgZ5UBcGlmNiaT1nubtUhg9VvcD7IJl6ibfc8ibndiaA1bQ8jqmz1QxbYBxd7ib1uKpWmib3IMCqicJgXX9ZA/640?wx_fmt=png&from=appmsg "")  
  
切换对应模型，并使用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TMwBibc8FlgZ5UBcGlmNiaT1nubtUhg9VvT8WicWw0Snkj5cwzXmpT7pmqAriaLQcXW0Eo4LKIkoMoVThwyLsK9RDQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/TMwBibc8FlgZ5UBcGlmNiaT1nubtUhg9VvQvOW8HhlXc7NRqIhXB3gdJSRiaEt20A8qAWQchxK6xlYr8SxM4luqfQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
