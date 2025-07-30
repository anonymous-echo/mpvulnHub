#  OLLAMA 未授权访问（CNVD-2025-04094）   
Superhero  Nday Poc   2025-03-29 20:29  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkYN4sZibCVo6EFo0N9b7Kib4I4N6j6Y10tynLOdgov9ibUmaNwW5yeoCbQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCkhic5lbbPcpxTLtLccZ04WhwDotW7g2b3zBgZeS5uvFH4dxf0tj0Rutw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/Melo944GVOJECe5vg2C5YWgpyo1D5bCk524CiapZejYicic1Hf8LPt8qR893A3IP38J3NMmskDZjyqNkShewpibEfA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
内容仅用于学习交流自查使用，由于传播、利用本公众号所提供的  
POC  
信息及  
POC对应脚本  
而造成的任何直接或者间接的后果及损失，均由使用者本人负责，公众号Nday Poc及作者不为此承担任何责任，一旦造成后果请自行承担！  
  
  
**00******  
  
**产品简介**  
  
  
Ollama是一个本地私有化部署大  
语言模型  
（LLM，如DeepSeek等）的运行环境和平台，简化了大语言模型在本地的部署、运行和管理过程，具有简化部署、轻量级可扩展、API支持、跨平台等特点，在AI领域得到了较为广泛的应用。  
**01******  
  
**漏洞概述**  
  
  
Ollama存在未授权访问漏洞。由于Ollama默认未设置身份验证和访问控制功能，未经授权的攻击者可在远程条件下调用Ollama服务接口，执行包括但不限于敏感模型资产窃取、虚假信息投喂、模型计算资源滥用和拒绝服务、系统配置篡改和扩大利用等恶意操作。未设置身份验证和访问控制功能且暴露在公共互联网上的Ollama易受此漏洞攻击影响。  
**02******  
  
**搜索引擎**  
  
  
FOFA:  
```
app="Ollama"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKT5ibjAbk4rx8WO05svEXXml2gFmaCxF1dSicsYNUVXfQG4zBibWfQhWqOibpicDiaUoibYqZY2GZsLxlzQ/640?wx_fmt=png&from=appmsg "")  
  
  
**03******  
  
**漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKT5ibjAbk4rx8WO05svEXXmYoeaRxBBfAL6n6r8apAx7WI7xRsrX74YEy1GhTncvSZWUEa5yZ8pRw/640?wx_fmt=png&from=appmsg "")  
  
在此利用Chatbox配置API功能即可使用他人的模型资源  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKT5ibjAbk4rx8WO05svEXXmSTicIiaHXZCMcGIXZUSgeUKoVb7slBXhzUbxWYNKKRMpStf12XdnduzA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKT5ibjAbk4rx8WO05svEXXmCBaSNb7FK8bEfFBrWVocO7qnhJXZyEib6zLNJgFnuMUurBDnJ7PXdrg/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**自查工具**  
  
  
nuclei  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKT5ibjAbk4rx8WO05svEXXmZ0OxqiaOTia1gwEx1LkeDbHZuwACPcZ65vnicyJ2Mmdh7dWxT8xaFzS2A/640?wx_fmt=png&from=appmsg "")  
  
afrog  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKT5ibjAbk4rx8WO05svEXXmrH7UImhtvXedR5dybRjrqaX2fw47nMsEC1WYRuUk6CA9rh4QbCrU7g/640?wx_fmt=png&from=appmsg "")  
  
xray  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwKT5ibjAbk4rx8WO05svEXXmDhVDic04zw7QKr2icD0Aiavu0ibCPX0O4NDJaQMpLLvjv1X0lMkWwTuWFw/640?wx_fmt=png&from=appmsg "")  
  
  
**05******  
  
**修复建议**  
  
  
1、关闭互联网暴露面或接口设置访问权限  
  
2、  
请使用Ollama部署大模型的单位和用户立即采取以下措施进行漏洞修复：  
  
1.若Ollama只对本地提供服务，建议设置环境变量Environment="OLLAMA_HOST=127.0.0.1"，仅允许本地访问。  
  
2.  若Ollama对外提供服务，建议选择以下方法添加认证机制：  
  
（1）修改config.yaml、settings.json配置文件限定可调用Ollama服务的IP地址；  
  
（2）在防火墙等设备部署IP白名单，严格限定访问IP地址；  
  
（3）通过反向代理实现身份验证和授权（如使用OAuth2.0协议），防止未经授权用户访问。  
  
  
**06******  
  
**内部圈子介绍**  
  
  
【Nday漏洞实战圈】🛠️   
  
专注公开1day/Nday漏洞复现  
 · 工具链适配支持  
  
 ✧━━━━━━━━━━━━━━━━✧   
  
🔍 资源内容  
  
 ▫️ 整合全网公开Nday漏洞POC详情  
  
 ▫️ 适配Xray/Afrog/Nuclei检测脚本  
  
 ▫️ 支持内置与自定义POC目录混合扫描   
  
🔄 更新计划   
  
▫️ 每周新增7-10个实用POC（来源公开平台）   
  
▫️ 所有脚本经过基础测试，降低调试成本   
  
🎯 适用场景   
  
▫️ 企业漏洞自查 ▫️ 渗透测试 ▫️ 红蓝对抗   
▫️ 安全运维  
  
✧━━━━━━━━━━━━━━━━✧   
  
⚠️ 声明：仅限合法授权测试，严禁违规使用！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/wnJTy44dqwI0beBCCyKGykkAazuPyvibgC0ooBGy9elQQ72f1WIB73UDYuPhx8cnCobvnOBdTcxmdwBbt2eAYIQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
