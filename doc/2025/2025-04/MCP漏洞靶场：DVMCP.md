#  MCP漏洞靶场：DVMCP   
原创 玄月调查小组  玄月调查小组   2025-04-20 11:02  
  
之前介绍了MCP的工具投毒攻击(  
Tool Poisoning Attacks，TPA)，[模型上下文协议（MCP）中的工具投毒攻击](https://mp.weixin.qq.com/s?__biz=MzkzMTY0MDgzNg==&mid=2247484300&idx=1&sn=2dd27dd2da797998472c21114a1a4a6f&scene=21#wechat_redirect)  
。  
  
除此之外MCP还有其他安全隐患。例如Rakesh Gohel总结了常见的MCP漏洞：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/aYef9qMYLnKaicicqYqCehzFGYsQcg9Q3y7zqgdBhI7V8omzPSmvzGnBGhAtficXdxBvicBAicnZTsosialcS5Im8p0g/640?wx_fmt=gif&from=appmsg "")  
  
本次要介绍的是MCP的漏洞靶场：  
DVMCP[1]  
## 项目简介  
  
DVMCP项目包括了以下漏洞场景：  
- 提示注入：通过恶意输入操纵 LLM 行为  
  
- 工具中毒：在工具描述中隐藏恶意指令  
  
- 权限过度：利用过度宽松的工具访问  
  
- Rug Pull 攻击：利用工具定义突变  
  
- 工具隐藏：用恶意工具覆盖合法工具  
  
- 间接提示注入：通过数据源注入指令  
  
- 令牌盗窃：利用不安全的令牌存储  
  
- 恶意代码执行：通过易受攻击的工具执行任意代码  
  
- 远程访问控制：获取未经授权的系统访问权限  
  
- 多向量攻击：结合多种漏洞  
  
项目地址：https://github.com/harishsg993010/damn-vulnerable-MCP-server  
  
DVMCP项目目前支持  
Cline[2]  
作为MCP客户端。issue里也有不支持Claude Desktop的反馈。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aYef9qMYLnKaicicqYqCehzFGYsQcg9Q3ySanG2V48iaicGX7x6V9ZQX65IbZpdNNAL77qNZNAkmHSPobJIxHricJvQ/640?wx_fmt=png&from=appmsg "")  
  
此外比较有趣的是，作者直言项目使用了cursor和 Manus。  
  
👉 关注「玄月调查小组」，解剖硬核技术！  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aYef9qMYLnJgNxsHxmSeNIn3YDnErkLfWBPz7CFxD2Zs8s58xJ6XkjE6Zln5GU9qSgic9YDwF8L7nb0cZfb07UA/640?wx_fmt=png&from=appmsg "")  
  
### 参考资料  
  
[1]   
Damn Vulnerable Model Context Protocol (DVMCP): https://github.com/harishsg993010/damn-vulnerable-MCP-server  
  
[2]   
Cline: https://docs.cline.bot/  
  
