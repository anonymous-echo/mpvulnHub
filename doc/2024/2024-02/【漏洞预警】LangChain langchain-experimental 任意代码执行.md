#  【漏洞预警】LangChain langchain-experimental 任意代码执行   
cexlife  飓风网络安全   2024-02-28 22:50  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu00E5bq7xsQibDHbWhOr2Hh1t99pEn7gnQTXb09uO9oF1cJ06SAOleHicDs7o3wr1YkTFns4KLc8ibYicw/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**LangChain Experimental 在 pal_chain/base.py 中未禁止对特定Python属性的访问，这些属性包括__import__、__subclasses__、__builtins__、__globals__、__getattribute__、__bases__、__mro__、__base__,攻击者可以通过这些属性绕过CVE-2023-44467的修复措施执行任意代码。**影响范围:**暂无**修复方案:**暂无**参考链接:**https://github.com/langchain-ai/langchain/commit/de9a6cdf163ed00adaf2e559203ed0a9ca2f1de7https://github.com/advisories/GHSA-v8vj-cv27-hjv8  
  
