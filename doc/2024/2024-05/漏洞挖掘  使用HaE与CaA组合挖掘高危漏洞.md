#  漏洞挖掘 | 使用HaE与CaA组合挖掘高危漏洞   
校长  不懂安全的校董   2024-05-07 19:32  
  
## 0x01 前言  
  
我发现我好久没发过赏金漏洞的挖掘了，今天特此来更新一篇HaE搭配CaA挖掘到高危漏洞的实战案例  
  
这里不得不说一下HaE搭配CaA  
```
HaE: https://github.com/gh0stkey/HaE
CaA: https://github.com/gh0stkey/CaA

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icefLCXrhxfh3iaSQMe8N9FeOMxqicibnhamLlT3lRBV0licAibuicvPvxZ3UNV0rqbUnOjdhWXrYSt0B6MoEXF1aTdVw/640?wx_fmt=png&from=appmsg "")  
## 0x02 正文  
  
在对某管理后台的漏洞挖掘过程中，我在 HaE 的 Linkfinder 规则提取结果中发现了一个请求路径。根据其字面意思就是根据 **TenantId** 获取所有用户: /public/getAllUserByTenantId  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icefLCXrhxfh3iaSQMe8N9FeOMxqicibnhamgyC5q6yYgeUD52glh1pWmsiadDaGBSEHrutfvsP1FVI5ewHyd5yhbEg/640?wx_fmt=jpeg&from=appmsg "")  
  
直接请求该路径很显然不行，会返回400错误，因为没有参数，因此直接猜测参数就是 TenantId，但参数值应该是特定值，输入 **1、2、3** 之类的返回没有任何数据。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icefLCXrhxfh3iaSQMe8N9FeOMxqicibnhamyC85JjHBUFPo7gwEMUiaNeAwTRLZtwr72XzWzZBv58dEF9bFng5WicyA/640?wx_fmt=jpeg&from=appmsg "")  
  
那没有参数值的情况下怎么办？我们可以通过 CaA 的收集页面 **Collectlnfo**，找到 All - Value，里面会收集参数和参数值，选中想要的数据右键 Send to Fuzzer，发送到Fuzzer模块中。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icefLCXrhxfh3iaSQMe8N9FeOMxqicibnhamQibubicene3BhXQ5OticJiafjcTHB38K2QgHclEiaY7JpEhRSF7tX6Sx3SQ/640?wx_fmt=jpeg&from=appmsg "")  
  
然后在Fuzzer配置中选中参数值，并右键选中 Rename 将参数值重命名为 tenantId，这样就可以将所有参数值带入到 tenantId 参数中进行Fuzzing工作。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icefLCXrhxfh3iaSQMe8N9FeOMxqicibnhamTSV6tr7YiciaicZVXzGw3zTQicWHGWFn29m4eccAibyHqBgibia1tx1oxiaznA/640?wx_fmt=jpeg&from=appmsg "")  
  
最终我们可以转移到 **CaA - Taskboard** 进行Fuzzing工作结果的查询，并根据 Length、Similarity 等字段进行筛选，找到了差异化的请求，如图所示我们点进相关请求，基于 **HaE - MarkInfo** 可以看见有许多手机号。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icefLCXrhxfh3iaSQMe8N9FeOMxqicibnham4Z8Ehic1BFy7oDSWIf6ffQ79uwicYh96icIoBSw8cNCt40xtx8DjhTBibA/640?wx_fmt=jpeg&from=appmsg "")  
  
那么在这里我们就成功的找到了 tenantId 的对应参数值，完成了一个高危未授权获取敏感信息漏洞的挖掘，成功获得赏金。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icefLCXrhxfh3iaSQMe8N9FeOMxqicibnhamORYsU9Plw5RVf8T6Bo73ZJc7pT1lVnxVQNRTGp7grxUypntwHkgZ9g/640?wx_fmt=jpeg&from=appmsg "")  
## 0x03 结尾  
  
承接红蓝对抗、安全众测、安全培训、CTF代打、CTF培训、PHP / JAVA / GO / Python 代码审计、渗透测试、应急响应、免杀/远控开发、二进制漏洞挖掘、Web3安全服务、智能合约代码审计 等等的安全项目，请联系下方微信。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icefLCXrhxfgp6OTRAV6boicrQdeFONewFSSYzuC8LYsM9hOrv3K6qVeUCUgoEZmfReVGJIjL6o9BE6MZAGEO87g/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
