#  CNCERT：关于Ollama存在未授权访问漏洞的安全公告   
 安全内参   2025-03-04 16:04  
  
安全公告编号  
:CNTA-2025-0003  
  
近日，国家信息安全漏洞共享平台（CNVD）收录了Ollama未授权访问漏洞（CNVD-2025-04094）。未经授权的攻击者可以远程访问Ollama服务接口执行敏感资产获取、虚假信息投喂、拒绝服务等恶意操作。CNVD建议受影响的单位和用户立即采取措施防范漏洞攻击风险。  
  
**一、漏洞情况分析**  
  
Ollama是一个本地私有化部署大语言模型（LLM，如DeepSeek等）的运行环境和平台，简化了大语言模型在本地的部署、运行和管理过程，具有简化部署、轻量级可扩展、API支持、跨平台等特点，在AI领域得到了较为广泛的应用。  
  
Ollama存在未授权访问漏洞。由于Ollama默认未设置身份验证和访问控制功能，未经授权的攻击者可在远程条件下调用Ollama服务接口，执行包括但不限于敏感模型资产窃取、虚假信息投喂、模型计算资源滥用和拒绝服务、系统配置篡改和扩大利用等恶意操作。未设置身份验证和访问控制功能且暴露在公共互联网上的Ollama易受此漏洞攻击影响。  
  
CNVD对该漏洞的综合评级为“高危”。  
  
**二、漏洞影响范围**  
  
漏洞影响的产品和版本：  
  
Ollama所有版本（未设置访问认证的情况下）  
  
**三、漏洞处置建议**  
  
请使用Ollama部署大模型的单位和用户立即采取以下措施进行漏洞修复：  
  
1、若Ollama只提供本地服务，设置环境变量Environment="OLLAMA_HOST=127.0.0.1"，仅允许本地访问。  
  
2、若Ollama需提供公网服务，选择以下方法添加认证机制：  
  
1）修改config.yaml、settings.json 配置文件，限定可访问Ollama 服务的IP地址；  
  
2）通过防火墙等设备配置IP白名单，阻止非授权IP的访问请求；  
  
3）通过反向代理进行身份验证和授权（如使用OAuth2.0协议），防止未经授权用户访问。  
  
  
**推荐阅读**  
- [网安智库平台长期招聘兼职研究员](http://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247499450&idx=2&sn=2da3ca2e0b4d4f9f56ea7f7579afc378&chksm=ebfab99adc8d308c3ba6e7a74bd41beadf39f1b0e38a39f7235db4c305c06caa49ff63a0cc1d&scene=21#wechat_redirect)  
  
  
- [欢迎加入“安全内参热点讨论群”](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247501251&idx=1&sn=8b6ebecbe80c1c72317948494f87b489&chksm=ebfa82e3dc8d0bf595d039e75b446e14ab96bf63cf8ffc5d553b58248dde3424fb18e6947440&token=525430415&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
  
  
  
文章来源：CNVD漏洞平台  
  
  
点击下方卡片关注我们，  
  
带你一起读懂网络安全 ↓  
  
  
  
