#  CNNVD | 关于Ollama安全漏洞的通报   
 中国信息安全   2025-03-03 18:17  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5ygBWlbicVGPEeCrNiamSb4yicJQRibdwpxoIGiblDZu7chmicVYhH6w6kTGicQgbdrCVqMygUbRZm0qWnXQ/640?wx_fmt=gif&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/1brjUjbpg5ygBWlbicVGPEeCrNiamSb4yicR7Eowa6sjBicu9tKDDnEwBuFNg5jO3fH7gHib1n8k01iaP04YN55ib8uOA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5ygBWlbicVGPEeCrNiamSb4yicJQRibdwpxoIGiblDZu7chmicVYhH6w6kTGicQgbdrCVqMygUbRZm0qWnXQ/640?wx_fmt=gif&from=appmsg "")  
  
**扫码订阅《中国信息安全》**  
  
  
邮发代号 2-786  
  
征订热线：010-82341063  
  
  
  
**漏洞情况**************  
  
近日，国家信息安全漏洞库（CNNVD）收到关于Ollama安全漏洞（CNNVD-202503-081）情况的报送。未经授权的攻击者可在远程条件下调用Ollama服务接口，执行包括但不限于敏感模型资产窃取、虚假信息投喂、模型计算资源滥用和拒绝服务、系统配置篡改和扩大利用等恶意操作。Ollama所有版本均受此漏洞影响。目前，Ollama暂未发布修复措施，但可以参考临时修复办法缓解漏洞带来的危害。  
  
## 一漏洞介绍  
  
  
Ollama是一个本地私有化部署大语言模型（LLM，如DeepSeek等）的运行环境和平台，简化了大语言模型在本地的部署、运行和管理过程，具有简化部署、轻量级可扩展、API支持、跨平台等特点，在AI领域得到了较为广泛的应用。Ollama存在安全漏洞，该漏洞源于默认未设置身份验证和访问控制功能，未经授权的攻击者可在远程条件下调用Ollama服务接口，执行包括但不限于敏感模型资产窃取、虚假信息投喂、模型计算资源滥用和拒绝服务、系统配置篡改和扩大利用等恶意操作。  
  
****  
## 二危害影响  
  
  
Ollama所有版本均受此漏洞影响。  
  
****  
## 三修复建议  
  
  
目前，Ollama官方暂未发布修复措施，但可以参考临时修复办法缓解漏洞带来的危害。官方临时修复办法链接：  
  
https://github.com/ollama/ollama/blob/main/docs/faq.md  
  
  
本通报由CNNVD技术支撑单位——华为技术有限公司、深信服科技股份有限公司、内蒙古启正信息科技有限公司、云南南天电子信息产业股份有限公司提供支持。  
  
  
CNNVD将继续跟踪上述漏洞的相关情况，及时发布相关信息。如有需要，可与CNNVD联系。  
  
  
联系方式：cnnvd@itsec.gov.cn  
  
  
（来源：CNNVD）  
  
  
  
**分享网络安全知识 强化网络安全意识**  
  
**欢迎关注《中国信息安全》杂志官方抖音号**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1brjUjbpg5ygBWlbicVGPEeCrNiamSb4yic7NUicyPu0ibex9mVSxoiaiby6BW5IJ0vQ0OxqIBvnWDDXWkII55rBKlLGQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**《中国信息安全》杂志倾力推荐**  
  
**“企业成长计划”**  
  
  
**点击下图 了解详情**  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MzA5MzE5MDAzOA==&mid=2664162643&idx=1&sn=fcc4f3a6047a0c2f4e4cc0181243ee18&scene=21#wechat_redirect)  
  
  
  
  
