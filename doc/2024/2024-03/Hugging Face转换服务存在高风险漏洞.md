#  Hugging Face转换服务存在高风险漏洞   
 安全客   2024-02-29 20:19  
  
安全公司 HiddenLayer 发现 Hugging Face 的 Safetensors 转换服务中存在一个漏洞，攻击者可以利用该漏洞拦截用户上传的 AI 模型并危及供应链。  
  
根据 HiddenLayer报告 ，攻击者可以从 Hugging Face 服务向平台上的任何存储库发送恶意合并请求，并拦截通过转换服务传输的任何模型。这项技术开辟了修改平台上任何存储库的方法，伪装成转换机器人。  
  
Hugging Face 是一个流行的协作平台，可帮助用户存储、部署和训练预先训练的机器学习模型和数据集。Safetensors 是该公司开发的一种用于安全存储张量的格式。  
  
HiddenLayer 的分析表明，网络犯罪分子可以使用恶意 PyTorch 二进制文件来劫持转换服务并危害托管该服务的系统。此外，旨在创建合并请求的官方机器人SFConvertbot的令牌 可以被窃取，以向网站上的任何存储库发送恶意请求，从而允许攻击者篡改模型并将后门嵌入其中。  
  
研究人员指出，当用户尝试转换其模型时，攻击者可以执行任何任意代码，同时对用户不可见。如果受害者尝试转换自己的私人存储库，这可能会导致 Hugging Face 令牌被盗、访问内部模型和数据集以及可能中毒。  
  
使问题更加复杂的是，任何用户都可以向公共存储库提交转换请求，从而导致常用模型被拦截或修改的可能性，从而给供应链带来重大风险。  
  
  
**来**  
  
**领**  
  
**资**  
  
**料**  
  
**【免费领】**  
**网络安全专业入门与进阶学习资料，轻松掌握网络安全技能！**  
  
****![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb59ibIezbic1Dob2DsGBgT7WkA3sJgtXriaUGWIocjCgU8JQth19dEFvC8lSOwlp1ALOVnZltOicA1RkA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
