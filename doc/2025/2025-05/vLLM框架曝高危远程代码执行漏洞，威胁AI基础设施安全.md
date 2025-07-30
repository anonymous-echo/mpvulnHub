#  vLLM框架曝高危远程代码执行漏洞，威胁AI基础设施安全   
 FreeBuf   2025-05-05 10:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibdLyAkLZJeUjiapk1hM3biaibI8gTCdFF9CVzUW2FiabbDXA2YNaNmgbrIXgM7ibsKibWEH76q1tEkFA1A/640?wx_fmt=png&from=appmsg "")  
  
  
  
高性能大语言模型（LLM）推理服务框架vLLM近日曝出高危安全漏洞（编号CVE-2025-32444），该漏洞CVSS评分达到满分10分，可能通过Mooncake集成组件引发远程代码执行（RCE）风险。作为GitHub上获得46,000星标的热门开源项目，vLLM凭借其卓越的速度和灵活性，被广泛应用于学术研究与企业级AI系统。随着大语言模型在各行业的快速普及，模型服务栈的安全性显得尤为重要。  
  
  
**01**  
  
  
  
**技术细节**  
  
  
该漏洞源于vLLM框架中Mooncake集成组件对网络序列化数据的处理机制。具体而言，组件通过不安全的ZeroMQ套接字传输数据时，错误地使用了Python的pickle模块进行反序列化操作。漏洞核心位于vllm/vllm/distributed/kv_transfer/kv_pipe/mooncake_pipe.py  
文件中的recv_pyobj()  
函数，该函数隐式调用pickle.loads()  
处理通过ZeroMQ套接字接收的数据。  
  
  
**02**  
  
  
  
**影响范围**  
  
  
  
此漏洞影响所有使用Mooncake集成组件且版本号≥0.6.5的vLLM实例。需要特别说明的是，若vLLM部署未启用Mooncake组件进行分布式键值传输，则不受此特定漏洞影响。  
  
  
**03**  
  
  
  
**修复方案**  
  
  
vLLM开发团队已紧急发布v0.8.5版本修复该漏洞。安全专家强烈建议所有受影响用户立即升级至该版本，以消除远程代码执行风险。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1y91mvSZuxibf3Q3g2rJ32FNzoYfx4yaBmWbfwcRaNicuMo3AxIck2bCw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651319699&idx=1&sn=127e9ca1a8d55931beae293a68e3b706&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651319591&idx=1&sn=5da9d56b39b3a2fad4071555e9de6b43&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651319257&idx=1&sn=a603c646a53e3a242a2e79faf4f06239&scene=21#wechat_redirect)  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1uEIoRxNoqa17tBBrodHPbOERbZXdjFvNZC5uz0HtCfKbKx3o3XarGQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS5KDnCKUfVLVQGsc9BiaQTUsrwzfcianumzeLVcmibOmm2FzUqef2V6WPQQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38mFMbqsUOVbBDicib7jSu7FfibBxO3LTiafGpMPic7a01jnxbnwOtajXvq5j2piaII2Knau7Av5Kxvp2wA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
