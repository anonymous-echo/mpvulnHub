#  腾讯偷偷接入了DeepSeek，也偷偷公布了大模型框架的漏洞和CVE   
原创 吉祥  吉祥讲安全   2025-02-17 09:33  
  
今天中午腾讯应急响应中心发布了AI相关的安全漏洞，并且提供了扫描工具。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/LkSZhKLnkUc8JAVqNqvOtpiaBxRut75yq4Ld3ZfKx1fj8EciaP8BNTic0ORbQo5pEovkia01hquqUcfPJWMGATianiaw/640?wx_fmt=png&from=appmsg "")  
并且还贴心的给大家说了如何去搜索这样的洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/LkSZhKLnkUc8JAVqNqvOtpiaBxRut75yq4ACLYOk8XmRA6lG7tCmvyAhDwwWMxb4M6yWUEf8DUMCib9HwQVVSQNA/640?wx_fmt=png&from=appmsg "")  
  
除此之外还把扫描工具给到了大家：  
```
开源地址：https://github.com/Tencent/AI-Infra-Guard/下载地址（根据系统下载自己系统的版本）：https://github.com/Tencent/AI-Infra-Guard/releases

```  
  
刚好正在更新我的星球中的面试题库，总觉得今年面试不简单，少不了有面试官会文大模型行管的问题。抓紧整理更新一波：  
  
网络安面试题库截止目前已更新51篇，近13w字，里面包含了网安的职业规划、面试准备篇幅、学习方向、求职名单、应届生面试题库、应届生笔试题库、国内外安全企业介绍、以及社会背调等。[15w字的面试经验](https://mp.weixin.qq.com/s?__biz=MzkwNjY1Mzc0Nw==&mid=2247486695&idx=1&sn=85fefa98f17e6f1f2dd745ef5a498a10&token=1860256701&lang=zh_CN&scene=21#wechat_redirect)  
  
文末有彩蛋  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/LkSZhKLnkUc8JAVqNqvOtpiaBxRut75yqUHEB7zpIKvibV3ia4ISRdfCfCdUrAkIkpg42SZOTNsyWqhsw2J573b4A/640?wx_fmt=png&from=appmsg "")  
  
以下是一些FOFA搜索引擎使用技巧及大模型框架资产测绘相关的内容，大家可以参考：  
  
**1. "假设我要找暴露在公网的TensorFlow Serving服务，怎么用FOFA构造精准搜索语法？"****答**  
：可组合使用body="TensorFlow Serving" && port="8501"  
语法。通过body字段匹配服务默认页特征，配合8501默认REST API端口过滤。进阶方案可添加&& country="US"  
限定地域，或&& after="2024-01-01"  
筛选近期活跃资产。  
  
**2. "如何用FOFA快速识别使用了Hugging Face Transformers框架的Web应用？"****答**  
：使用header="X-Powered-By: Transformers"  
或body="/static/js/transformers.*.js"  
。需结合目标应用特征，例如框架生成的JS文件命名规则，或自定义HTTP响应头标识。  
  
**3. "遇到搜索结果包含大量干扰项时，如何优化FOFA语法？"****答**  
：采用排除法，例如body="Stable Diffusion" && title!="Demo"  
过滤演示页面。结合&& os="Linux"  
限定操作系统，或&& !cert="Let's Encrypt"  
排除测试证书资产，提升结果置信度。  
  
**4. "怎么通过FOFA发现配置错误的LLAMA2 API端点？"****答**  
：构建path="/v1/completions" && body="model":"llama-2" && status_code="200"  
。需验证接口响应结构是否符合LLAMA2特征，并检查是否存在未授权访问（如缺少Authorization  
头）。  
  
**5. "如何用FOFA监控某组织新增的GPT类应用资产？"****答**  
：设定domain="xxx.com" && title="Chat" && after="2024-07-01"  
。结合组织域名特征及页面关键词，定期导出CSV进行增量对比，或使用FOFA API实现自动化监控告警。  
  
**6. "怎样通过证书信息定位使用PyTorch Model Server的企业内网暴露资产？"**答**  
：搜索cert.subject_org="CompanyName" && body="TorchServe"  
。需关联企业证书颁发机构(CA)及框架特征，结合port="8080,8081"  
限定预测/管理端口。  
  
**7. "FOFA查询结果中如何快速识别蜜罐型大模型服务？"****答**  
：特征包括非常规端口（如port="8000-9000"  
）、响应时间异常（&& response_time<100  
）、存在伪装登录页（body="admin/login"  
）。可叠加&& ip="xxx.xxx.xxx.0/24"  
检查IP段资产密集度。  
  
**8. "如何通过历史数据追踪某大模型框架的版本迭代趋势？"****答**  
：使用body="BERT" && before="2023-01-01"  
对比不同时间段的版本标识（如body="version:1.1.0"  
），结合FOFA的资产时间轴功能分析版本分布与升级周期。  
  
**9. "发现某IP存在LangChain应用，如何用FOFA挖掘关联资产？"****答**  
：执行ip="xxx.xxx.xxx.xxx" && body="langchain"  
定位主资产，再通过same_ip="xxx.xxx.xxx.xxx"  
检索同IP其他服务，或cert.sha1="xxx"  
查找相同证书签名的资产。  
  
**10. "如何构造语法批量导出全球暴露的AI训练平台Jupyter Notebook？"****答**  
：使用title="Jupyter Notebook" && port="8888" && protocol=="http"  
。需添加&& body!="password"  
排除密码保护实例，或&& country!="CN"  
按地域过滤敏感数据。  
  
**11. "FOFA搜索结果中如何识别使用FastAPI部署的大模型推理服务？"****答**  
：组合header="server: uvicorn" && body="/docs" && body="POST /predict"  
。验证OpenAPI文档路径及预测接口定义，排除默认配置风险（如调试模式）。  
  
**12. "如何通过备案信息关联某AI公司的未公开资产？"****答**  
：使用icp_number="xxx"  
获取备案主体所有域名，叠加body="AI Platform"  
或title="Model Hub"  
等关键词。结合domain_assets  
插件进行子域名爆破。  
## 星球介绍  
  
一个人走的很快，但一群人才能地的更远。吉祥同学学安全这个[星球🔗](https://mp.weixin.qq.com/s?__biz=MzkwNjY1Mzc0Nw==&mid=2247486065&idx=2&sn=b30ade8200e842743339d428f414475e&chksm=c0e4732df793fa3bf39a6eab17cc0ed0fca5f0e4c979ce64bd112762def9ee7cf0112a7e76af&scene=21#wechat_redirect)  
  
成立了1年左右，已经有300+的小伙伴了，如果你是网络安全的学生、想转行网络安全行业、需要网安相关的方案、ppt，戳[链接🔗（内有优惠卷）](https://mp.weixin.qq.com/s?__biz=MzkwNjY1Mzc0Nw==&mid=2247485310&idx=1&sn=616e51776b8c4c15e23eccd9a14762d3&chksm=c0e47e22f793f7340ff4cfb3820968296076f55f1a52938ae9fe04a52883a3be3a4e818d2e96&scene=21#wechat_redirect)  
  
快加入我们吧。系统性的知识库已经有：[《Java代码审计》](https://mp.weixin.qq.com/s?__biz=MzkwNjY1Mzc0Nw==&mid=2247484219&idx=1&sn=73564e316a4c9794019f15dd6b3ba9f6&chksm=c0e47a67f793f371e9f6a4fbc06e7929cb1480b7320fae34c32563307df3a28aca49d1a4addd&scene=21#wechat_redirect)  
  
++[《Web安全》](https://mp.weixin.qq.com/s?__biz=MzkwNjY1Mzc0Nw==&mid=2247484238&idx=1&sn=ca66551c31e37b8d726f151265fc9211&chksm=c0e47a12f793f3049fefde6e9ebe9ec4e2c7626b8594511bd314783719c216bd9929962a71e6&scene=21#wechat_redirect)  
  
++[《应急响应》](https://mp.weixin.qq.com/s?__biz=MzkwNjY1Mzc0Nw==&mid=2247484262&idx=1&sn=8500d284ffa923638199071032877536&chksm=c0e47a3af793f32c1c20dcb55c28942b59cbae12ce7169c63d6229d66238fb39a8094a2c13a1&scene=21#wechat_redirect)  
  
++[《护网资料库》](https://mp.weixin.qq.com/s?__biz=MzkwNjY1Mzc0Nw==&mid=2247484307&idx=1&sn=9e8e24e703e877301d43fcef94e36d0e&chksm=c0e47acff793f3d9a868af859fae561999930ebbe01fcea8a1a5eb99fe84d54655c4e661be53&scene=21#wechat_redirect)  
  
++[《网安面试指南》](https://mp.weixin.qq.com/s?__biz=MzkwNjY1Mzc0Nw==&mid=2247486695&idx=1&sn=85fefa98f17e6f1f2dd745ef5a498a10&token=1860256701&lang=zh_CN&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/LkSZhKLnkUc8JAVqNqvOtpiaBxRut75yqBSrqickIv5MKiafDLJK0WnJlQRzyAKLNkicWTTRvPHVoPV30YdPkwiaEEQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
