#  LangChain曝关键漏洞，数百万AI应用面临攻击风险   
疯狂冰淇淋  FreeBuf   2024-07-27 09:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR387cLQibZp3odAXgtYrY1vVCr4tJlnJSJk3Lkf0ZXbnCN5JmYkNAH6j8PEQdbPRUEqGscrnSfiaplgw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR387cLQibZp3odAXgtYrY1vVC3Oiatycl0Iic5RY0dcWgWibPiaCH8l4Nm7VexTSQtwSc8WJt9vP12tGrjw/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9JRBCdyJgMBiaBopViazJ5xX2zialNSuzEHlS6uKX07UQkzd340dRPG6BnIPKctVRLAkCp3xaNu1S2l6/640?wx_fmt=svg&from=appmsg "")  
  
左右滑动查看更多  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/0pygn8iaZdEfON2XFbCe9JRBCdyJgMBiaBopViazJ5xX2zialNSuzEHlS6uKX07UQkzd340dRPG6BnIPKctVRLAkCp3xaNu1S2l6/640?wx_fmt=svg&from=appmsg "")  
  
  
  
LangChain是一个流行的开源生成式人工智能框架，其官网介绍，有超过一百万名开发者使用LangChain框架来开发大型语言模型（LLM）应用程序。LangChain的合作伙伴包括云计算、人工智能、数据库和其他技术开发领域的许多知名企业。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR387cLQibZp3odAXgtYrY1vVCffFySLVqMSGSibhwmgDgd7X0iaZU0MZSNjCeNicmuwe6vV0aTnKOt7v7g/640?wx_fmt=png&from=appmsg "")  
  
  
近日，来自Palo Alto Networks的研究人员详细描述了LangChain中的两个重大安全漏洞。  
  
  
这些漏洞被识别为CVE-2023-46229和CVE-2023-44467，它们有可能允许攻击者执行任意代码和访问敏感数据。鉴于有一百多万名开发者依赖LangChain，这一发现给众多AI驱动的应用程序带来了重大安全风险。  
  
  
**CVE-2023-46229：服务器端请求伪造（SSRF）**  
  
  
  
在LangChain 0.0.317之前的版本中，存在一个通过精心设计的站点地图实现的SSRF漏洞。利用该漏洞，攻击者可以从内网获取敏感信息，并可能绕过访问控制。Palo Alto Networks在2023年10月13日发现了这一问题，并立即通知了LangChain团队。该漏洞已在版本0.0.317中通过拉取请求langchain#11925得到修复。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR387cLQibZp3odAXgtYrY1vVCt3bpKhL0nN0YMCx3cRofg1XG14YH8fQabTznXIdsNl9xF5BWekcHNg/640?wx_fmt=png&from=appmsg "")  
  
  
**CVE-2023-44467：LangChain实验版中的严重提示注入漏洞**  
  
  
##   
  
CVE-2023-44467是一个严重提示注入漏洞，影响0.0.306之前的LangChain实验版本。LangChain实验版是一个专为研究和试验而设计的Python库，包含可能被恶意提示利用的集成。这个漏洞影响了PALChain功能，这是一个通过程序辅助语言模型（PAL）增强语言模型生成代码解决方案的能力的功能。  
  
  
该漏洞允许攻击者利用PALChain的处理能力进行提示注入，使他们能够执行有害的命令或代码。这种利用可能导致未经授权的访问或操纵，带来重大的安全风险。Palo Alto Networks在2023年9月1日识别出这一问题，并及时通知了LangChain开发团队，后者在第二天在LangChain实验PyPI页面上发布了警告。  
  
  
随着对大型语言模型（LLM）应用需求的增加，LangChain的受欢迎程度在最近几个月急剧上升。其丰富的预构建组件和集成库使其成为开发者的首选工具。然而，这种广泛的应用也意味着这些漏洞的潜在影响被放大。  
  
  
Palo Alto Networks的研究人员强烈建议使用LangChain的开发者和组织将LangChain更新到最新的修补版本，以确保应用安全。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://securityonline.info/critical-flaws-in-langchain-expose-millions-of-ai-apps-to-attack/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494632&idx=1&sn=39d15121b9d4a665a970768a9b377194&chksm=ce1f1177f9689861d973b98e71492ef76d1894ad7e593b40c27fbdbee4417d4d1a1c24b36621&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247494601&idx=1&sn=d02355354ca064cfe25a770b4a650dc8&chksm=ce1f1156f9689840013d9eee16215311ff387b3a0f68cec30ee999a7a00875056790b11052d9&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
