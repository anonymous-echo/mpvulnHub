#  这是一篇避雷贴！OpenStack这个安全漏洞你修复了吗？   
 深信服千里目安全技术中心   2024-04-18 19:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zEibc95Xllq8rFQ5GbCRSvbJH1ibakgkq8miaHx6lC5vrxDr7gPIVyuIeFLGea8U1mF6MTZljYVySicw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
对于开发者们来说，**OpenStack**  
并不陌生。  
  
作为**全球主流开源的云计算管理平台**  
，它由NASA和Rackspace合作研发并发起，由全球开发者共同维护，是众多组织和企业构建云计算环境的首选，用户基数巨大，适用场景广泛。  
  
近日，OpenStack官方发布了一则漏洞公告，表示Murano服务组件存在安全隐患，提醒用户**尽快关闭或者删除其中的Murano服务组件**  
，  
否则可能导致敏感的服务账户信息泄露，进而威胁到整个系统的安全。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5wib564mgPghr7q4WBViaxsX8SQ5ia4JREicic3athCe5qGkgbbXeYric0kd1T1TROiaOjERTlhAeibyOJNWA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5wib564mgPghr7q4WBViaxsX8icAlhYmp1NUQdzOJfQS9fM1mNZgckWkhDH6grIPVDHoG9Gp3piccLXag/640?wx_fmt=png&from=appmsg "")  
  
OpenStack官网公告  
  
附官网公告链接：  
OSSN/OSSN-0093 - OpenStack  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5yXUcNXlZTfLSicHtNGMWIVun4xMdkfQTMhX8Cpczfibypfr8mF6FTRRSZJicGVOTowrqKwScuzCUJbg/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
**这一漏洞是怎样运行的？**  
  
  
Murano是OpenStack中的一个组件，原本用于提供应用程序商店和部署功能，然而，MuranoPL扩展对YAQL语言的处理存在**不安全环境处理**  
的问题。  
  
**更为严重的是**  
，Murano项目目前已经停止维护，意味着没有官方修复计划来修补这个漏洞。  
  
也就是说，  
任何熟悉OpenStack的攻击者，都有可能利用这一漏洞，**通过Murano上传恶意组件，进而实现控制整个云平台的目的**  
。他们可以毫无阻拦地直击目标对象的“要害”，窃取或篡改其敏感数据、导致服务中断，甚至直接接管其平台管理权限，造成难以挽回的损失。  
  
值得一提的是，该漏洞是**深信服安全研究员lawliet和ZhiniangPeng**  
在日常研究中发现的。深信服判断其可能导致潜在的安全风险，便积极与监管机构和OpenStack官方取得联系，将漏洞信息提交给了官方。  
  
OpenStack官方对此表示高度重视，并在第一时间发布了公告，提醒广大用户关注此问题。  
  
OpenStack之所以能得到如此广泛的应用，离不开全球开发者的共同维护与努力，其强大的安全系统一直是其核心竞争力之一。  
  
然而，此漏洞的发现，也让我们看到了安全问题的复杂性和严峻性。深信服作为国内领先的云和安全服务提供商，在此次事件中的表现，无疑彰显了其深厚的技术实力。  
  
  
**关于深信服**  
  
深信服  
是一家专注于企业级网络安全、云计算、IT基础设施及物联网的产品和服务供应商。在如今的数字化时代，公司立志于承载各行业用户数字化转型过程中的基石性工作，从而让每个用户的数字化更简单、更安全。  
  
基于多年的技术积累，深信服在国内率先推出了多个前沿安全产品及服务，并在去年首秀**自研的安全大模型——安全GPT**  
的技术应用。发布至今，安全GPT已收获**100+体验用户**  
。  
  
目前，深信服已得到海内外用户的广泛认可，全球已有**超过10万家用户**  
正在使用深信服的产品，业务覆盖新加坡、马来西亚、泰国、意大利等50余个国家和地区。同时在国内**多个大型企业和机构**  
广泛应用，覆盖政府、金融、能源、运营商、医疗、教育、互联网等行业领域。  
  
最后，再次提醒各位OpenStack用户，如果你仍在使用或运行  
Murano组件，**请****务必尽快关闭或删除，**  
以免遭受潜在的安全风险！也建议大家定期关注官方公告，加强系统安全防护，提高安全意识，以确保业务的稳定运行。  
  
在这个充满挑战与机遇的时代，让我们携手共进，共同守护云端的安全与稳定！  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5yhazmB4EP58dqwjelKs39pE94xnsGXv55micVojHs0SSdCeia76yMcNgAwsU9TaB2TLd14jORrZFqg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
