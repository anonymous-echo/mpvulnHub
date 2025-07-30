#  漏洞预警 美特CRM mcc_login.jsp SQL注入漏洞   
by 融云安全-cas  融云攻防实验室   2025-05-21 01:55  
  
**0x01 阅读须知**  
  
**融云安全的技术文章仅供参考，此文所提供的信息只为网络安全人员对自己所负责的网站、服务器等（包括但不限于）进行检测或维护参考，未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责。本文所提供的工具仅用于学习，禁止用于其他！！**  
  
**0x02 漏洞描述**  
  
美特软件是中国最强大的客户关系管理软件MetaCRM的提供商。MetaCRM是一款智能平台化CRM软件,通过提升企业管理和协同办公,全面提高企业管理水平和运营效率,帮助企业实现卓越管理。美特软件的使命是为企业客户提供咨询、产品、实施、服务在内一体化的客户关系管理服务。为客户先进、高效、实用的CRM软件系统，协助客户有效管理企业资源，提高运营效率，与客户一起走向成功。美特CRM mcc_login.jsp 存在SQL注入漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GWXBjgPE49wqfvccjGmrHbOfCS9ecgcdSeCZWhLsw7w0rp9gRPPxB4El8hGSxhgD7aVheQR47ctRBOibDj2s90g/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞复现**  
  
**f****o****fa:body="/common/scripts/basic.js"**  
  
1.执行poc发现存在SQL报错  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GWXBjgPE49wqfvccjGmrHbOfCS9ecgcdTtXwatFl4fGfr2QIywEEC2WtUzbTx1rUMPys3B64prpnjC5PnvjMdQ/640?wx_fmt=png&from=appmsg "")  
  
**2.nuclei脚本和代码审计过程发布在知识星球（AI时代，不会审计比原来更难拿到高薪。这位是七八年的审计经验大哥的代码审计星球。加入星球一起学习，全年POC 0 day、代码审计技巧服务）**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GWXBjgPE49wqfvccjGmrHbOfCS9ecgcd8T1lht8Z9EK5K0QHHiaUgNt0RVYzicVvvbConBNAZqsrnnLG9BYuGNbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/GWXBjgPE49wqfvccjGmrHbOfCS9ecgcdkjmmkfbntgm3vP7sZbaLsOZ9VP7zx8TKLBXpzYV7VZHS013V7ITwLw/640?wx_fmt=png&from=appmsg "")  
  
**高质量漏洞利用研究，代码审计圈子等。**  
  
**【圈子权益】**  
  
**1，一年至少200+漏洞Poc及对应漏洞批量利用工具**  
  
**2，各种漏洞利用工具及后续更新，渗透工具、文档资源分享**  
  
**星球目前在推广期价格为79元，优惠30元，后面恢复原价。**  
![图片](https://mmbiz.qpic.cn/mmbiz_png/GWXBjgPE49xKicPTzjrTnfF8oYyhDcc1ITEfg8wqjLIicS2XeTVb9q8lpGbicVh9vT9V7lDUU5lgF3Kv62ciabVmQg/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**0x05 公司简介**  
  
江西渝融云安全科技有限公司，2017年发展至今，已成为了一家集云安全、物联网安全、数据安全、等保建设、风险评估、信息技术应用创新及网络安全人才培训为一体的本地化高科技公司，是江西省信息安全产业链企业和江西省政府部门重点行业网络安全事件应急响应队伍成员。  
  
   公司现已获得信息安全集成三级、信息系统安全运维三级、风险评估三级等多项资质认证，拥有软件著作权十八项；荣获2020年全国工控安全深度行安全攻防对抗赛三等奖；庆祝建党100周年活动信息安全应急保障优秀案例等荣誉......  
****  
‌  
  
**编制：sm**  
  
**审核：fjh**  
  
**审核：Dog**  
  
****  
**1个1朵********5毛钱**  
  
**天天搬砖的小M**  
  
**能不能吃顿好的**  
  
**就看你们的啦**  
  
****  
  
