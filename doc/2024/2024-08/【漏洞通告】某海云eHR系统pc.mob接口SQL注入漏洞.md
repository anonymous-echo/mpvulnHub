#  【漏洞通告】某海云eHR系统pc.mob接口SQL注入漏洞   
原创 常行安服团队  常行科技   2024-08-30 21:20  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/r8QjvJibulhQKuLaKRzbgyb2UiaMLGFD5u4ia6dZ0DQjdAicZEI5IYCbxa1VaJsexOmgUbTW6zlAW6mLXAeibvxWAGA/640?wx_fmt=png&from=appmsg "")  
  
  
  
某海  
eHR  
系统，聚焦人力资源管理痛点，打破传统  
eHR  
系统各功能模块数据割裂局限，为企业打造数据一体化、流程一体化、终端一体化的智能互联人力资源管理解决方案，构建业务闭环流畅、全局数据贯通、系统高度集成、权限规范可控的一站式人力资源管理数字化平台。  
  
  
  
<table><tbody style="outline: 0px;visibility: visible;"><tr style="outline: 0px;visibility: visible;"><td colspan="4" height="27" align="center" valign="middle" style="outline: 0px;word-break: break-all;hyphens: auto;background: rgb(70, 118, 217);visibility: visible;"><p style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 14px;color: rgb(255, 255, 255);visibility: visible;">漏洞概述</span><span style="outline: 0px;font-size: 16px;color: white;font-family: 宋体;visibility: visible;"></span></p></td></tr><tr style="outline: 0px;visibility: visible;"><td style="border-top-width: initial;border-top-style: none;outline: 0px;word-break: break-all;hyphens: auto;visibility: visible;" width="76.33333333333333"><p style="outline: 0px;text-align: left;line-height: 16px;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 13px;font-family: 微软雅黑, sans-serif;visibility: visible;">漏洞名称</span></strong></p></td><td colspan="3" style="border-top-width: initial;border-top-style: none;border-left-width: initial;border-left-style: none;outline: 0px;word-break: break-all;hyphens: auto;line-height: 16px;visibility: visible;text-align: left;width: 578px;font-family: system-ui, -apple-system, &#34;system-ui&#34;, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;text-wrap: wrap;background-color: rgb(255, 255, 255);" width="461.3333333333333"><span style="color: rgb(0, 0, 0);font-size: 13px;letter-spacing: 1px;text-decoration: none solid rgb(0, 0, 0);">某海云eHR系统pc.mob接口SQL注入漏洞</span><span style="color: rgb(0, 0, 0);font-size: 13px;letter-spacing: 1px;text-decoration: none solid rgb(0, 0, 0);"></span></td></tr><tr style="outline: 0px;text-align: left;line-height: 16px;visibility: visible;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;"><td style="border-top-width: initial;border-top-style: none;outline: 0px;word-break: break-all;hyphens: auto;line-height: 16px;visibility: visible;" width="109.33333333333333"><p style="outline: 0px;line-height: 16px;visibility: visible;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 13px;font-family: 微软雅黑, sans-serif;visibility: visible;">公开时间</span></strong></p></td><td style="border-top-width: initial;border-top-style: none;border-left-width: initial;border-left-style: none;outline: 0px;word-break: break-all;hyphens: auto;line-height: 16px;visibility: visible;" width="164.33333333333334"><p style="outline: 0px;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;border-left-width: initial;border-left-style: none;line-height: 16px;visibility: visible;"><span style="color: black;font-size: 13px;letter-spacing: 1px;">2024-08-20</span></p></td><td style="border-top-width: initial;border-top-style: none;outline: 0px;word-break: break-all;hyphens: auto;line-height: 16px;visibility: visible;" width="102.33333333333333"><p style="outline: 0px;line-height: 16px;visibility: visible;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 13px;font-family: 微软雅黑, sans-serif;visibility: visible;">影响量级</span></strong></p></td><td style="border-top-width: initial;border-top-style: none;border-left-width: initial;border-left-style: none;outline: 0px;word-break: break-all;hyphens: auto;line-height: 16px;visibility: visible;" width="155.33333333333334"><p style="outline: 0px;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;border-left-width: initial;border-left-style: none;line-height: 16px;visibility: visible;"><span style="outline: 0px;color: black;font-size: 13px;letter-spacing: 1px;text-decoration-style: solid;text-decoration-color: rgb(0, 0, 0);visibility: visible;">万级</span></p></td></tr><tr style="outline: 0px;text-align: left;line-height: 16px;visibility: visible;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;"><td style="border-top-width: initial;border-top-style: none;outline: 0px;word-break: break-all;hyphens: auto;line-height: 16px;visibility: visible;" width="78"><p style="outline: 0px;line-height: 16px;visibility: visible;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 13px;font-family: 微软雅黑, sans-serif;visibility: visible;">风险评级</span></strong></p></td><td style="border-top-width: initial;border-top-style: none;border-left-width: initial;border-left-style: none;outline: 0px;word-break: break-all;hyphens: auto;visibility: visible;" width="164.33333333333334"><p style="outline: 0px;line-height: 16px;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 13px;color: red;font-family: 微软雅黑, sans-serif;visibility: visible;">高危</span></strong></p></td><td style="border-top-width: initial;border-top-style: none;outline: 0px;word-break: break-all;hyphens: auto;line-height: 16px;visibility: visible;" width="107.33333333333333"><p style="outline: 0px;line-height: 16px;visibility: visible;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 13px;font-family: 微软雅黑, sans-serif;visibility: visible;">CVSS 3.1分数</span></strong></p></td><td style="border-top-width: initial;border-top-style: none;border-left-width: initial;border-left-style: none;outline: 0px;word-break: break-all;hyphens: auto;visibility: visible;" width="155.33333333333334"><p style="outline: 0px;line-height: 16px;visibility: visible;"><span style="color: rgb(0, 0, 0);"><strong style="outline: 0px;visibility: visible;"><span style="color: rgb(0, 0, 0);outline: 0px;font-size: 13px;font-family: 微软雅黑, sans-serif;visibility: visible;">-</span></strong></span></p></td></tr><tr style="outline: 0px;text-align: left;line-height: 16px;visibility: visible;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;"><td style="border-top-width: initial;border-top-style: none;outline: 0px;word-break: break-all;hyphens: auto;line-height: 16px;visibility: visible;" width="78"><p style="outline: 0px;line-height: 16px;visibility: visible;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 13px;font-family: 微软雅黑, sans-serif;visibility: visible;">威胁类型</span></strong></p></td><td style="border-top-width: initial;border-top-style: none;border-left-width: initial;border-left-style: none;outline: 0px;word-break: break-all;hyphens: auto;line-height: 16px;visibility: visible;" width="164.33333333333334"><p style="outline: 0px;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;border-left-width: initial;border-left-style: none;line-height: 16px;visibility: visible;"><span style="color: rgb(0, 0, 0);font-size: 13px;letter-spacing: 1px;">SQL注入</span></p></td><td style="border-top-width: initial;border-top-style: none;outline: 0px;word-break: break-all;hyphens: auto;line-height: 16px;visibility: visible;" width="107.33333333333333"><p style="outline: 0px;line-height: 16px;visibility: visible;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 13px;font-family: 微软雅黑, sans-serif;visibility: visible;">利用可能性</span></strong></p></td><td style="border-top-width: initial;border-top-style: none;border-left-width: initial;border-left-style: none;outline: 0px;word-break: break-all;hyphens: auto;line-height: 16px;visibility: visible;" width="155.33333333333334"><p style="outline: 0px;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;border-left-width: initial;border-left-style: none;line-height: 16px;visibility: visible;"><span style="color: rgb(255, 0, 0);"><strong><span style="color: rgb(255, 0, 0);outline: 0px;font-size: 13px;letter-spacing: 1px;text-decoration-style: solid;text-decoration-color: rgb(0, 0, 0);visibility: visible;">高</span></strong></span></p></td></tr><tr style="outline: 0px;text-align: left;line-height: 16px;visibility: visible;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;"><td style="border-top-width: initial;border-top-style: none;outline: 0px;word-break: break-all;hyphens: auto;line-height: 16px;visibility: visible;" width="78"><p style="outline: 0px;line-height: 16px;visibility: visible;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 13px;font-family: 微软雅黑, sans-serif;visibility: visible;">POC状态</span></strong></p></td><td style="border-top-width: initial;border-top-style: none;border-left-width: initial;border-left-style: none;outline: 0px;word-break: break-all;hyphens: auto;visibility: visible;" width="164.33333333333334"><p style="outline: 0px;line-height: 16px;visibility: visible;"><span style="outline: 0px;font-size: 13px;font-family: 微软雅黑, sans-serif;visibility: visible;"><strong style="outline: 0px;letter-spacing: 0.578px;visibility: visible;"><span style="outline: 0px;color: red;visibility: visible;">已公开</span></strong></span></p></td><td style="border-top-width: initial;border-top-style: none;outline: 0px;word-break: break-all;hyphens: auto;line-height: 16px;visibility: visible;" width="107.33333333333333"><p style="outline: 0px;line-height: 16px;visibility: visible;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 13px;font-family: 微软雅黑, sans-serif;visibility: visible;">在野利用状态</span></strong></p></td><td style="border-top-width: initial;border-top-style: none;border-left-width: initial;border-left-style: none;outline: 0px;word-break: break-all;hyphens: auto;line-height: 16px;visibility: visible;" width="155.33333333333334"><p style="outline: 0px;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;border-left-width: initial;border-left-style: none;line-height: 16px;visibility: visible;"><span style="outline: 0px;color: black;font-size: 13px;letter-spacing: 1px;text-decoration-style: solid;text-decoration-color: rgb(0, 0, 0);visibility: visible;">有<br/></span></p></td></tr><tr style="outline: 0px;text-align: left;line-height: 16px;visibility: visible;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;"><td style="border-top-width: initial;border-top-style: none;outline: 0px;word-break: break-all;hyphens: auto;line-height: 16px;visibility: visible;" width="78"><p style="outline: 0px;line-height: 16px;visibility: visible;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 13px;font-family: 微软雅黑, sans-serif;visibility: visible;">EXP状态</span></strong></p></td><td style="border-top-width: initial;border-top-style: none;border-left-width: initial;border-left-style: none;outline: 0px;word-break: break-all;hyphens: auto;visibility: visible;" width="164.33333333333334"><p style="outline: 0px;line-height: 16px;visibility: visible;"><span style="outline: 0px;font-size: 13px;font-family: 微软雅黑, sans-serif;color: rgb(39, 44, 39);visibility: visible;"><strong style="outline: 0px;letter-spacing: 0.578px;visibility: visible;"><span style="outline: 0px;color: red;visibility: visible;">已公开</span></strong></span></p></td><td style="border-top-width: initial;border-top-style: none;outline: 0px;word-break: break-all;hyphens: auto;line-height: 16px;visibility: visible;" width="107.33333333333333"><p style="outline: 0px;line-height: 16px;visibility: visible;word-break: break-all;hyphens: auto;border-top-width: initial;border-top-style: none;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 13px;font-family: 微软雅黑, sans-serif;visibility: visible;">技术细节状态</span></strong></p></td><td style="border-top-width: initial;border-top-style: none;border-left-width: initial;border-left-style: none;outline: 0px;word-break: break-all;hyphens: auto;visibility: visible;" width="155.33333333333334"><p style="outline: 0px;line-height: 16px;visibility: visible;"><strong style="outline: 0px;visibility: visible;"><span style="outline: 0px;font-size: 13px;color: red;font-family: 微软雅黑, sans-serif;visibility: visible;">已公开</span></strong></p></td></tr></tbody></table>  
  
**漏洞详情**  
  
   
Vulnerability Details   
  
  
  
**0x00**  
  
- **漏洞描述**  
  
  
近日，互联网披露某海云eHR系统pc.mob接口存在SQL注入漏洞的情报，该平台接口/RedseaPlatform/goApp/pc.mob存在sql注入，攻击者可利用此漏洞获取敏感信息，对系统造成危害。  
  
常行安服团队分析并复现此漏洞，鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护  
  
  
  
  
**受影响范围**  
  
   
Affected Version   
  
  
  
**0x01**  
  
某海云eHR  
  
  
**修复方案**  
  
   
Solutions   
  
  
  
**0x02**  
- **临时解决方案**  
  
1.加强系统和网络的访问控制，修改防火墙策略，不将非必要服务暴露于公网;  
  
2.如果目前无法升级，若业务环境允许，使用白名单限制应用服务端口的访问来降低风险;  
  
3.定期对服务器上的网站后门文件进行及时查杀。  
  
  
  
- **解决方案**  
  
目前官方已发布漏洞修复版本，建议用户升级到安全版本。  
  
  
**漏洞复现/验证**  
  
   
Reproduction   
  
  
  
**0x03**  
  
服务器响应成功延迟3秒。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/r8QjvJibulhQKuLaKRzbgyb2UiaMLGFD5uAYtBXbF8AbGcrHw6lt40icGibicqWeRKcz7gicCtmMWO96evUiauLB4Yhmg/640?wx_fmt=png&from=appmsg "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5ibqUx1JicPMtpzBF9mpibjVeab8S0LPppgyJS90BEuqdO07WNt8kmenK1FGaoVBxTSgibfLdUL4SLKy7DCsaYdxxQ/640?wx_fmt=png "")  
  
**the end**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/5ibqUx1JicPMtpzBF9mpibjVeab8S0LPppgQDn95A8w6k7yF4nOjPR3icYcLzQnF22HZl8g3o5VLvKMQJEo4gPS7wQ/640?wx_fmt=png "")  
  
  
  
常行科技是一家专注于**网络安全解决方案和运营服务**  
的“专精特新”企业，粤港澳专精特新标杆企业 TOP100，国家级高新技术企业，国家级科技型中小企业，广东省创新型中小企业，立志深耕于网络安全服务领域，是网络安全运营服务**PTM理论**  
的首创者。  
  
自建网络安全攻防实验室“**大圣·攻防实验室(DS-Lab)**”，专注于最新的网络攻防技术研究、安全人才培养、客户环境模拟、安全产品研发、应急演练模拟、安全技术培训等。与鹏城实验室深入合作，共建**鹏城靶场常行科技分靶场**。大圣·攻防实验室“行者战队”近年来多次参加国内外的实战攻防演练及比赛，并取得优秀战果。  
  
常行科技**三大服务体系、六大场景化解决方案**多维度为客户提供最适合自身需求的高性价比网络安全解决方案，**低成本、高质量**地帮助客户解决网络和数据安全相关问题。  
  
  
**有常行，更安全**  
  
****  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/r8QjvJibulhT9xicZgBkutnwqozGYfW20cxgUzbMVP117Px3xDtnafDiaeY2ToD2ibicnd3SaQE7qHuCMrL0X2ND0Qg/640?wx_fmt=jpeg "")  
  
常为而不置  
  
常行而不休  
  
了解更多咨询请关注公众号  
  
  
