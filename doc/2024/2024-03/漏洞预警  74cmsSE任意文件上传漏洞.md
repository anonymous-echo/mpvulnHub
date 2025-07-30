#  漏洞预警 | 74cmsSE任意文件上传漏洞   
浅安  浅安安全   2024-03-21 07:50  
  
**0x00 漏洞编号**  
- # CVE-2024-2561  
  
**0x01 危险等级**  
- 高危  
  
**0x02 漏洞概述**  
  
74CMS人才招聘系统是基于PHP+MYSQL的免费网站管理系统源码，提供完善的人才招聘网站建设方案。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/7stTqD182SXtdjia5D9icjEAia4Q27JS1QYWdSDvV1horBa5QWO223YzXyCHV1al2E21VpEIr84Zy1ZxibJl5Eufow/640?wx_fmt=png&from=appmsg "")  
  
**0x03 漏洞详情**  
  
**CVE-2024-2561**  
  
**漏洞类型：**  
文件上传  
  
**影响：**  
接管服务器  
  
**简述：**  
74cmsSE 3.28.0版本中存在任意文件上传漏洞，受影响的组件是企业logo处理程序的文件/controller/company/Index.php#sendCompanyLogo中的sendCompanyLogo函数，通过操纵参数imgBase64可以导致无限制的文件上传。  
###   
  
**0x04 影响版本**  
- 74cmsSE 3.28.0  
  
**0x05****POC**  
  
https://gist.github.com/Southseast/9f5284d8ee0f6d91e72eef73b285512a  
  
**仅供安全研究与学习之用，若将工具做其他用途，由使用者承担全部法律及连带责任，作者及发布****者**  
**不承担任何法律及连带责任。**  
  
**0x06****修复建议**  
  
**目前官方暂未发布漏洞修复版本，建议用户关注官网动态****：**  
  
https://www.74cms.com/  
  
  
  
