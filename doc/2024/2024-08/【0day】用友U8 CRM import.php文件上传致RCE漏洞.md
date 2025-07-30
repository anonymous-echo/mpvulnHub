#  【0day】用友U8 CRM import.php文件上传致RCE漏洞   
原创 7coinSec  7coinSec   2024-08-10 22:52  
  
## 免责声明  
> 本文章仅用于信息安全防御技术分享，  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关  
，请严格遵循法律法规。  
> 未经作者允许，严禁转载。如有转载：请在公众号下留言  
  
## 漏洞简述  
  
用友CRM系统客户关系管理的第一需求就是对客户资源的集中管理，即为客户资源的企业化管理,可以避免因业务调整或人员变动造成的客户资源流失和客户管理盲区的产生;更重要是可以基于客户状况来归集相关业务信息，通过完善的信息来支持业务角色的工作,同时达到对业务阶段和行动的监控指导。这也是CRM对企业带来的核心变化。其接口import.php存在任意文件上传漏洞，攻击者课通过该漏洞获取系统服务器权限。  
## FOFA语法  
```
```  
## 响应内容特征  
  
![](https://mmbiz.qpic.cn/mmbiz_png/p863n88MewrXibPMzHtPhicUsVwB6mbzbZN2QgySaS7Vq7lXeHgndgVpc8IY7uSHrkcR14ZmBRHfeNrMNGJVpMvQ/640?wx_fmt=png&from=appmsg "")  
  
## 关注我们回复关键字【20240810】获取最新POC  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/p863n88MewrrZDHj38ibIOLPsYibtuWjyicoPwia4bq3iaDOribz04XYR5GzWAt61lWzp8MVSXicSZiciblkosoASKUiaNfQ/640?wx_fmt=jpeg "")  
  
**扫码关注**  
  
  
