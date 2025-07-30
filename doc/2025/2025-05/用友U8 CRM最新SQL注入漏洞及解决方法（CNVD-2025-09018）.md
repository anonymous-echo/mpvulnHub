#  用友U8 CRM最新SQL注入漏洞及解决方法（CNVD-2025-09018）   
原创 护卫神  护卫神说安全   2025-05-15 02:28  
  
![](https://mmbiz.qpic.cn/mmbiz_png/NV9GjS35LEhHico3Fp4v5ZrribXKibSZKibAeA1XYBDq92p6K8TZ5wC5OTyVqNXiaMchxRybBAU69icdOyRBA4GRgtVA/640?wx_fmt=png&from=appmsg "")  
  
用友U8 CRM是用友网络针对成长型企业推出的客户关系管理系统，聚焦客户全生命周期管理。其核心功能涵盖客户信息整合、销售机会跟进、市场活动管理及售后服务处理，支持从线索挖掘到订单成交的全流程自动化。系统内置销售漏斗分析工具，可实时监控商机推进阶段，科学预测销售业绩；同时提供多维客户价值评估模型，助力企业精准定位高价值客户群体。产品采用模块化设计，支持与用友ERP-U8财务、供应链等模块无缝集成，实现业财一体化管理。界面简洁易用，支持移动端协同办公，尤其适合制造业项目型销售及商贸流通领域企业，通过规范化流程管控降低客户流失率，提升服务响应效率。  
  
  
国家信息安全漏洞共享平台于2025-05-10公布该程序存在代码SQL注入漏洞。  
  
**漏洞编号**  
：CNVD-2025-09018  
  
**影响产品**  
：用友U8 CRM  
  
**漏洞级别**  
：  
高  
  
**公布时间**  
：2025-05-10  
  
**漏洞描述**  
：用友网络科技股份有限公司用友U8 CRM存在SQL注入漏洞，攻击者可利用该漏洞获取数据库敏感信息。。  
  
  
**解决办法：**  
  
厂商已发布补丁，请访问用友官方下载补丁更新。  
  
您也可以使用『护卫神·防入侵系统』的“  
注入防护  
”模块来解决该注入漏洞，不止对该漏洞有效，对网站所有的SQL注入漏洞和跨脚本漏洞都可以防护。  
  
  
  
**1、SQL注入防护和XSS跨站攻击防护**  
  
『护卫神·防入侵系统』自带的SQL注入防护模块（如图一）除了拦截SQL注入，还可以拦截XSS跨站脚本（如图二），一并解决U8 CRM的其他安全漏洞，拦截效果如图三。  
  
  
![U8 CRM防护SQL注入攻击](https://mmbiz.qpic.cn/mmbiz_png/NV9GjS35LEhHico3Fp4v5ZrribXKibSZKibAcO8wpemicyu9dzsjWyjgBeF5E0NYhD7maWdKVicjFUeFBklSS64A37sQ/640?wx_fmt=png&from=appmsg "U8 CRM防护SQL注入攻击")  
  
（图一：U8 CRM防护SQL注入攻击）  
  
  
  
![U8 CRM防护XSS跨站脚本攻击](https://mmbiz.qpic.cn/mmbiz_png/NV9GjS35LEhHico3Fp4v5ZrribXKibSZKibA4wLWnmDnAw9k9ISTvEIvDZYU9DfuCoFeLyicYALb2LcZzvAiaeYhIA6g/640?wx_fmt=png&from=appmsg "U8 CRM防护XSS跨站脚本攻击")  
  
（图二：U8 CRM防护XSS跨站脚本攻击）  
  
  
  
![SQL注入拦截效果](https://mmbiz.qpic.cn/mmbiz_png/NV9GjS35LEhHico3Fp4v5ZrribXKibSZKibAKF7PudFiccicmicl2RnRWo7ic1ORk7xeUzY8JDPj4R3NMrzN3mFkJCSW3A/640?wx_fmt=png&from=appmsg "SQL注入拦截效果")  
  
（图三：SQL注入拦截效果）  
  
  
  
