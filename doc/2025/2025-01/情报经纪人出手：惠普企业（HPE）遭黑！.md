#  情报经纪人出手：惠普企业（HPE）遭黑！   
原创 网空闲话  网空闲话plus   2025-01-17 00:00  
  
2025年1月17日，监测泄露论坛发现，惠普企业（HPE）遭遇了一起重大数据泄露事件，威胁行为者IntelBroker、zjj和EnergyWeaponUser声称对此负责。此次攻击涉及HPE的多个关键系统，泄露了大量敏感数据，包括私有GitHub存储库、Docker构建、SAP Hybris文档、证书（私钥和公钥）、产品源代码、API访问凭据、WePay集成、自托管GitHub存储库以及用户个人身份信息（PII）。攻击者通过暗网论坛BreachForums公开了部分泄露数据，并提供了相关证据以支持其说法。帖子中没有透露数据的总体数量，也没有提及售价，只是留下了联系方式。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0KRmt3K30icUib1OTrNlvtmdOMVHiaEORxKmTcuErlo5npuULFbElsRYicfsGPn0lGEKCZGdd9icgBxvV83qkDnOndw/640?wx_fmt=other&from=appmsg "")  
#### 攻击概述  
- **攻击者与攻击方式**  
：威胁行为者IntelBroker声称在两天内成功入侵HPE的多个系统，并窃取了大量敏感数据。攻击者展示了包括Zerto和iLO等专有技术的源代码存储库、API和WePay访问凭证、证书以及客户PII等证据。  
  
- **泄露数据范围**  
：  
  
- **私有存储库**  
：包括GitHub托管和自托管的存储库，涉及产品开发的敏感细节。  
  
- **证书**  
：HPE服务中使用的公钥和私钥，可能导致进一步的安全风险。  
  
- **用户PII**  
：包括过去客户的姓名、地址等个人身份信息。  
  
- **集成详情**  
：API系统和WePay支付网关的访问凭证。  
  
- **其他数据**  
：SAP Hybris文档、Docker构建和专有代码库。  
  
- ![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icUib1OTrNlvtmdOMVHiaEORxKibuy2lZiaUiacyLicSC6K5EZRYrvlNIwu01AogW1ficILTnCuOUatF7035Q/640?wx_fmt=png&from=appmsg "")  
  
  
#### 攻击者的证据  
  
攻击者在暗网论坛上分享了多张截图，展示了其对HPE内部系统和API端点的访问权限。这些截图包括：  
- 后端系统的访问权限。  
  
- API端点的详细信息。  
  
- 内部文档和集成系统的截图。  
  
- ![](https://mmbiz.qpic.cn/mmbiz_png/0KRmt3K30icUib1OTrNlvtmdOMVHiaEORxKic8VJdFSH0x4JArRPpZcGa0AJeZvVJZiagpLZbagF8hXek227LnpJj4w/640?wx_fmt=png&from=appmsg "")  
  
  
#### 泄露事件影响  
  
此次数据泄露事件对HPE的运营和声誉可能产生深远影响：  
- **知识产权盗窃**  
：Zerto和iLO等技术的产品源代码泄露，可能导致竞争对手获取HPE的专有解决方案，削弱其市场竞争力。  
  
- **客户信任受损**  
：泄露的客户PII和交付记录可能损害HPE在客户中的声誉，导致客户流失或法律纠纷。  
  
- **运营中断风险**  
：攻击者通过获取API访问凭证和证书，可能进一步利用漏洞破坏HPE的服务，导致业务中断。  
  
- **潜在后续攻击**  
：泄露的API访问凭据和证书可能被用于发起更多攻击，进一步扩大安全风险。  
  
#### 应对建议  
  
为应对此次数据泄露事件，HPE应采取以下措施：  
- **事件响应**  
：立即评估违规的程度，采取措施阻止进一步的未授权访问。  
  
- **凭证管理**  
：撤销并轮换所有API密钥、证书和访问凭证，确保系统的安全性。  
  
- **数据安全审计**  
：对存储库、开发系统和API中的安全控制进行全面审查，识别并修复潜在漏洞。  
  
- **客户通知**  
：向受影响的客户发出违规警报，并提供数据保护资源，帮助客户降低风险。  
  
- **威胁监控**  
：持续监控暗网论坛，查找与泄露数据相关的进一步帖子或交易，及时采取应对措施。  
  
#### 结论  
  
此次HPE数据泄露事件凸显了高级威胁行为者对大型企业的持续威胁。攻击者通过窃取敏感数据，对HPE的知识产权、客户信任和运营稳定性构成了重大风险。HPE必须迅速采取行动，修复漏洞、加强安全防护，并将潜在影响降至最低。同时，这一事件也为其他企业敲响了警钟，提醒其在网络安全方面保持高度警惕，防止类似事件的发生。  
  
此前，2024年10月情报经纪人透露其攻击了思科，获取了大量数据。到12月，情报经纪人曾泄露了思科4.5T数据。  
  
[情报经纪人放大招：思科4.5T数据已泄露](https://mp.weixin.qq.com/s?__biz=MzkyMjQ5ODk5OA==&mid=2247506248&idx=1&sn=d6ef4804d0eaf02f0cb9a25030fe613d&scene=21#wechat_redirect)  
  
  
[出大事了！情报经纪人声称泄露大量思科数据，思科称“正在进行调查”](https://mp.weixin.qq.com/s?__biz=MzkyMjQ5ODk5OA==&mid=2247504090&idx=1&sn=5c8a4dac025b56645f818ee09d00375f&scene=21#wechat_redirect)  
  
  
  
参考资源  
  
1、https://darkwebinformer.com/intelbroker-zjj-and-energyweaponuser-are-allegedly-selling-the-data-of-hewlett-packard-enterprise-hpe/  
  
2、https://breachforums.st/Thread-SELLING-Hewlett-Packet-Enterprise  
  
