#  泛微E-Cology9 任意用户登录漏洞   
深瞳漏洞实验室  深信服千里目安全技术中心   2023-05-16 17:47  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wLgQcSChGGSs1eMMv2hsqiarV64THp7TBzC721XHnnkvKaJJjibS46icjOeUKY9hm8DRGPq2gniajmHA/640?wx_fmt=gif "")  
  
**漏洞名称：**  
  
泛微E-Cology9 任意用户登录漏洞  
  
**组件名称：**  
  
E-Cology9   
  
**影响范围：**  
  
E-Cology9 < 10.57.1  
  
**漏洞类型：**  
  
绕过认证  
  
**利用条件：**  
  
1、用户认证：否  
  
2、前置条件：默认配置  
  
3、触发方式：远程  
  
**综合评价：**  
  
<综合评定利用难度>：容易  
  
<综合评定威胁等级>：高危，能导致任意用户登录。  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wLgQcSChGGSs1eMMv2hsqiauUS5bVM6SGd7g3PV8YSAMMVAFZD2F89k6RnUpfCZqLsnnMIiaMqvuFA/640?wx_fmt=gif "")  
  
**组件介绍**  
  
泛微E-Cology9系统是一套基于JSP及SQL Server数据库的OA系统，广泛应用于各个行业。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wLgQcSChGGSs1eMMv2hsqiauUS5bVM6SGd7g3PV8YSAMMVAFZD2F89k6RnUpfCZqLsnnMIiaMqvuFA/640?wx_fmt=gif "")  
  
**漏洞简介**  
  
该漏洞是由于泛微E-Cology9存在一个信息泄露接口，攻击者在未授权的情况下，可利用该接口获取系统已注册的用户。此外，由于泛微E-Cology9使用了不安全的算法设计，**攻击者可以利用获取到的用户名构造恶意数据，模拟任意用户登录后台。**  
  
  
**影响范围**  
  
目前厂商暂未发布修复措施解决此安全问题，建议随时关注厂商主页或联系厂商以获取解决办法：  
  
https://www.e-office.cn/  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wLgQcSChGGSs1eMMv2hsqiauUS5bVM6SGd7g3PV8YSAMMVAFZD2F89k6RnUpfCZqLsnnMIiaMqvuFA/640?wx_fmt=gif "")  
  
**官方修复建议**  
  
  
当前官方已发布受影响版本的对应补丁，建议受影响的用户及时更新官方的安全补丁。链接如下：  
  
https://www.weaver.com.cn/cs/securityDownload.asp  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wLgQcSChGGSs1eMMv2hsqiauUS5bVM6SGd7g3PV8YSAMMVAFZD2F89k6RnUpfCZqLsnnMIiaMqvuFA/640?wx_fmt=gif "")  
  
**深信服解决方案**  
  
  
**1.风险资产发现**  
  
支持对泛微E-Cology9 的主动检测，可**批量检出**业务场景中该事件的**受影响资产**情况，相关产品如下：  
  
**【深信服主机安全检测响应平台CWPP】**已发布资产检测方案。  
  
**【深信服云镜YJ】**已发布资产检测方案。  
  
  
**2.漏洞主动检测**  
  
支持对泛微E-Cology9 任意用户登录漏洞的主动检测，可**批量快速检出**业务场景中是否存在漏洞风险，相关产品如下：  
  
**【深信服云镜YJ】**预计2023年5月19日发布检测方案。  
  
**【深信服漏洞评估工具TSS】**预计2023年5月22日发布检测方案。  
  
**【深信服主机安全检测响应平台CWPP】**预计2023年5月19日发布检测方案。  
  
**【深信服安全托管服务MSS】**预计2023年5月19日发布检测方案。  
  
**【深信服安全检测与响应平台XDR】**预计2023年5月19日发布检测方案。  
  
  
**3.漏洞安全监测**  
  
支持对泛微E-Cology9 任意用户登录漏洞的监测，可依据流量收集实时监控业务场景中的**受影响资产**情况，**快速检查**受影响范围，相关产品及服务如下：  
  
**【深信服安全感知管理平台SIP】**预计2023年5月19日发布检测方案。  
  
**【深信服安全托管服务MSS】**预计2023年5月19日发布检测方案。  
  
**【深信服安全检测与响应平台XDR】**预计2023年5月19日发布检测方案。  
  
  
**4.漏洞安全防护**  
  
支持对泛微E-Cology9 任意用户登录漏洞的防御，可阻断攻击者针对该事件的入侵行为，相关产品及服务如下：  
  
**【深信服下一代防火墙AF】**预计2023年5月19日发布防护方案。  
  
**【深信服终端安全管理系统EDR】**预计2023年5月19日发布防护方案。  
  
**【深信服Web应用防火墙WAF】**预计2023年5月19日发布防护方案。  
  
**【深信服安全托管服务MSS】**预计2023年5月19发布防护方案。  
  
**【深信服安全检测与响应平台XDR】**预计2023年5月19日发布防护方案。  
  
  
**参考链接**  
  
https://www.weaver.com.cn/cs/securityDownload.asp  
  
  
**时间轴**  
  
  
  
**2023/5/16**  
  
深信服监测到泛微官方发布安全补丁。  
  
  
**2023/5/16**  
  
深信服千里目安全技术中心发布漏洞通告。  
  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5wLgQcSChGGSs1eMMv2hsqiau2C6efcmkdTqCxkbJWWtIFaQenTdn5W0iaDvoSq8icqhoJibxByWVA89g/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5wLgQcSChGGSs1eMMv2hsqiaNHRsmzJVRtb1CQuK7E646K5TSfTq9Bia4OAWKusYsmNtV81cmjhJkIw/640?wx_fmt=jpeg "")  
  
  
