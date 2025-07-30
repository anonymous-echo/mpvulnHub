#  【漏洞通告】Ivanti Connect Secure,Policy Secure&ZTA Gateways缓冲区溢出漏洞   
深瞳漏洞实验室  深信服千里目安全技术中心   2025-01-09 08:34  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zLZ5FfjZh8edmIIRJhuudiahg9nDUmPyNoNlpibwJDWBKOSc8ibHhuDicAynQ7JwUZ6KWYpQkEK1TRLw/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞名称：**  
  
Ivanti Connect Secure, Policy Secure & ZTA Gateways 缓冲区溢出漏洞(CVE-2025-0282)  
  
**组件名称：**  
  
Ivanti Connect Secure, Policy Secure & ZTA Gateways  
  
  
**影响范围：**  
  
22.7R2 ≤ Ivanti Connect Secure < 22.7R2.5  
  
22.7R1 ≤ Ivanti Policy Secure < 22.7R1.2  
  
22.7R2 ≤ ZTA gateways < 22.7R2.3  
  
**漏洞类型：**  
  
缓冲区溢出  
  
**利用条件：**  
  
1、用户认证：不需要用户认证  
  
2、前置条件：默认配置  
  
3、触发方式：远程  
  
**综合评价：**  
  
<综合评定利用难度>：容易，无需授权即可造成远程代码执行。  
  
<综合评定威胁等级>：严重，能造成远程代码执行。  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zLZ5FfjZh8edmIIRJhuudiayrurlhFqo80mtkRsAjnqbOhlCIbBMpJuNLce57MK4z2m2BnmM61mtg/640?wx_fmt=gif&from=appmsg "")  
  
**组件介绍**  
  
Ivanti Connect Secure, Policy Secure & ZTA Gateways 均为 Ivanti 公司提供的网络产品。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zLZ5FfjZh8edmIIRJhuudiayrurlhFqo80mtkRsAjnqbOhlCIbBMpJuNLce57MK4z2m2BnmM61mtg/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞简介**  
  
2025年1月9日，深瞳漏洞实验室监测到一则Ivanti Connect Secure, Policy Secure & ZTA Gateways组件存在缓冲区溢出漏洞的信息，漏洞编号：CVE-2025-0282，漏洞威胁等级：严重。  
  
Ivanti Connect Secure 22.7R2.5 版本之前、Ivanti Policy Secure 22.7R1.2 版本之前以及 Ivanti Neurons for ZTA Gateways 22.7R2.3 版本之前存在基于堆栈的缓冲区溢出漏洞，该漏洞允许远程未经身份验证的**攻击者执行任意代码，导致服务器失陷。注：该漏洞已出现在野利用。**  
  
****  
  
  
**影响范围**  
  
目前受影响的Ivanti 产品版本：  
  
22.7R2 ≤ Ivanti Connect Secure < 22.7R2.5  
  
22.7R1 ≤ Ivanti Policy Secure < 22.7R1.2  
  
22.7R2 ≤ ZTA gateways < 22.7R2.3  
  
  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zLZ5FfjZh8edmIIRJhuudiayrurlhFqo80mtkRsAjnqbOhlCIbBMpJuNLce57MK4z2m2BnmM61mtg/640?wx_fmt=gif&from=appmsg "")  
  
**官方修复建议**  
  
  
**安全版本：**  
  
Ivanti Connect Secure 22.7R2.5  
  
Ivanti Policy Secure 22.7R1.2  
  
ZTA gateways 22.7R2.3  
  
  
**修复建议：**  
  
建议受影响客户将设备更新到安全版本。  
  
Ivanti Connect Secure补丁下载链接：https://portal.ivanti.com/  
  
针对Ivanti Policy Secure 、ZTA gateways补丁预计于1月21日发布。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zLZ5FfjZh8edmIIRJhuudiayrurlhFqo80mtkRsAjnqbOhlCIbBMpJuNLce57MK4z2m2BnmM61mtg/640?wx_fmt=gif&from=appmsg "")  
  
**临时修复建议**  
  
  
对于Ivanti Connect Secure的用户，运行内置完整性检查工具 (ICT)。  
  
如扫描结果不存在威胁，恢复出厂设置并应用最新补丁；  
  
如扫描结果中发现威胁，请立刻断开受影响的产品并与其他资源隔离，重置任何已连接的密码，密钥和证书，联系官方进行进一步的应急和溯源。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5zLZ5FfjZh8edmIIRJhuudiayrurlhFqo80mtkRsAjnqbOhlCIbBMpJuNLce57MK4z2m2BnmM61mtg/640?wx_fmt=gif&from=appmsg "")  
  
**深信服解决方案**  
  
  
**风险资产发现**  
  
支持对Ivanti Connect Secure, Policy Secure & ZTA Gateways的主动检测，可批量检出业务场景中该事件的受影响资产情况，相关产品如下：  
  
**【深信服云镜YJ】** 已发布资产检测方案，指纹ID:0030642。  
  
**【深信服漏洞评估工具TSS】**已发布资产检测方案，指纹ID:0030642。  
  
  
  
**参考链接**  
  
  
  
https://www.ivanti.com/blog/security-update-ivanti-connect-secure-policy-secure-and-neurons-for-zta-gateways  
  
  
https://forums.ivanti.com/s/article/Security-Advisory-Ivanti-Connect-Secure-Policy-Secure-ZTA-Gateways-CVE-2025-0282-CVE-2025-0283?language=en_US&_gl=1*17imebm*_gcl_au*MjAwNjQ2ODMyMy4xNzM2Mzg0NTA4  
  
  
  
**时间轴**  
  
  
  
**2025/01/09**  
  
深瞳漏洞实验室监测到Ivanti Connect Secure, Policy Secure & ZTA Gateways 缓冲区溢出漏洞信息。  
  
  
**2025/01/09**  
  
深瞳漏洞实验室发布漏洞通告。  
  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5wOJ3wQu9LcWzhpCdtn9ia2QMcod5AV89wfibknicNXBWTARK84osW46a5KkllibibiaYH18zyHjoAh3C6A/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5zLZ5FfjZh8edmIIRJhuudiadhRV5mEFL6xvaXwcJzxf8NodDUQZKnH7bvz30DeoA0LwyRFhhXClMg/640?wx_fmt=png&from=appmsg "")  
  
  
