#  【漏洞通告】kkFileView任意文件上传漏洞   
深瞳漏洞实验室  深信服千里目安全技术中心   2024-04-18 19:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wib564mgPghr7q4WBViaxsX83o7icicyTxiaLiagUzLWIIcWuRRzx5QbyJytNGD7vldhojGMb82SUhNxAA/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞名称：**  
  
kkFileView任意文件上传漏洞  
  
**组件名称：**  
  
kkFileView  
  
**影响范围：**  
  
4.2.0 ≤ kkFileView ≤ v4.4.0-beta  
  
**漏洞类型：**  
  
任意文件上传  
  
**利用条件：**  
  
1、用户认证：否  
  
2、前置条件：默认配置  
  
3、触发方式：远程  
  
**综合评价：**  
  
<综合评定利用难度>：容易，无需授权即可任意文件上传。  
  
<综合评定威胁等级>：高危，能造成远程代码执行。  
  
**官方解决方案：**  
  
已发布  
  
  
  
  
  
**漏洞分析**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wib564mgPghr7q4WBViaxsX8ohhW780Oa6J23atvmSVLEk6JQTTpnrIUK1hCtyS2W13FIQqaHhJ5Pg/640?wx_fmt=gif&from=appmsg "")  
  
**组件介绍**  
  
kkFileView是基于Spring Boot开发的一款开源文档在线预览项目，支持主流文档格式预览。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wib564mgPghr7q4WBViaxsX8ohhW780Oa6J23atvmSVLEk6JQTTpnrIUK1hCtyS2W13FIQqaHhJ5Pg/640?wx_fmt=gif&from=appmsg "")  
  
**漏洞简介**  
  
2024年4月18日，深瞳漏洞实验室监测到一则kkFileView组件存在任意文件上传漏洞的信息，漏洞威胁等级：高危。  
  
该漏洞是由于kkFileView组件v4.2.0及以上版本中解压缩功能存在缺陷导致，**攻击者可利用该漏洞在未授权的情况下，通过演示页面上传恶意构造的压缩包，可以实现覆盖系统文件，最终获取服务器权限。**  
  
  
**影响范围**  
  
目前受影响的kkFileView版本：  
  
4.2.0 ≤ kkFileView ≤ v4.4.0-beta  
  
  
**漏洞验证**  
  
  
  
搭建kkFileView组件环境，复现该漏洞，效果如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5wib564mgPghr7q4WBViaxsX87gWhlbc1I6TpGzqY5EOh4JzfVoBNYlRT2nroEo66OskTU9S0Z0VZHg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wib564mgPghr7q4WBViaxsX8ohhW780Oa6J23atvmSVLEk6JQTTpnrIUK1hCtyS2W13FIQqaHhJ5Pg/640?wx_fmt=gif&from=appmsg "")  
  
**如何检测组件系统版本**  
  
  
访问kkFileView系统，点击“版本发布记录”即可查看当前系统版本：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5wib564mgPghr7q4WBViaxsX8ibIawoichUucChBiagW9LGYImnqvficDygeROz6k1LLrib1giagFNLhtbWAw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wib564mgPghr7q4WBViaxsX8ohhW780Oa6J23atvmSVLEk6JQTTpnrIUK1hCtyS2W13FIQqaHhJ5Pg/640?wx_fmt=gif&from=appmsg "")  
  
**官方修复建议**  
  
  
当前官方已发布最新版本，建议受影响的用户及时更新升级到最新版本。链接如下：  
  
https://github.com/kekingcn/kkFileView  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/w8NHw6tcQ5wib564mgPghr7q4WBViaxsX8ohhW780Oa6J23atvmSVLEk6JQTTpnrIUK1hCtyS2W13FIQqaHhJ5Pg/640?wx_fmt=gif&from=appmsg "")  
  
**深信服解决方案**  
  
****  
**1.风险资产发现**  
  
支持对kkFileView的主动检测，可**批量检出**业务场景中该事件的**受影响资产**情况，相关产品如下：  
  
**【深信服云镜YJ】**已发布资产检测方案。  
  
  
**2.漏洞主动检测**  
  
支持对kkFileView任意文件上传漏洞的主动检测，可**批量快速检出**业务场景中是否存在**漏洞风险**，相关产品如下：  
  
**【深信服云镜YJ】**预计2024年04月21日发布检测方案。  
  
**【深信服漏洞评估工具TSS】**预计2024年04月22日发布检测方案。  
  
**【深信服安全托管服务MSS】**预计2024年04月22日发布检测方案，（需要具备**TSS或CWPP**组件能力）。  
  
**【深信服安全检测与响应平台XDR】**预计2024年04月21日发布检测方案,（需要具备**云镜或CWPP**组件能力）。  
  
  
**3.漏洞安全监测**  
  
支持对kkFileView任意文件上传漏洞的监测，可依据流量收集**实时监控**业务场景中的**受影响资产情况，快速检查受影响范围**，相关产品及服务如下：  
  
**【深信服安全感知管理平台SIP】**预计2024年05月07日发布检测方案。  
  
**【深信服安全托管服务MSS】**预计2024年05月07日发布检测方案，（需要具备**SIP**组件能力）。  
  
**【深信服安全检测与响应平台XDR】**预计2024年05月07日发布检测方案。  
  
  
**4.漏洞安全防护**  
  
支持对kkFileView任意文件上传漏洞的防御，**可阻断攻击者针对该事件的入侵行为**，相关产品及服务如下：  
  
**【深信服下一代防火墙AF】**预计2024年05月07日发布防护方案。  
  
**【深信服Web应用防火墙WAF】**预计2024年05月07日发布防护方案。  
  
**【深信服安全托管服务MSS】**预计2024年05月07日发布防护方案，（需要具备**AF**组件能力）。  
  
**【深信服安全检测与响应平台XDR】**预计2024年05月07日发布防护方案，（需要具备**AF**组件能力）。  
  
  
  
**参考链接**  
  
  
https://github.com/kekingcn/kkFileView/commit/421a2760d58ccaba4426b5e104938ca06cc49778  
  
  
**时间轴**  
  
  
  
**2024/4/18**  
  
深瞳漏洞实验室监测到kkFileView组件存在任意文件上传漏洞的信息。  
  
  
**2024/4/18**  
  
深瞳漏洞实验室发布漏洞通告。  
  
  
点击**阅读原文**，及时关注并登录深信服**智安全平台**，可轻松查询漏洞相关解决方案。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/w8NHw6tcQ5wib564mgPghr7q4WBViaxsX8sfcgCJqDia8FJq2hR8EUDoXqWP8NfyS045FeCjrEEbbd84lKS5nzbibw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/w8NHw6tcQ5wib564mgPghr7q4WBViaxsX8sktnTL6wwlh3rpHqjDEqemgbnpQfooh5RzsUbq41t7haRuwXJJ00nw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
