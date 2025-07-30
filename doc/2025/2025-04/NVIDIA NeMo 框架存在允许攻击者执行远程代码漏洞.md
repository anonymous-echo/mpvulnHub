#  NVIDIA NeMo 框架存在允许攻击者执行远程代码漏洞   
 网安百色   2025-04-25 11:31  
  
NVIDIA NeMo 框架中存在三个严重性较高的漏洞，可能允许攻击者执行远程代码，从而可能危及 AI 系统并导致数据篡改。  
  
这些安全漏洞被确定为 CVE-2025-23249、CVE-2025-23250 和 CVE-2025-23251，CVSS 基本评分均为 7.6，表明流行的生成式 AI 框架的用户面临重大风险。  
  
NVIDIA 于 2025 年 4 月 22 日发布了安全补丁，敦促用户立即更新，以减少跨 Windows、Linux 和 macOS 平台的潜在漏洞利用。  
## NVIDIA NeMo 框架中的高危漏洞  
  
第一个漏洞 （CVE-2025-23249） 涉及对不受信任数据的不安全反序列化，这可能允许攻击者远程执行任意代码。  
  
此缺陷被归类为 CWE-502，使攻击者能够在数据处理周期内纵序列化对象并注入恶意代码。  
  
“NVIDIA NeMo 框架包含一个漏洞，用户可以通过远程代码执行来反序列化不受信任的数据。成功利用此漏洞可能会导致代码执行和数据篡改，“官方安全公告指出。  
  
第二个漏洞 （CVE-2025-23250） 源于不正确的路径验证 （CWE-22），可能使攻击者能够通过利用路径遍历技术来执行任意文件写入。  
  
安全研究人员指出，此漏洞可能允许攻击者覆盖敏感文件或引入恶意配置，从而可能劫持训练管道或毒害 AI 工作流中的数据集。  
  
第三个漏洞 （CVE-2025-23251） 与代码生成控制不当 （CWE-94） 有关，可被利用进行远程代码执行。  
  
这对于专为生成式 AI 应用程序设计的框架尤其令人担忧，因为它直接影响受信任和不受信任的代码执行环境之间的边界。  
  
<table><tbody><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><strong msttexthash="7544134" msthash="72" style="box-sizing: border-box;font-weight: bold;"><span leaf="">CVE 证书</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><strong msttexthash="17242355" msthash="73" style="box-sizing: border-box;font-weight: bold;"><span leaf="">受影响的产品</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><strong msttexthash="4085822" msthash="74" style="box-sizing: border-box;font-weight: bold;"><span leaf="">冲击</span></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><strong msttexthash="17124536" msthash="75" style="box-sizing: border-box;font-weight: bold;"><span leaf="">利用先决条件</span></strong><strong style="box-sizing: border-box;font-weight: bold;"></strong></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><strong msttexthash="8943688" msthash="76" style="box-sizing: border-box;font-weight: bold;"><span leaf="">CVSS 3.1 分数</span></strong></td></tr><tr style="box-sizing: border-box;"><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section><span leaf="">CVE-2025-23249、CVE-2025-23250、</span><span leaf=""><br/></span><span leaf="">CVE-2025-23251</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section><span leaf="">NVIDIA NeMo 框架（Windows、Linux、macOS;25.02 之前的所有版本）</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section><span leaf="">代码执行、数据篡改</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section><span leaf="">远程攻击者，需要用户交互</span></section></td><td style="box-sizing: border-box;padding: 2px 8px;border: 1px solid;word-break: break-word;"><section><span leaf="">7.6 （高）</span></section></td></tr></tbody></table>  
所有三个漏洞都具有相同的攻击媒介规范 （AV：N/AC：L/PR：N/UI：R/S：U/C：L/I：H/A：L），这表明它们可以被远程利用，攻击复杂度低，不需要权限，但需要用户交互。  
  
NeMo 框架是一个可扩展的云原生生成式 AI 平台，被使用多语言模型 （LLM）、多模态模型和各种 AI 应用程序（包括语音识别和计算机视觉）的研究人员和开发人员广泛使用。  
  
该公司已发布版本 25.02 来解决这些问题，并强烈建议立即更新所有受影响的系统。  
  
安全专家建议使用 NeMo Framework 的组织：  
- 立即更新到版本 25.02  
  
- 审查可能已受损的任何 AI 系统  
  
- 围绕 AI 开发管道实施额外的安全控制  
  
- 监控系统是否存在可能表明漏洞利用的异常活动  
  
**免责声明**  
：  
  
本公众号所载文章为本公众号原创或根据网络搜索下载编辑整理，文章版权归原作者所有，仅供读者学习、参考，禁止用于商业用途。因转载众多，无法找到真正来源，如标错来源，或对于文中所使用的图片、文字、链接中所包含的软件/资料等，如有侵权，请跟我们联系删除，谢谢！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/1QIbxKfhZo5lNbibXUkeIxDGJmD2Md5vKicbNtIkdNvibicL87FjAOqGicuxcgBuRjjolLcGDOnfhMdykXibWuH6DV1g/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
