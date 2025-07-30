#  Spring Data MongoDBSpEL表达式注入漏洞安全风险通告   
原创 QAX CERT  奇安信 CERT   2022-06-21 14:36  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4icrhoWdKnhTgicSjB9pXdeZwDibNIBAEMegibEdG1vrjOibsq887TUz3ztMkM6Qvibic7r26sqbUIbicOMYg/640?wx_fmt=png "https://image.ipaiban.com/upload-ueditor-image-20201112-1605175807303084927.png")  
  
奇安信CERT  
  
**致力于**  
第一时间  
为企业级用户提供安全风险  
**通告**  
和  
**有效**  
解决方案。  
  
  
**安全通告**  
  
  
  
近日，奇安信CERT监测到**Spring Data MongoDB SpEL表达式注入漏洞(CVE-2022-22980)**，当使用@Query或@Aggregation注解进行查询时，若通过SpEL表达式中形如“?0”的占位符来进行参数赋值，同时应用程序未对用户输入进行过滤处理，则可能受到SpEL表达式注入的影响，成功利用该漏洞的攻击者可在目标服务器上执行代码。**鉴于漏洞影响范围较大，建议客户尽快做好自查及防护。**  
  
****  
<table><tbody><tr><td style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" width="70"><p><strong><span style="font-size: 14px;">漏洞名称</span></strong></p></td><td colspan="3" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;">Spring Data MongoDB SpEL表达式注入漏洞</span></p></td></tr><tr><td style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" width="91"><p draggable="true"><strong><span style="font-size: 14px;">公开时间</span></strong></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="209"><p><span style="font-size: 14px;">2022-06-20</span></p></td><td style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" width="163"><p><strong><span style="font-size: 14px;">更新时间</span></strong></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="241"><p><span style="font-size: 14px;">2022-06-21</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="110"><p><strong><span style="font-size: 14px;">CVE编号</span></strong></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="218"><p><span style="font-size: 14px;">CVE-2022-22980</span></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="173"><p><strong><span style="font-size: 14px;">其他编号</span></strong></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="243"><p><span style="font-size: 14px;">QVD-2022-9645</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="122"><p><strong><span style="font-size: 14px;">威胁类型</span></strong></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="218"><p><span style="font-size: 14px;">代码执行</span></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="177"><p><strong><span style="font-size: 14px;">技术类型</span></strong></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="239"><p><span style="font-size: 14px;">SpEL表达式注入</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="131"><p><strong><span style="font-size: 14px;">厂商</span></strong></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="214"><p><span style="font-size: 14px;">VMware</span></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="178"><p><strong><span style="font-size: 14px;">产品</span></strong></p></td><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="236"><p><span style="font-size: 14px;">Spring Data   MongoDB</span></p></td></tr><tr><td colspan="4" style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" align="center" valign="middle"><p><strong><span style="font-size: 14px;">风险等级</span></strong></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><strong><span style="font-size: 14px;">奇安信CERT风险评级</span></strong></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><strong><span style="font-size: 14px;">风险等级</span></strong></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;word-break: break-all;border-color: rgb(221, 221, 221);"><p><span style="color: rgb(255, 0, 0);"><span style="color: rgb(255, 0, 0);font-size: 14px;">高危</span></span></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;word-break: break-all;border-color: rgb(221, 221, 221);"><p><span style="color: rgb(12, 118, 240);"><span style="color: rgb(12, 118, 240);font-size: 14px;">蓝色（一般事件）</span></span></p></td></tr><tr><td colspan="4" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><strong><span style="font-size: 14px;">现时威胁状态</span></strong></p></td></tr><tr><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="138"><p><strong><span style="font-size: 14px;">POC状态</span></strong></p></td><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="212"><p><strong><span style="font-size: 14px;">EXP状态</span></strong></p></td><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="178"><p><strong><span style="font-size: 14px;">在野利用状态</span></strong></p></td><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="234"><p><strong><span style="font-size: 14px;">技术细节状态</span></strong></p></td></tr><tr><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="143"><p><span style="font-size: 14px;">未发现</span></p></td><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="211"><p><span style="font-size: 14px;">未发现</span></p></td><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="177"><p><span style="font-size: 14px;">未发现</span></p></td><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="233"><p><span style="font-size: 14px;">未发现</span></p></td></tr><tr><td style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" width="146"><p><strong><span style="font-size: 14px;">漏洞描述</span></strong></p></td><td colspan="3" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;">当使用@Query或@Aggregation注解进行查询时，若通过SpEL表达式中形如“?0”的占位符来进行参数赋值，同时应用程序未对用户输入进行过滤处理，则可能受到SpEL表达式注入的影响，成功利用该漏洞的攻击者可在目标服务器上执行代码。</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="149"><p><strong><span style="font-size: 14px;">影响版本</span></strong></p></td><td colspan="3" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;">Spring Data MongoDB == 3.4.0</span></p><p><span style="font-size: 14px;">3.3.0 &lt;= Spring Data MongoDB &lt;= 3.3.4</span></p><p><span style="font-size: 14px;">旧的、不受支持的版本也会受到影响</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="151"><p><strong><span style="font-size: 14px;">不受影响版本</span></strong></p></td><td colspan="3" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;">Spring Data MongoDB   &gt;= 3.4.1</span></p><p><span style="font-size: 14px;">Spring Data MongoDB   &gt;= 3.3.5</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="152"><p><strong><span style="font-size: 14px;">其他受影响组件</span></strong></p></td><td colspan="3" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><span style="font-size: 14px;">使用 Spring Data MongoDB依赖的应用程序</span></p></td></tr></tbody></table>  
  
风险等级  
  
奇安信 CERT风险评级为：  
高危  
  
风险等级：  
蓝色（一般事件）  
  
  
威胁评估  
  
<table><tbody><tr><td style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" width="63"><p><strong><span style="font-size: 14px;">漏洞名称</span></strong></p></td><td colspan="4" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="482"><p><span style="font-size: 14px;">Spring Data MongoDB SpEL表达式注入漏洞</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="53"><p><strong><span style="font-size: 14px;">CVE编号</span></strong></p></td><td style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" align="center" valign="middle" width="101"><p><span style="font-size: 14px;">CVE-2022-22980</span></p></td><td colspan="2" style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" width="234"><p><strong><span style="font-size: 14px;">其他编号</span></strong></p></td><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="95"><p><span style="font-size: 14px;">QVD-2022-9645</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="63"><p><strong><span style="font-size: 14px;">CVSS 3.1评级</span></strong></p></td><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="101"><p><span style="font-size: 14px;">高危</span></p></td><td colspan="2" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="234"><p><strong><span style="font-size: 14px;">CVSS 3.1分数</span></strong></p></td><td align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="95"><p><span style="font-size: 14px;">8.2</span></p></td></tr><tr><td rowspan="8" style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" width="63"><p><strong><span style="font-size: 14px;">CVSS向量</span></strong></p></td><td colspan="2" align="center" valign="middle" style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" width="231"><p><strong><span style="font-size: 14px;">访问途径（AV）</span></strong></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);"><p><strong><span style="font-size: 14px;">攻击复杂度（AC）</span></strong></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="232"><p><span style="font-size: 14px;">网络</span></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="132"><p><span style="font-size: 14px;">高</span></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" width="232"><p><strong><span style="font-size: 14px;">用户认证（Au）</span></strong></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="132"><p><strong><span style="font-size: 14px;">用户交互</span></strong></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="232"><p><span style="font-size: 14px;">无</span></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="132"><p><span style="font-size: 14px;">不需要</span></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" width="232"><p><strong><span style="font-size: 14px;">影响范围</span></strong></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="132"><p><strong><span style="font-size: 14px;">机密性影响（C）</span></strong></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" width="232"><p><span style="font-size: 14px;">不改变</span></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="132"><p><span style="font-size: 14px;">高</span></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="word-break: break-all;padding: 5px 10px;border-color: rgb(221, 221, 221);" width="232"><p><strong><span style="font-size: 14px;">完整性影响（I）</span></strong></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="132"><p><strong><span style="font-size: 14px;">可用性影响（A）</span></strong></p></td></tr><tr><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="232"><p><span style="font-size: 14px;">高</span></p></td><td colspan="2" align="center" valign="middle" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="132"><p><span style="font-size: 14px;">高</span></p></td></tr><tr><td style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="63"><p><strong><span style="font-size: 14px;">危害描述</span></strong></p></td><td colspan="4" style="padding: 5px 10px;border-color: rgb(221, 221, 221);" width="478"><p><span style="font-size: 14px;">当使用@Query或@Aggregation注解进行查询时，若通过SpEL表达式中形如“?0”的占位符来进行参数赋值，同时应用程序未对用户输入进行过滤处理，则可能受到SpEL表达式注入的影响，成功利用该漏洞的攻击者可在目标服务器上执行代码。</span></p></td></tr></tbody></table>  
  
  
处置建议  
  
目前，VMware官方已发布漏洞修复补丁，建议用户尽快下载安装补丁程序或采取缓解措施。  
  
**1.补丁升级**  
  
建议尽快升级至官方修护版本：  
  
Spring Data MongoDB 3.4.1版本：  
  
https://github.com/spring-projects/spring-data-mongodb/releases/tag/3.4.1  
  
Spring Data MongoDB 3.3.5版本：  
  
https://github.com/spring-projects/spring-data-mongodb/releases/tag/3.3.5  
  
  
**2. 缓解措施**  
  
（1）如果您的应用程序需要使用由用户输入控制的SpEL表达式，那么使用数组形式语法“[0]”引入SpEL参数而不是“?0”形式；  
  
（2）实现自定义存储库方法，详见：https://docs.spring.io/spring-data/mongodb/docs/current/reference/html/#repositories.single-repository-behavior；  
  
（3）通过BeanPostProcessor和受限的QueryMethodEvaluationContextProvider重新配置存储工厂bean；  
  
（4）在调用查询方法时过滤用户输入内容。  
  
  
更多修复建议请参考官方发布的安全建议文档：  
  
https://spring.io/blog/2022/06/20/spring-data-mongodb-spel-expression-injection-vulnerability-cve-2022-22980  
  
  
参考资料  
  
[1]https://spring.io/blog/2022/06/20/spring-data-mongodb-spel-expression-injection-vulnerability-cve-2022-22980  
  
  
时间线  
  
2022年6月21日，  
奇安信 CERT发布安全风险通告  
  
  
点击**阅读原文**  
到奇安信NOX-安全监测平台查询更多漏洞详情  
