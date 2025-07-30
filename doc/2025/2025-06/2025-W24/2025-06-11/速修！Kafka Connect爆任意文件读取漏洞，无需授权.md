#  速修！Kafka Connect爆任意文件读取漏洞，无需授权  
原创 微步情报局  微步在线研究响应中心   2025-06-10 02:20  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKNkm4Pg1Ed6nv0proxQLEKJ2CUCIficfAwKfClJ84puialc9eER0oaibMn1FDUpibeK1t1YvgZcLYl3A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**漏洞概况**  
  
  
  
Apache Kafka Connect是Apache Kafka生态系统中的一个组件，它提供了一种可靠且可扩展的方式来连接Kafka与其他系统。  
  
微步情报局通过X漏洞奖励计划获取到Apache Kafka Connect任意文件读取漏洞（https://x.threatbook.com/v5/vul/XVE-2024-28168），攻击者可在未授权的情况下，通过该漏洞读取系统敏感文件，利用难度较低。另外，由于Apache Druid 使用了受影响的Kafka版本，也受该漏洞影响。Kafka官方已修复该漏洞，建议受影响的客户尽快修复。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMJAGnGMY6libdLENlD3kdoibFN3FoaXJI0c5LQVNa4KWnicvsKJgXMYRmpEbiaAibMztMDTibx7Qs5VGT1A/640?wx_fmt=png&from=appmsg "")  
  
  
**漏洞处置优先级(VPT)**  
  
  
  
**综合处置优先级：高**  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 31.0667px;visibility: visible;"><td rowspan="5" data-colwidth="110" width="110" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px 7.2px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0.666667px solid rgb(191, 191, 191);max-width: 100%;box-sizing: border-box !important;vertical-align: top;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span leaf="">基本信息</span></strong></span><o:p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"></o:p></p></td><td data-colwidth="188" width="158.33333333333334" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">微步编号</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="88" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);" data-pm-slice="2 2 [&#34;table&#34;,{&#34;interlaced&#34;:null,&#34;align&#34;:null,&#34;class&#34;:null,&#34;style&#34;:&#34;width:557px;&#34;},&#34;table_body&#34;,null,&#34;table_row&#34;,{&#34;class&#34;:null,&#34;style&#34;:&#34;outline: 0px;height: 31.0667px;&#34;},&#34;table_cell&#34;,{&#34;colspan&#34;:1,&#34;rowspan&#34;:1,&#34;colwidth&#34;:[261],&#34;width&#34;:&#34;88&#34;,&#34;valign&#34;:null,&#34;align&#34;:null,&#34;style&#34;:&#34;padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;&#34;},&#34;para&#34;,{&#34;tagName&#34;:&#34;p&#34;,&#34;attributes&#34;:{},&#34;namespaceURI&#34;:&#34;http://www.w3.org/1999/xhtml&#34;}]"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">XVE-</span></span><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">2024-</span></span><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">28168</span></span></span></td></tr><tr><td data-colwidth="188"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">CVE编号</span></span></section></td><td data-colwidth="229"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">C</span></span><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">VE-2025-27817</span></span></section></td></tr><tr><td data-colwidth="188"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);">C</span></span><span style="color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 0.544px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);">NNVD编号</span></span></span></section></td><td data-colwidth="229"><p><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);">CNNVD-2024-30029666</span></span></p></td></tr><tr><td data-colwidth="188"><p data-pm-slice="0 0 []"><span style="mso-spacerun:&#39;yes&#39;;font-family:微软雅黑;font-size:10.5000pt;mso-font-kerning:0.0000pt;"><font face="微软雅黑"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);">NVDB编号</span></span></font></span></p></td><td data-colwidth="229"><p data-pm-slice="0 0 []"><span style="mso-spacerun:&#39;yes&#39;;font-family:微软雅黑;font-size:10.5000pt;"><font face="微软雅黑"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);">NVDB-CNVDB-2024409929</span></span></font></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px 7.2px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 31.0667px;"><td data-colwidth="188"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">漏洞类型</span></span></section></td><td data-colwidth="229"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);">文件读取</span></span></section></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 31.0667px;"><td rowspan="5" data-colwidth="110" width="135" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px 7.2px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0.666667px solid rgb(191, 191, 191);max-width: 100%;box-sizing: border-box !important;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf="">利用条件评估</span></span></strong><o:p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"></o:p></p></td><td data-colwidth="188" width="158.33333333333334" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">利用漏洞的网络条件</span></span><span leaf=""><br/></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="221" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">远程</span></span></span></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 31.0667px;"><td data-colwidth="188" width="200" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">是否需要绕过安全机制</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="221" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">不需要</span></span></span></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 27px;"><td data-colwidth="188" width="200" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">对被攻击系统的要求</span></span><span leaf=""><br/></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="221" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);">默认配置</span></span></section></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 27px;"><td data-colwidth="188" width="200" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">利用漏洞的权限要求</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="221" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">无需权限</span></span></span></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 27px;"><td data-colwidth="188" width="200" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">是否需要受害者配合</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="88" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">否</span></span></span></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 27.2px;"><td rowspan="2" data-colwidth="110" width="115" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px 7.2px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0.666667px solid rgb(191, 191, 191);max-width: 100%;box-sizing: border-box !important;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf="">利用情报</span></span></strong><o:p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"></o:p></p></td><td data-colwidth="188" width="158.33333333333334" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">POC是否公开</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="88" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 27.2px;"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);">否</span></span></section></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px 7.2px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 27.2px;"><td data-colwidth="188" width="180" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="outline: 0px;font-size: 14px;color: rgb(84, 84, 84);"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">已知利用行为</span></span><span leaf=""><br/></span></span></td><td data-colwidth="229" width="222" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 27px;"><section style="margin-bottom: 0px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">否</span></span></section></td></tr></tbody></table>  
****  
**漏洞影响范围**  
  
  
  
<table><tbody><tr style="outline: 0px;height: 33.2px;"><td data-colwidth="148" width="152" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf="">产品名称</span></span></strong><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="398" width="346" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);">Apache软件基金会 | Apache Kafka</span></span></p></td></tr><tr style="outline: 0px;height: 27px;"><td data-colwidth="148" width="172" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf="">受影响版本</span></span></strong><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="398" width="346" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);">3.1.0 ≤ version &lt; 3.9.1</span></span></p></td></tr><tr style="outline: 0px;height: 27px;"><td data-colwidth="148" width="172" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p data-pm-slice="0 0 []"><span style=""><font face="微软雅黑"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: bold;">有无修复补丁</span></span></font></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="398" width="346" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="letter-spacing: 0.578px;font-size: 14px;color: rgb(84, 84, 84);"><span leaf="">有</span></span></td></tr></tbody></table>  
  
**漏洞复现**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMJAGnGMY6libdLENlD3kdoibFXlO5Ds40l39AVB4lLw3on4GfhzvukZJ7GzWwgve89fqDiaqwdZ4icx6A/640?wx_fmt=png&from=appmsg "")  
  
  
**修复方案**  
  
  
  
  
**官方修复方案：**  
  
Kafka官方已发布修复版本，请尽快更新至3.9.1及以上版本：  
- 通告链接：https://lists.apache.org/thread/6cm2d0q5126lp7w591wt19211s5xxcsm  
  
- 下载链接：https://github.com/apache/kafka/releases/tag/3.9.1  
  
## 临时缓解措施：  
  
1. 避免将Kafka Connect实例对外网开放，配置方式如下：  
- 若使用standalone模式启动Kafka Connect，则可通过修改connect-standalone.properties配置文件中的listeners或rest.host.name字段进行配置；  
  
- 若使用distributed模式启动Kafka Connect，则可通过修改connect-distributed.properties配置文件中的listeners或rest.host.name字段进行配置。  
  
2. 使用流量防护设备，对/connectors的  
请求体中含有敏感文件路径的访问请求  
进行拦截。  
  
  
**微步产品侧支持情况**  
  
  
  
微步  
威胁感知平台TDP   
已支持检测，  
TDP检测ID：  
S3100154573、S3100154580  
，模型/规则高于  
   
20241009000000 可检出。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMJAGnGMY6libdLENlD3kdoibFUf7C57zjIcUhwk87pvRneUG3aouA8sJWrH9FA3H8ibDFA4eURs6LyaA/640?wx_fmt=png&from=appmsg "")  
  
微步威胁防御系统OneSIG已支持防护，规则ID为：3100150726。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMJAGnGMY6libdLENlD3kdoibF8sDnPFunoYF0IegXOMPVw7HpcDdz4Ak8kHea8qjslCmIBWu8TyibgtQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
- END -  
  
  
  //    
  
**微步漏洞情报订阅服务**  
  
  
微步提供漏洞情报订阅服务，精准、高效助力企业漏洞运营：  
- 提供高价值漏洞情报，具备及时、准确、全面和可操作性，帮助企业高效应对漏洞应急与日常运营难题；  
  
- 可实现对高威胁漏洞提前掌握，以最快的效率解决信息差问题，缩短漏洞运营MTTR；  
  
- 提供漏洞完整的技术细节，更贴近用户漏洞处置的落地；  
  
- 将漏洞与威胁事件库、APT组织和黑产团伙攻击大数据、网络空间测绘等结合，对漏洞的实际风险进行持续动态更新  
。  
  
  
扫码在线沟通  
  
↓  
↓↓  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hQl5bZ5Mx6PTAQg6tGLiciarvXajTdDnQiacxmwJFZ0D3ictBOmuYyRk99bibwZV49wbap77LibGQHdQPtA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Yv6ic9zgr5hTIdM9koHZFkrtYe5WU5rHxSDicbiaNFjEBAs1rojKGviaJGjOGd9KwKzN4aSpnNZDA5UWpY2E0JAnNg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
[点此电话咨询]()  
  
  
  
  
**X漏洞奖励计划**  
  
  
“X漏洞奖励计划”是微步X情报社区推出的一款  
针对未公开  
漏洞的奖励计划，我们鼓励白帽子提交挖掘到的0day漏洞，并给予白帽子可观的奖励。我们期望通过该计划与白帽子共同努力，提升0day防御能力，守护数字世界安全。  
  
活动详情：  
https://x.threatbook.com/v5/vulReward  
  
  
  
  
