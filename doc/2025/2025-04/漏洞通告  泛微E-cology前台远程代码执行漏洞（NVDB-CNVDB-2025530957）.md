#  漏洞通告 | 泛微E-cology前台远程代码执行漏洞（NVDB-CNVDB-2025530957）   
原创 微步情报局  微步在线研究响应中心   2025-04-22 08:59  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKNkm4Pg1Ed6nv0proxQLEKJ2CUCIficfAwKfClJ84puialc9eER0oaibMn1FDUpibeK1t1YvgZcLYl3A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**漏洞概况**  
  
  
  
泛微E-cology是一款企业级协同办公自动化系统，主要为中大型企业提供全面的信息化解决方案。它以智能化、平台化和全程数字化为特点，旨在提升组织的协同办公效率和管理水平。  
  
近日，微步情报局通过X漏洞奖励计划获取到泛微E-cology远程代码执行漏洞情报（https://x.threatbook.com/v5/vul/XVE-2025-10090），该漏洞由于将用户可控的参数拼接SQL语句，且该接口经过DES加密传输，导致全局WAF失效，造成SQL注入漏洞。攻击者可利用该漏洞向数据库中写入数据，并利用Ole组件导出为Webshell，实现远程代码执行，进而获取服务器权限。  
  
该漏洞可绕过身份认证、利用方式简单、且具备规模化利用的条件。泛微官方已于4月10日的发布10.74版本修复该漏洞，建议受影响用户  
尽快修复  
。  
  
  
**漏洞处置优先级(VPT)**  
  
  
  
**综合处置优先级：高**  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 31.0667px;visibility: visible;"><td rowspan="3" data-colwidth="110" width="110" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px 7.2px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0.666667px solid rgb(191, 191, 191);max-width: 100%;box-sizing: border-box !important;vertical-align: top;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span leaf="">基本信息</span></strong></span><o:p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"></o:p></p></td><td data-colwidth="188" width="158.33333333333334" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">微步编号</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="88" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);" data-pm-slice="2 2 [&#34;table&#34;,{&#34;interlaced&#34;:null,&#34;align&#34;:null,&#34;class&#34;:null,&#34;style&#34;:&#34;width:557px;&#34;},&#34;table_body&#34;,null,&#34;table_row&#34;,{&#34;class&#34;:null,&#34;style&#34;:&#34;outline: 0px;height: 31.0667px;&#34;},&#34;table_cell&#34;,{&#34;colspan&#34;:1,&#34;rowspan&#34;:1,&#34;colwidth&#34;:[261],&#34;width&#34;:&#34;88&#34;,&#34;valign&#34;:null,&#34;align&#34;:null,&#34;style&#34;:&#34;padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;&#34;},&#34;para&#34;,{&#34;tagName&#34;:&#34;p&#34;,&#34;attributes&#34;:{},&#34;namespaceURI&#34;:&#34;http://www.w3.org/1999/xhtml&#34;}]"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">XVE-</span></span><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">2025-10090</span></span></span></td></tr><tr><td data-colwidth="188"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">NVDB编号</span></span></section></td><td data-colwidth="229"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">NVDB-CNVDB-2025530957</span></span></section></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px 7.2px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 31.0667px;"><td data-colwidth="188"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">漏洞类型</span></span></section></td><td data-colwidth="229"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">SQL注入、远程代码执行</span></span></section></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 31.0667px;"><td rowspan="5" data-colwidth="110" width="135" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px 7.2px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0.666667px solid rgb(191, 191, 191);max-width: 100%;box-sizing: border-box !important;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf="">利用条件评估</span></span></strong><o:p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"></o:p></p></td><td data-colwidth="188" width="158.33333333333334" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">利用漏洞的网络条件</span></span><span leaf=""><br/></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="221" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">远程</span></span></span></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 31.0667px;"><td data-colwidth="188" width="200" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">是否需要绕过安全机制</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="221" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">不需要</span></span></span></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 27px;"><td data-colwidth="188" width="200" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">对被攻击系统的要求</span></span><span leaf=""><br/></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="221" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(219, 0, 0);"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">默认配置</span></span></span></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 27px;"><td data-colwidth="188" width="200" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">利用漏洞的权限要求</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="221" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">无需权限</span></span></span></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 27px;"><td data-colwidth="188" width="200" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">是否需要受害者配合</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="88" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="font-size: 14px;color: rgb(84, 84, 84);"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">否</span></span></span></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 27.2px;"><td rowspan="2" data-colwidth="110" width="115" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px 7.2px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0.666667px solid rgb(191, 191, 191);max-width: 100%;box-sizing: border-box !important;vertical-align: top;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf="">利用情报</span></span></strong><o:p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"></o:p></p></td><td data-colwidth="188" width="158.33333333333334" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">POC是否公开</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="88" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 27.2px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">否</span></span></span></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px 7.2px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 27.2px;"><td data-colwidth="188" width="180" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="outline: 0px;font-size: 14px;color: rgb(84, 84, 84);"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">已知利用行为</span></span><span leaf=""><br/></span></span></td><td data-colwidth="229" width="222" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 27px;"><section style="margin-bottom: 0px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">否</span></span></section></td></tr></tbody></table>  
****  
**漏洞影响范围**  
  
  
  
<table><tbody><tr style="outline: 0px;height: 33.2px;"><td data-colwidth="148" width="152" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf="">产品名称</span></span></strong><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="398" width="346" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf="">上海泛微网络科技股份有限公司 - E-cology</span></span></td></tr><tr style="outline: 0px;height: 27px;"><td data-colwidth="148" width="172" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf="">受影响版本</span></span></strong><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="398" width="346" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);">补丁版本 &lt; v10.74</span></span><span style="font-size: var(--articleFontsize);letter-spacing: 0.034em;"></span></p></td></tr><tr style="outline: 0px;height: 27px;"><td data-colwidth="148" width="172" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><p data-pm-slice="0 0 []"><span style=""><font face="微软雅黑"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: bold;">有无修复补丁</span></span></font></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="398" width="346" style="padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;"><span style="letter-spacing: 0.578px;font-size: 14px;color: rgb(84, 84, 84);"><span leaf="">有</span></span></td></tr></tbody></table>  
  
**漏洞复现**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLdNROqPjHD5nmgSZItiacE2FO5FWgHaJIV8sefuNkHdhaCVfF7beJmVAthv1PgHokbjNWyhGVPSyw/640?wx_fmt=png&from=appmsg "")  
  
  
**修复方案**  
  
  
  
  
**官方修复方案：**  
  
泛微官方已发布修复补丁，请尽快更新至v10.74版本：  
  
https://www.weaver.com.cn/cs/securityDownload.html?src=cn  
  
## 临时修复方案：  
- 可配置防护策略，限制访问漏洞相关路径。完整漏洞利用路径请通过微步漏洞情报查询。  
  
- 如非必要，避免将资产暴露在互联网。  
  
**微步产品侧支持情况**  
  
  
  
微步  
威胁感知平台TDP 已支持检测，  
检测ID：S3100159591，模型/规则高于20250415000000可检出。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMLdNROqPjHD5nmgSZItiacE2U8Z9UefCqQ4JZO7MlHEEnp3fl75Ke6R4uCwuQvIcsQ7kGOrndhOSyg/640?wx_fmt=png&from=appmsg "")  
  
  
  
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
  
  
  
  
