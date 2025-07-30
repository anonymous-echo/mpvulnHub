#  漏洞通告 | llama_Index SQL注入漏洞   
原创 微步情报局  微步在线研究响应中心   2025-06-03 08:49  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMKNkm4Pg1Ed6nv0proxQLEKJ2CUCIficfAwKfClJ84puialc9eER0oaibMn1FDUpibeK1t1YvgZcLYl3A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**漏洞概况**  
  
  
  
llama_Index是一个用于构建基于数据的LLM驱动代理的领先框架。  
  
微步情报局获取到llama_Index SQL注入漏洞（CVE-2025-1750）。该漏洞由于llama_Index的DuckDBVectorStore组件中的ref_doc_id参数直接执行攻击者传递的恶意SQL语句，导致任意文件读取和写入漏洞。  
  
该漏洞利用难度低，且技术细节已公开，建议受影响用户尽快修复。  
  
  
**漏洞处置优先级(VPT)**  
  
  
  
**综合处置优先级：高**  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 31.0667px;visibility: visible;"><td rowspan="3" data-colwidth="110" width="110" style="-webkit-tap-highlight-color:transparent;margin:0px;padding:0px 7.2px;outline:0px;overflow-wrap:break-word !important;word-break:break-all;hyphens:auto;border:0.666667px solid rgb(191, 191, 191);max-width:100%;box-sizing:border-box !important;vertical-align:top;visibility:visible;border-color:#888888;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span leaf="">基本信息</span></strong></span><o:p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"></o:p></p></td><td data-colwidth="188" width="158.33333333333334" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#888888;vertical-align:top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">微步编号</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="88" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#888888;vertical-align:top;"><section><span leaf="" style="color:rgb(84, 84, 84);font-size:14px;">XVE-2025-6427</span></section></td></tr><tr><td data-colwidth="188" style="border-color:#888888;"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">CVE编号</span></span></section></td><td data-colwidth="229" style="border-color:#888888;"><section><span leaf="" style="color:rgb(84, 84, 84);font-size:14px;" data-pm-slice="1 1 [&#34;table&#34;,{&#34;interlaced&#34;:null,&#34;align&#34;:null,&#34;class&#34;:null,&#34;style&#34;:&#34;-webkit-tap-highlight-color:transparent;margin:0px 0px 10px;padding:0px;outline:0px;border-collapse:collapse;display:table;width:527px;max-width:100%;box-sizing:border-box !important;overflow-wrap:break-word !important;color:rgba(0, 0, 0, 0.9);font-family:\&#34;PingFang SC\&#34;, system-ui, -apple-system, BlinkMacSystemFont, \&#34;Helvetica Neue\&#34;, \&#34;Hiragino Sans GB\&#34;, \&#34;Microsoft YaHei UI\&#34;, \&#34;Microsoft YaHei\&#34;, Arial, sans-serif;font-size:17px;font-style:normal;font-variant-ligatures:normal;font-variant-caps:normal;font-weight:400;letter-spacing:0.544px;orphans:2;text-align:justify;text-transform:none;widows:2;word-spacing:0px;-webkit-text-stroke-width:0px;white-space:normal;background-color:rgb(255, 255, 255);text-decoration-thickness:initial;text-decoration-style:initial;text-decoration-color:initial;visibility:visible&#34;},&#34;table_body&#34;,null,&#34;table_row&#34;,{&#34;class&#34;:null,&#34;style&#34;:&#34;-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 31.0667px;visibility: visible;&#34;},&#34;table_cell&#34;,{&#34;colspan&#34;:1,&#34;rowspan&#34;:1,&#34;colwidth&#34;:[229],&#34;width&#34;:&#34;88&#34;,&#34;valign&#34;:null,&#34;align&#34;:null,&#34;style&#34;:&#34;padding: 0px 7.2px;outline: 0px;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;&#34;},&#34;para&#34;,{&#34;tagName&#34;:&#34;section&#34;,&#34;attributes&#34;:{},&#34;namespaceURI&#34;:&#34;&#34;}]">CVE-2025-1750</span></section></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px 7.2px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 31.0667px;"><td data-colwidth="188" style="border-color:#888888;"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">漏洞类型</span></span></section></td><td data-colwidth="229" style="border-color:#888888;"><section><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">SQL注入</span></span></section></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 31.0667px;"><td rowspan="5" data-colwidth="110" width="135" style="-webkit-tap-highlight-color:transparent;margin:0px;padding:0px 7.2px;outline:0px;overflow-wrap:break-word !important;word-break:break-all;hyphens:auto;border:0.666667px solid rgb(191, 191, 191);max-width:100%;box-sizing:border-box !important;vertical-align:top;border-color:#888888;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf="">利用条件评估</span></span></strong><o:p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"></o:p></p></td><td data-colwidth="188" width="158.33333333333334" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#888888;vertical-align:top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">利用漏洞的网络条件</span></span><span leaf=""><br/></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="221" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#888888;vertical-align:top;"><span style="color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">远程</span></span></span></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 31.0667px;"><td data-colwidth="188" width="200" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#888888;vertical-align:top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">是否需要绕过安全机制</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="221" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#888888;vertical-align:top;"><span style="font-size: 14px;color: rgb(84, 84, 84);"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">不需要</span></span></span></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 27px;"><td data-colwidth="188" width="200" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#888888;vertical-align:top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">对被攻击系统的要求</span></span><span leaf=""><br/></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="221" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#888888;vertical-align:top;"><span style="font-size: 14px;color: rgb(219, 0, 0);"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">无</span></span></span></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 27px;"><td data-colwidth="188" width="200" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#888888;vertical-align:top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">利用漏洞的权限要求</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="221" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#888888;vertical-align:top;"><span style="color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">无需权限</span></span></span></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 27px;"><td data-colwidth="188" width="200" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#888888;vertical-align:top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">是否需要受害者配合</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="88" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#888888;vertical-align:top;"><span style="font-size: 14px;color: rgb(84, 84, 84);"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">否</span></span></span></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;height: 27.2px;"><td rowspan="2" data-colwidth="110" width="115" style="-webkit-tap-highlight-color:transparent;margin:0px;padding:0px 7.2px;outline:0px;overflow-wrap:break-word !important;word-break:break-all;hyphens:auto;border:0.666667px solid rgb(191, 191, 191);max-width:100%;box-sizing:border-box !important;vertical-align:top;border-color:#888888;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf="">利用情报</span></span></strong><o:p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"></o:p></p></td><td data-colwidth="188" width="158.33333333333334" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#888888;vertical-align:top;"><p style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">POC是否公开</span></span></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="229" width="88" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#888888;vertical-align:top;height:27.2px;"><span style="outline: 0px;color: rgb(84, 84, 84);font-size: 14px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(219, 0, 0);font-weight: normal;">是</span></span></span></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px 7.2px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border-width: 0.666667px;border-color: rgb(191, 191, 191);vertical-align: top;height: 27.2px;"><td data-colwidth="188" width="180" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#888888;vertical-align:top;"><span style="outline: 0px;font-size: 14px;color: rgb(84, 84, 84);"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">已知利用行为</span></span><span leaf=""><br/></span></span></td><td data-colwidth="229" width="222" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#888888;vertical-align:top;height:27px;"><section style="margin-bottom: 0px;"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: normal;">否</span></span></section></td></tr></tbody></table>  
****  
**漏洞影响范围**  
  
  
  
<table><tbody><tr style="outline: 0px;height: 33.2px;"><td data-colwidth="148" width="152" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#000000;vertical-align:top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf="">产品名称</span></span></strong><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="398" width="346" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#000000;vertical-align:top;"><span style="color: rgb(84, 84, 84);font-size: 14px;letter-spacing: 1px;"><p data-pm-slice="0 0 []"><span style="mso-spacerun:&#39;yes&#39;;font-family:微软雅黑;font-size:10.5000pt;mso-font-kerning:0.0000pt;"><font face="微软雅黑"><span leaf="">Run-llama</span></font></span><span style="mso-spacerun:&#39;yes&#39;;font-family:微软雅黑;font-size:10.5000pt;mso-font-kerning:0.0000pt;"><span leaf=""> </span></span><span style="mso-spacerun:&#39;yes&#39;;font-family:微软雅黑;font-size:10.5000pt;mso-font-kerning:0.0000pt;"><font face="微软雅黑"><span leaf="">|</span></font></span><span style="mso-spacerun:&#39;yes&#39;;font-family:微软雅黑;font-size:10.5000pt;mso-font-kerning:0.0000pt;"><span leaf=""> </span></span><span style="mso-spacerun:&#39;yes&#39;;font-family:微软雅黑;font-size:10.5000pt;mso-font-kerning:0.0000pt;"><font face="微软雅黑"><span leaf="">Llama_index</span></font></span></p></span></td></tr><tr style="outline: 0px;height: 27px;"><td data-colwidth="148" width="172" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#000000;vertical-align:top;"><p style="outline: 0px;"><strong style="outline: 0px;"><span style="outline: 0px;color: rgb(84, 84, 84);letter-spacing: 1px;font-size: 14px;"><span leaf="">受影响版本</span></span></strong><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="398" width="346" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#000000;vertical-align:top;"><p><span leaf=""><br/></span></p><section><span leaf="" style=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);">version&lt;=0.12.19受影响</span></span></section><span style="font-size: var(--articleFontsize);letter-spacing: 0.034em;"></span><p><span leaf=""><br/></span></p></td></tr><tr style="outline: 0px;height: 27px;"><td data-colwidth="148" width="172" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#000000;vertical-align:top;"><p data-pm-slice="0 0 []"><span style=""><font face="微软雅黑"><span leaf=""><span textstyle="" style="font-size: 14px;color: rgb(84, 84, 84);font-weight: bold;">有无修复补丁</span></span></font></span><o:p style="outline: 0px;"></o:p></p></td><td data-colwidth="398" width="346" style="padding:0px 7.2px;outline:0px;word-break:break-all;hyphens:auto;border-width:0.666667px;border-color:#000000;vertical-align:top;"><span style="letter-spacing: 0.578px;font-size: 14px;color: rgb(84, 84, 84);"><span leaf="">有</span></span></td></tr></tbody></table>  
  
**漏洞复现**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMIvb7u7qKmYxaKWB5ITACoNEyx2bibrEOcrdJOaAmgYT4vbyDBxwt0eoGFTACSib2gffrvfjxOxdFSw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMIvb7u7qKmYxaKWB5ITACoN09icEibMC7otdX5nhGXBqDGTz7fEvIDfnFqnafPITKk5ibZB5o8XZNqIQ/640?wx_fmt=png&from=appmsg "")  
  
  
**修复方案**  
  
  
  
  
**官方修复方案：**  
  
llama_index  
官方已发布修复补丁，请尽快更新至不受影响版本：  
  
https://github.com/run-llama/llama_index/releases/tag/v0.12.40  
  
## 临时缓解措施：  
- 输入验证：对ref_doc_id 参数进行严格的输入验证，确保其不包含任何可能导致 SQL 注入的字符  
。  
  
- 参数化查询：使用参数化查询来执行SQL 语句，避免直接将用户输入拼接到 SQL 查询中  
。  
  
**微步产品侧支持情况**  
  
  
  
微步  
威胁感知平台TDP 已支持检测，  
tdp规则id：S3100160396，  
模型/规则高于220250603000000可检出  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fFyp1gWjicMIvb7u7qKmYxaKWB5ITACoNugja4icSvuExHIAL8JxR5rBQJq4HAXFLdibibQcuia7n7Np6XTWOnMlhmw/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
  
  
  
