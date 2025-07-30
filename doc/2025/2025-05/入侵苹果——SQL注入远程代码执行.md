#  入侵苹果——SQL注入远程代码执行   
 Ots安全   2025-05-03 05:48  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
介绍  
  
在上一篇博文中，我们深入研究了 Lucee 的内部工作原理，并查看了 Masa/Mura CMS 的源代码，并意识到其潜在的攻击面之广。显然，花时间理解代码是值得的。经过一周的探索，我们偶然发现了几个可以利用的切入点，包括一个关键的 SQL 注入漏洞，我们可以利用该漏洞在 Apple 的 Book Travel 门户中进行攻击。  
  
在这篇博文中，我们旨在分享我们的见解和经验，详细说明我们如何识别漏洞接收器，将其链接回其源，并利用 SQL 注入实现远程代码执行 (RCE)。  
  
Finding the sink  
通过对 Masa/Mura CMS 的测试，我们了解了我们的攻击面——主要是在 Apple 环境中可访问的攻击面。我们主要关注的是 JSON API，因为它暴露了一些在 Apple 环境中可访问的方法。我们发现的任何潜在漏洞的源头都应该在 JSON API 中。  
  
我们仔细研究了优化方法，以简化源代码审查流程。我们探索了静态分析器或 CFM 解析器的可用性，这些分析器能够遍历代码，同时忽略杀毒程序。  
  
例如，这是通过基于标签的 CFM 编写安全参数化 SQL 查询的方式：  
  
```
<cfquery>select * from table where column=<cfqueryparam cfsqltype="cf_sql_varchar"value="#arguments.user_input#"></cfquery>
```  
  
  
不安全的 SQL 查询的写法如下：  
  
  
```
<cfquery>select * from table where column=#arguments.user_input#</cfquery>
```  
  
  
如果我们能够解析并遍历代码，并且只打印cfquery包含未过滤输入的标签（无论cfqueryparam其中是否包含该标签），那就太好了。我们偶然发现了https://github.com/foundeo/cfmlparser，它可以让我们做到这一点。  
  
以下是我们针对 SQL 注入接收器检测的方法：  
- 解析每个 CFM/CFC 文件。  
  
- 浏览每个语句，如果该语句是标签并且其名称为，则选择该语句cfquery。  
  
- 删除 cfquery 代码块内的所有标签（如 cfqueryparam），如果它仍然arguments在代码块中，则输入未参数化，并且查询容易受到 SQL 注入，因为没有其他验证。  
  
- 打印此查询。  
  
```
<cfscript>    targetDirectory = "../mura-cms/";    files = DirectoryList(targetDirectory, true, "query");    for (file in files) {        if (FindNoCase(".cfc", file.name) or FindNoCase(".cfm", file.name)) {            fname = file.directory & "/" & file.name;            if (file.name != "dbUtility.cfc" && file.name != "configBean.cfc" && !FindNoCase("admin", file.directory) && !FindNoCase("dbUpdates", file.directory)) {                filez = new cfmlparser.File(fname);                statements = filez.getStatements();                info = [];                for (s in statements) {                    if (s.isTag() && s.getName() == "cfquery" && FindNoCase("arguments", s.getStrippedInnerContent(true, true))) {                        WriteOutput("Filename: <b>#fname#</b>");                        WriteOutput("<br><br>" & s.getStrippedInnerContent(true, true));                        WriteOutput("<br><br><br><br>");                    }                }            }        }    }</cfscript>
```  
  
我们开始仔细研究结果，但心里想着几件事，比如忽略 siteid 之类的输入，因为 JSON API 会提前对其进行验证。  
  
其中一个具有另外两个输入的查询是这样的：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taficXvRFfGgK62bXsYicU5edgjPyseibP7aSWtYCFSQIBEMEz4uehVmibxjGbx1cUte8k66HV9VTmPdcA/640?wx_fmt=webp&from=appmsg "")  
  
追踪汇点至源点  
  
查看执行此查询的函数，发现只有一个可利用的参数，即 ContentHistID 。参数 columnid 是数字，并且默认会验证 siteid 。  
  
```
<cffunction name="getObjects" output="false">  <cfargument name="columnID" required="yes" type="numeric" >  <cfargument name="ContentHistID" required="yes" type="string" >  <cfargument name="siteID" required="yes" type="string" >  <cfset var rsObjects=""/>  <cfquery attributeCollection="#variables.configBean.getReadOnlyQRYAttrs(name='rsObjects')#">    select tcontentobjects.object,tcontentobjects.name,tcontentobjects.objectid, tcontentobjects.orderno, tcontentobjects.params, tplugindisplayobjects.configuratorInit from tcontentobjects    inner join tcontent On(    tcontentobjects.contenthistid=tcontent.contenthistid    and tcontentobjects.siteid=tcontent.siteid)    left join tplugindisplayobjects on (tcontentobjects.object='plugin'                      and tcontentobjects.objectID=tplugindisplayobjects.objectID)    where tcontent.siteid='#arguments.siteid#'    and tcontent.contenthistid ='#arguments.contentHistID#'    and tcontentobjects.columnid=#arguments.columnID#    order by tcontentobjects.orderno  </cfquery>  <cfreturn rsObjects></cffunction>
```  
  
  
在 core/mura/content/contentRendererUtility.cfc 组件中的 dspObjects 函数中调用了函数 getObjects 。  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taficXvRFfGgK62bXsYicU5edgI9hwzHK33aEYTkhA4yGnNicUa9iaFTmgVmkkhoH4TiaibyqbLsfPiaYhZWA/640?wx_fmt=webp&from=appmsg "")  
  
调用堆栈是：  
  
JSON API -> processAsyncObject -> 对象案例：displayregion -> dspobjects() -> getobjects()。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taficXvRFfGgK62bXsYicU5edgWujUPISeSNcKiazWNbXPd2G9IfhWeOwPPnZxzToa63szlOJPNvoWRaQ/640?wx_fmt=webp&from=appmsg "")  
  
触发和利用 SQL 注入  
  
默认情况下，Lucee 在输入单引号时，会通过在单引号前添加反斜杠来转义单引号。您可以使用反斜杠来转义其中一个单引号。  
  
这应该会触发 SQL 注入：  
  
```
/_api/json/v1/default/?method=processAsyncObject&object=displayregion&contenthistid=x%5c'
```  
  
  
然而，事实并非如此。重新审视源代码后，我们发现 dspObjects 函数中有一个关键条件。在调用 getObjects 之前，必须满足一个 if 条件：在 Mura servlet 事件处理程序中，必须将 isOnDisplay 属性设置为 true。最初，我们假设事件处理程序上的任何属性都可以通过简单地将属性名称及其值作为参数传递来设置。这一假设基于我们在代码库中的调试会话。  
  
我们尝试以这种方式设置 isOnDisplay 属性，但没有成功。看来代码中的某个地方覆盖了该属性。  
  
在进行一些 grep 搜索之后，我们偶然发现了 JSON API 的 processAsyncObjects 中的 standardSetIsOnDisplayHandler 函数调用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taficXvRFfGgK62bXsYicU5edgDp9pQkz9NYF4rLmrICWoVMUOnhJOrpYreNEwC0CgNk5u1icgIE96ZMw/640?wx_fmt=webp&from=appmsg "")  
  
看起来，只需传递具有任意值的 previewID 参数，我们就可以设置 previewID 属性，进而将 isOnDisplay 属性设置为 true。  
```
/_api/json/v1/default/?method=processAsyncObject&object=displayregion&contenthistid=x%5c'&previewID=x
```  
  
  
并且它有效：  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taficXvRFfGgK62bXsYicU5edgQU4GicXSF5bITGw0K0jOtyopMlpXN96KEMZJE3SRLoQ4ppHJZwF7HQA/640?wx_fmt=webp&from=appmsg "")  
  
由于这是一个基于错误的 SQL 注入，我们可以很容易地利用它来实现远程代码执行 (RCE)。在本地，我们按照以下步骤成功执行了 RCE：  
- 重置管理员用户的密码。  
  
- 通过 SQL 注入获取重置令牌和用户 ID。  
  
- 使用带有泄露信息的密码重置端点。  
  
- 利用插件安装上传 CFM 文件。  
  
然而，在 Apple 的环境中，我们只遇到了一个未处理的异常错误，没有任何与查询相关的信息，这使其成为一次 SQL 盲注。幸运的是，令牌和用户 ID 都是 UUID，因此窃取它们相对简单。我们编写了一些脚本，就完成了这项任务。  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taficXvRFfGgK62bXsYicU5edgFkf6n9GPYDASIA5e46nr0U3JCeJnsTWefTr7eKLQFh5ZCfHrFK9MXQ/640?wx_fmt=webp&from=appmsg "")  
  
我们立即向 Apple 提交了报告，其中包括演示如何登录帐户的概念验证 (PoC)，同时从理论上向他们提供 RCE 详细信息。  
通过  
Nuclei检测  
  
可以利用以下 Nuclei 模板来识别此 SQL 注入漏洞：  
  
```
id: CVE-2024-32640info:  name: Mura/Masa CMS - SQL Injection  author: iamnoooob,rootxharsh,pdresearch  severity: critical  description: |    The Mura/Masa CMS is vulnerable to SQL Injection.  reference:    - https://blog.projectdiscovery.io/mura-masa-cms-pre-auth-sql-injection/    - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32640  impact: |    Successful exploitation could lead to unauthorized access to sensitive data.  remediation: |    Apply the vendor-supplied patch or updateto a secure version.  metadata:    verified: true    max-request: 3    vendor: masacms    product: masacms    shodan-query: 'Generator: Masa CMS'  tags: cve,cve2022,sqli,cms,masa,masacmshttp:  - raw:      - |        POST /index.cfm/_api/json/v1/default/?method=processAsyncObject HTTP/1.1        Host: {{Hostname}}        Content-Type: application/x-www-form-urlencoded        object=displayregion&contenthistid=x\'&previewid=1    matchers:      - type: dsl        dsl:          - 'status_code == 500'          - 'contains(header, "application/json")'          - 'contains_all(body, "Unhandled Exception")'          - 'contains_all(header,"cfid","cftoken")'        condition: and
```  
  
  
我们还在 nuclei-templates GitHub 项目中添加了模板。  
https://github.com/projectdiscovery/nuclei-templates/pull/9721  
结论  
  
总而言之，我们对 Masa/Mura CMS 的探索是一次富有成效的旅程，发现了一些关键漏洞。代码审查流程首先关注易受攻击的 SQL 注入代码模式，然后利用 CFM/CFC 解析器在代码库中搜索特定模式，这种方法类似于 Semgrep。一旦识别出潜在的漏洞，我们就会将其追溯到源头，在本例中是 Mura/Masa CMS 的 JSON API。  
  
我们负责任地向 Apple 以及相应的 Masa 和 Mura CMS 团队披露了这些发现。  
  
苹果在收到初始报告后两小时内就做出了响应并实施了修复，迅速解决了报告的问题。与苹果的合作一如既往地愉快。  
  
CMS 质量：  
  
Masa 是 Mura CMS 的一个开源分支，他们非常透明，并发布了 Masa CMS 的新版本并修复了相关问题。7.4.6、7.3.13 和 7.2.8 版本都包含最新的安全补丁，其中包括另一个关键的预授权 SQL 注入漏洞，该漏洞被分配了 CVE 编号 ( CVE-2024-32640 )。  
  
尽管我们多次尝试联系 Mura 团队，告知他们这些漏洞，但通过多种沟通渠道均未收到任何回复。由于 90 天的标准期限已过，我们现发布此博客文章，详细说明所报告的漏洞  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
