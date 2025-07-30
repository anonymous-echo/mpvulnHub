#  从 SQL 注入到远程代码执行   
 迪哥讲事   2025-01-11 20:33  
  
<table><tbody><tr><td width="557" valign="top" style="word-break: break-all;"><h1 data-selectable-paragraph="" style="white-space: normal;outline: 0px;max-width: 100%;font-family: -apple-system, system-ui, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;letter-spacing: 0.544px;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;"><strong style="outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="color: rgb(255, 0, 0);"><strong><span style="font-size: 15px;">声明：</span></strong></span><span style="font-size: 15px;"></span></span></strong><span style="outline: 0px;max-width: 100%;font-size: 18px;box-sizing: border-box !important;overflow-wrap: break-word !important;"><span style="font-size: 15px;">文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由用户承担全部法律及连带责任，文章作者不承担任何法律及连带责任。</span></span></h1></td></tr></tbody></table>#   
  
  
  
****  
背景介绍  
#   
  
还记得之前的那篇 [Hello Lucee! 让我们再次黑掉Apple～](http://mp.weixin.qq.com/s?__biz=MjM5Mzc4MzUzMQ==&mid=2650258000&idx=1&sn=59553b3a46882c411436d78be50bc02c&chksm=be92d1d489e558c218ff7da6655bd824f14e735bcf2323dfecaedcf5335c9631db0832326695&scene=21#wechat_redirect)  
吧？国外研究人员深入研究了 Lucee 的内部工作原理，并查看了 Masa/Mura CMS 的源代码，巨大的潜在攻击面让研究人员震惊，很明显，投入时间理解代码也收获了相应回报。  
  
经过一周的探索，研究人员又发现了几个漏洞利用点，其中包括能够在 Apple Book Travel 门户中利用一个关键 SQL 注入漏洞，本文将为分享他们如何识别漏洞接收器并将其链接回源头，以及如何利用 SQL 注入来最终实现远程代码执行 (RCE)。让我们开始吧～  
# 寻找漏洞点  
  
通过使用 Masa/Mura CMS，研究人员了解了 Apple 环境中可访问的攻击面，他们的主要关注点是 JSON API，因为它公开了一些可在 Apple 环境中访问的方法。  
  
研究人员发现找到的任何潜在的漏洞点都应该源自 JSON API，于是他们仔细考虑了优化方法，从而简化源代码审查流程。研究人员探讨了是否有静态分析器或 CFM 解析器能够在不考虑消毒器的情况下遍历代码。  
  
例如，这是通过基于标签的 CFM 编写安全参数化 SQL 查询的方式：  
```
<cfquery>
select * from table where column=<cfqueryparam cfsqltype="cf_sql_varchar" value="#arguments.user_input#">
</cfquery>
```  
  
下面是不安全 SQL 查询的编写方式:  
```
<cfquery>
select * from table where column=#arguments.user_input#
</cfquery>
```  
  
如果能够解析和遍历代码，并且只打印具有未经处理的输入的 cfquery 标签，无论内部是否有 cfqueryparam 标签，那就太棒了。他们发现 https://github.com/foundeo/cfmlparser 可以轻松实现这一点。  
  
以下是针对 SQL 注入接收器检测的方式：  
- 解析每个 CFM/CFC 文件  
  
- 浏览每个语句，如果它是标签且名称为 cfquery ，则选择该语句  
  
- 删除 cfquery 代码块内的所有标签（如cfqueryparam），如果代码块中仍然有 arguments ，则输入不会参数化，并且查询容易受到 SQL 注入（假设没有其他验证）地方  
  
- 打印此查询  
  
```
<cfscript>
    targetDirectory = "../mura-cms/";
    files = DirectoryList(targetDirectory, true, "query");

    for (file in files) {
        if (FindNoCase(".cfc", file.name) or FindNoCase(".cfm", file.name)) {
            fname = file.directory & "/" & file.name;
            if (file.name != "dbUtility.cfc" && file.name != "configBean.cfc" && !FindNoCase("admin", file.directory) && !FindNoCase("dbUpdates", file.directory)) {
                filez = new cfmlparser.File(fname);
                statements = filez.getStatements();
                info = [];
                for (s in statements) {
                    if (s.isTag() && s.getName() == "cfquery" && FindNoCase("arguments", s.getStrippedInnerContent(true, true))) {
                        WriteOutput("Filename: <b>#fname#</b>");
                        WriteOutput("<br><br>" & s.getStrippedInnerContent(true, true));
                        WriteOutput("<br><br><br><br>");
                    }
                }
            }
        }
    }
</cfscript>
```  
  
研究人员开始检查结果时考虑了一些事情，例如忽略像 siteid 这样的输入，因为 JSON API 会提前对其进行验证。  
  
有两个其它输入的查询之一是这样的：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jmZHnoibapuiaRHDBMQ9iaRNRsBIN7qCfB6M96vrEd9obKicibMvuU8icUk3LfcyKia2f6NJA4ib572f8Af2Q/640?wx_fmt=png&from=appmsg "")  
# 从源头追溯  
  
查看具有此查询的函数可以得出结论，只有一个可利用的参数，即 ContentHistID ，参数 columnid 是数字，并且 siteid 默认情况下经过验证。  
```
<cffunction name="getObjects" output="false">
    <cfargument name="columnID" required="yes" type="numeric" >
    <cfargument name="ContentHistID" required="yes" type="string" >
    <cfargument name="siteID" required="yes" type="string" >

    <cfset var rsObjects=""/>

    <cfquery attributeCollection="#variables.configBean.getReadOnlyQRYAttrs(name='rsObjects')#">
        select tcontentobjects.object,tcontentobjects.name,tcontentobjects.objectid, tcontentobjects.orderno, tcontentobjects.params, tplugindisplayobjects.configuratorInit from tcontentobjects
        inner join tcontent On(
        tcontentobjects.contenthistid=tcontent.contenthistid
        and tcontentobjects.siteid=tcontent.siteid)
        left join tplugindisplayobjects on (tcontentobjects.object='plugin'
                                            and tcontentobjects.objectID=tplugindisplayobjects.objectID)
        where tcontent.siteid='#arguments.siteid#'
        and tcontent.contenthistid ='#arguments.contentHistID#'
        and tcontentobjects.columnid=#arguments.columnID#
        order by tcontentobjects.orderno
    </cfquery>

    <cfreturn rsObjects>

</cffunction>
```  
  
函数 getObjects 在 core/mura/content/contentRendererUtility.cfc 组件的 dspObjects 函数中调用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jmZHnoibapuiaRHDBMQ9iaRNRsfC5ZgqYcwkeEedniaFX1iaUibrlKgavLLVSOiaUv2k9R7QNnb9jRrvhOWg/640?wx_fmt=png&from=appmsg "")  
  
堆栈调用过程:  
  
JSON API -> processAsyncObject -> object case: displayregion -> dspobjects() -> getobjects().  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jmZHnoibapuiaRHDBMQ9iaRNRsunJmP1icC9pFcNJb1d5tyYVth6N0icLd0kFsRxWObQUWYuTewlS3Twtg/640?wx_fmt=png&from=appmsg "")  
# 触发与利用SQL注入  
  
默认情况下，Lucee 在作为输入传递时通过在单引号前添加反斜杠来转义单引号，这可以通过使用反斜杠转义单引号之一来管理，应该会触发SQL注入：  
```
/_api/json/v1/default/?method=processAsyncObject&object=displayregion&contenthistid=x%5c'
```  
  
然而，事实并非如此，重新访问源代码后，研究人员  
发现了 dspObjects  
 函数中的一个关键条件，在调用 getObjects  
 之前，必须满足 if  
 条件：  
必须在 Mura servlet 事件处理程序中将 isOnDisplay  
 属性设置为 true。  
  
最初，研究人员假设事件处理程序上的任何属性都可以通过将属性名称及其值作为参数传递来简单地设置，这个假设是基于在代码库中的调试会话。尝试以这种方式设置 isOnDisplay 属性没有成功，看来在代码中的某个地方，该属性被覆盖了。  
  
在进行一些 grep 搜索后，研究人员发现了 JSON API 的 processAsyncObjects 中的 standardSetIsOnDisplayHandler 函数调用。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jmZHnoibapuiaRHDBMQ9iaRNRsTicZR2gD5Prs8Qt97icWR4Kqvic1kdic1kWfo8aRKnpBVSDvKQn4ygMD4Q/640?wx_fmt=png&from=appmsg "")  
  
通过简单地向 previewID 参数传递任何值，就可以设置 previewID 属性，反过来又会将 isOnDisplay 属性设置为 true。  
```
/_api/json/v1/default/?method=processAsyncObject&object=displayregion&contenthistid=x%5c'&previewID=x
```  
  
成功！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jmZHnoibapuiaRHDBMQ9iaRNRstRBkPJ3CdAucwAXfOer3AI3t4WhecRvVgHqzznn78siaY1b3K8FJySQ/640?wx_fmt=png&from=appmsg "")  
  
由于这是一个基于错误的 SQL 注入，因此可以利用它来实现远程代码执行 (RCE)，在本地环境中通过以下步骤成功执行了 RCE：  
1. 重置管理员用户的密码  
  
1. 通过SQL注入获取重置令牌和用户ID  
  
1. 使用带有泄露信息的密码重置端点  
  
1. 利用插件安装上传 CFM 文件  
  
然而在Apple的环境中，只遇到了一个Unhandled Exception错误，没有任何查询相关的信息，从而将其变成了SQL盲注，幸运的是，token和用户 ID 是 UUID，因此泄露它们相对简单。  
  
利用一些脚本编写，完成任务：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/hZj512NN8jmZHnoibapuiaRHDBMQ9iaRNRsdwG0m18VZ89AeTTC3nicXCVdvH6qvFVIBZZXFWHtVIaWDDU0opiaNQ5g/640?wx_fmt=png&from=appmsg "")  
  
研究人员立即向苹果提交了漏洞报告，包括演示登录帐户的PoC（概念验证），同时理论上向他们提供了 RCE 详细信息。  
# 通过Nuclei检测  
  
可以利用以下 Nuclei 模板来识别 SQL 注入漏洞：  
```
id: CVE-2024-32640

info:
  name: Mura/Masa CMS - SQL Injection
  author: iamnoooob,rootxharsh,pdresearch
  severity: critical
  description: |
    The Mura/Masa CMS is vulnerable to SQL Injection.
  reference:
    - https://blog.projectdiscovery.io/mura-masa-cms-pre-auth-sql-injection/
    - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32640
  impact: |
    Successful exploitation could lead to unauthorized access to sensitive data.
  remediation: |
    Apply the vendor-supplied patch or update to a secure version.
  metadata:
    verified: true
    max-request: 3
    vendor: masacms
    product: masacms
    shodan-query: 'Generator: Masa CMS'
  tags: cve,cve2022,sqli,cms,masa,masacms

http:
  - raw:
      - |
        POST /index.cfm/_api/json/v1/default/?method=processAsyncObject HTTP/1.1
        Host: {{Hostname}}
        Content-Type: application/x-www-form-urlencoded

        object=displayregion&contenthistid=x\'&previewid=1

    matchers:
      - type: dsl
        dsl:
          - 'status_code == 500'
          - 'contains(header, "application/json")'
          - 'contains_all(body, "Unhandled Exception")'
          - 'contains_all(header,"cfid","cftoken")'
        condition: and
```  
# 结论  
  
对 Masa/Mura CMS 的探索是一次相当有意义的旅程，代码审查过程首先关注易受攻击的 SQL 注入代码模式，然后利用 CFM/CFC 解析器在代码库中搜索特定模式，这与 Semgrep 的方法类似。一旦识别出潜在的接收器，将追溯源头，在本例中为 Mura/Masa CMS 的 JSON API。  
  
苹果公司在收到初步报告后 2 小时内做出了回应并实施了修复，迅速解决了所报告的问题。  
  
Masa 是 Mura CMS 的开源分支，它们非常透明，并发布了带有修复程序的新版本 Masa CMS。7.4.6、7.3.13 和 7.2.8 版本具有最新的安全补丁，其中包括另一个关键预身份验证的 SQL 注入，该漏洞被分配了相应的CVE（CVE-2024-32640）。  
  
尽管研究人员多次尝试就这些漏洞与 Mura 团队联系，都没有收到任何回复。随着 90 天的标准期限过去，研究人员公布了本文，详细介绍了所报告的漏洞。  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5EMr3X76qdKBrhIIkBlVVyuiaiasseFZ9LqtibyKFk7gXvgTU2C2yEwKLaaqfX0DL3eoH6gTcNLJvDQ/640?wx_fmt=png&from=appmsg "")  
## 往期回顾  
  
[一款bp神器](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495880&idx=1&sn=65d42fbff5e198509e55072674ac5283&chksm=e8a5faabdfd273bd55df8f7db3d644d3102d7382020234741e37ca29e963eace13dd17fcabdd&scene=21#wechat_redirect)  
  
  
[ssrf绕过新思路](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247495841&idx=1&sn=bbf477afa30391b8072d23469645d026&chksm=e8a5fac2dfd273d42344f18c7c6f0f7a158cca94041c4c4db330c3adf2d1f77f062dcaf6c5e0&scene=21#wechat_redirect)  
  
  
[一个辅助测试ssrf的工具](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247496380&idx=1&sn=78c0c4c67821f5ecbe4f3947b567eeec&chksm=e8a5f8dfdfd271c935aeb4444ea7e928c55cb4c823c51f1067f267699d71a1aad086cf203b99&scene=21#wechat_redirect)  
  
  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
  
  
以上内容由骨哥翻译并整理。  
  
原文：https://blog.projectdiscovery.io/hacking-apple-with-sql-injection/?ref=projectdiscovery-io-blog-newsletter  
  
  
