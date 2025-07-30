#  Roundcube ≤ 1.6.10 通过 PHP 对象反序列化进行身份验证后 RCE   
 Ots安全   2025-06-05 07:58  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
2025年6月5日，网络安全研究人员Kirill Firsov披露了Roundcube webmail（版本1.1.0至1.6.10）中的一个严重远程代码执行（RCE）漏洞，编号CVE-2025-49113。该漏洞源于PHP对象反序列化机制中的缺陷，存在于Roundcube的会话处理代码中长达十年之久。攻击者只需具备有效的用户名和密码即可通过文件上传功能注入恶意载荷，绕过Web应用防火墙（WAF），实现远程代码执行，威胁程度极高（CVSS评分9.9/10.0）。  
  
  
Roundcube作为广泛使用的开源webmail解决方案，被GoDaddy、Hostinger等托管服务商以及cPanel、Plesk等控制面板默认集成，全球约5300万主机受到影响，涵盖约翰霍普金斯大学、剑桥大学等知名机构。  
  
  
补丁版本1.6.11和1.5.10已发布，但由于漏洞细节在GitHub补丁公开后48小时内被攻击者利用，并在地下论坛以高达5万美元的价格出售，研究人员提前发布了技术分析（未含完整PoC），敦促用户立即升级并监控文件上传和会话活动，以防御潜在的攻击风险。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tad1tDwGSfhIjPWQicIHBdcDK4mPqtGtzSU4j2bdMVqfDAQ72ia8icTB2lIJwlbETq9V5zKfwc20ic86ibg/640?wx_fmt=webp&from=appmsg "")  
  
为什么这次披露来得这么早  
  
这项研究原本计划在负责任的披露期后发布。然而，由于补丁在 GitHub 上迅速公开，且攻击者已在 48 小时内对漏洞进行了 diff 和武器化，技术细节已不再有效保密。  
  
鉴于该漏洞的活跃利用和在地下论坛上出售的证据，我认为发布完整的技术细节但暂时不发布完整的 PoC 符合防御者、蓝队和更广泛的安全社区的最佳利益。  
  
进行此项披露是为了让维权者在进一步的剥削升级之前获得平等的地位，并为理解问题提供透明度和技术准确性。  
  
电子邮件末日即服务  
  
你在渗透测试中遇到 Roundcube 的频率有多高？我猜：比 SSL 配置错误更常见。它无处不在——就像 WordPress 插件一样，但不知何故权限隔离更弱。  
  
Roundcube 基本上已经成为“网络邮件客户端”的默认代名词，这不仅仅是因为人们喜欢它，还因为主机提供商喜欢免费赠送它。你会发现它被Hostinger、GoDaddy、Dreamhost、OVH、Gandi等所有以每月 3.99 美元的价格出售共享主机的公司捆绑销售。  
  
别担心——控制面板也不想被冷落。cPanel 、Plesk、ISPConfig、DirectAdmin——  它们都把 Roundcube 塞进去了。这意味着，只要有一个 bug 出现，所有控制面板都会获得一个 shell。欢迎来到CVE-2025-49113：一份持续泄露的礼物。  
  
除了私营部门，Roundcube 在教育和政府机构中也得到了广泛的采用，其中包括约翰·霍普金斯大学、哥伦比亚大学和剑桥大学等知名机构。它在学术界、公共服务和高科技领域的存在，凸显了它作为一种无处不在、久经考验的解决方案的声誉，并受到世界上一些最受尊敬的机构的信赖。  
  
还认为这个漏洞只会影响小众自托管服务商吗？再想想。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tad1tDwGSfhIjPWQicIHBdcDKlny8mnAOp6XWUDeYkgWZLbkv9aZyEEiboNUicBOPTw9UXexl5mgU6UBA/640?wx_fmt=webp&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tad1tDwGSfhIjPWQicIHBdcDKviblW5F4rU3TQEEmqdHcibcgaAJ0DhTezjnqgf6kic8pib7fkFUfQZiaxcg/640?wx_fmt=webp&from=appmsg "")  
  
攻击面并不大——而是工业规模。  
  
鉴于 Roundcube 如此受欢迎，它频频引起信息安全专家的关注也就不足为奇了。我们收集到了许多引人入胜且精彩绝伦的研究成果——其中最引人注目的包括SonarSource报告的标志性CVE-2016-9920漏洞、Ambionics 🚀提供的iconv()复杂漏洞利用，以及SSD Secure Disclosure团队发现的markasjunk插件远程代码执行 (RCE) 。每一次深入研究这些报告，不仅能带来黑客的乐趣，还能激发我们去发现新事物的动力。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tad1tDwGSfhIjPWQicIHBdcDKErFpBsntibf2vUpHlGO9tG9W2ib3iaEMPN5ruKFbibXLP6HMj23lUkjBYw/640?wx_fmt=webp&from=appmsg "")  
  
当然，像Crowdfence这样的经纪商提供的    高达5 万美元的现金奖励确实很诱人——但说实话，我们来这里不只是为了赚钱。我们真正的使命是追求公共安全，推进安全研究，并保护用户和组织免受恶意攻击。  
  
我建议我们一起踏上另一场引人入胜的冒险之旅。这项调查耗费了我十几个小时的紧张精力，但你或许只需花上十几分钟就能读完，也希望它能激励其他人踏上类似的旅程！  
  
首先，让我们快速概述一下此漏洞的关键部分：  
- 影响从1.1.0到1.5.9和1.6.x到1.6.10的所有发布版本🎯  
  
- 在默认安装上可靠地重现  
  
- 无需依赖或 PHP 的黑魔法  
  
- 在代码库中潜伏了10 多年🕵️  
  
- WAF 无法检测到漏洞  
  
- 需要有效的用户名/密码组合😞（从技术上讲，CSRF 是可行的，但不够刺激）  
  
⚠️ 如果您还没有修补，请立即修补  
  
此漏洞影响 Roundcube 版本 1.1.0 至 1.6.10，包括 cPanel、Plesk、ISPConfig 和其他版本中的默认安装。  
  
安全版本是：  
- 1.6.11（最新稳定版本）  
  
- 1.5.10（长期支持版本）  
  
如果您正在运行任何旧版本，那么您就很容易上当受骗了！  
  
既然我们已经掌握了要点，那就让我们撸起袖子，直接行动起来吧！所有演示和讨论都将基于1.6.10版本——这是本次探索时的最新版本。让我们开始黑客攻击吧，当然，要负责任！  
  
Roundcube 并非普通的邮件应用，它更像是 Web 邮件客户端中的一把瑞士军刀，拥有令人印象深刻的可定制性和无限的灵活性。它能够轻松处理数十个插件，与多种数据库完美兼容，甚至支持 LDAP。这种广泛的多功能性迫使开发人员编写高度通用且适应性强的代码。此外，它必须运行流畅，主机托管巨头们依赖它的响应能力来服务其众多用户。  
  
深入野兽之腹：会议、连载与混乱  
  
当然，寻找像直接调用 exec()、include()或eval()这样的简单漏洞很常见，但说实话，在我们之前，无数黑客已经涉足过这个领域。真正有趣的是探索中间件层，也就是那些用户输入会以微妙而隐蔽的方式影响关键操作的隐蔽位置。  
  
一个有趣的机制是存储客户端的当前状态，这可以在客户端或服务器端完成。Roundcube 巧妙地处理客户端会话，其数据存储方式远远超出了标准 PHP 实践。其开发人员实现了一个高级解决方案，使会话与 MySQL、PostgreSQL、Redis、Memcached 甚至自定义存储系统兼容。这确保了数据处理的一致性，并由./program/lib/Roundcube/rcube_session.php中的内部逻辑高效管理，该文件堪称 Roundcube 框架的大脑。  
  
我发现 Roundcube 的源代码写得很好，可读性也很强。尤其引人入胜的是其即时会话处理机制。与 PHP 简单的会话存储不同，远程存储在高流量情况下可能会因持续连接而陷入困境。Roundcube 的方法巧妙地最大限度地减少了资源密集型交互，并即时执行快速无缝的会话数据更新、重新计算和规范化。  
  
由于会话文件格式基于标准 PHP 序列化，但有一些小问题，例如使用竖线 (  | ) 作为分隔符，因此 Roundcube 在实现上也遵循相同的方法。每次执行脚本并使用$_SESSION变量时，抽象类rcube_session的子类之一都会勤勉地重新计算、更新并规范化当前会话数据。效率至上！  
  
其中一个辅助方法是rcube_session→unserialize()：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tad1tDwGSfhIjPWQicIHBdcDKHOibtAdCByKSfeB7JNPhz0ZzpUv9lNiaqJopsDz7ibg7tldXkxoibfAXRg/640?wx_fmt=webp&from=appmsg "")  
  
./program/lib/Roundcube/rcube_session.php  
  
如果您曾经浏览过 PHP 源代码，您就会认出其中的奥妙——序列化数据处理涉及在结构化框架中移动指针，并计算条件、值和名称。如果您也关注 PHP 漏洞，您就会明白这里隐藏着多少陷阱。  
  
自然而然地，我的目光立刻被这句好奇的小句子吸引住了：if ($str[$p] == '!')。感叹号？这是什么意思？🤔 我突然想不起以前见过这个，于是迫不及待地点击了评论里提供的链接，找到了方法……惊喜！惊喜！那里根本没有类似的东西，既没有函数本身，也没有感叹号。这难道不是仔细研究一下这个点的好理由吗？绝对有！💯  
  
为了进行测试，我们以 RC 为每个用户生成的数据集为例。例如，在 MySQL 中，数据存储在会话表的vars列中，并以这种不太常见的格式呈现：  
  
```
dGVtcHxiOjE7bGFuZ3VhZ2V8czo1OiJlbl9VUyI7dGFza3xzOjU6ImxvZ2luIjtza2luX2NvbmZpZ3xhOjc6e3M6MTc6InN1cHBvcnRlZF9sYXlvdXRzIjthOjE6e2k6MDtzOjEwOiJ3aWRlc2NyZWVuIjt9czoyMjoianF1ZXJ5X3VpX2NvbG9yc190aGVtZSI7czo5OiJib290c3RyYXAiO3M6MTg6ImVtYmVkX2Nzc19sb2NhdGlvbiI7czoxNzoiL3N0eWxlcy9lbWJlZC5jc3MiO3M6MTk6ImVkaXRvcl9jc3NfbG9jYXRpb24iO3M6MTc6Ii9zdHlsZXMvZmVhcnNvZmYub3JnIjtzOjE3OiJkYXJrX21vZGVfc3VwcG9ydCI7YjoxO3M6MjY6Im1lZGlhX2Jyb3dzZXJfY3NzX2xvY2F0aW9uIjtzOjQ6Im5vbmUiO3M6MjE6ImFkZGl0aW9uYWxfbG9nb190eXBlcyI7YTozOntpOjA7czo0OiJkYXJrIjtpOjE7czo1OiJzbWFsbCI7aToyO3M6MTA6InNtYWxsLWRhcmsiO319cmVxdWVzdF90b2tlbnxzOjMyOiJhOVFKdkpGQXNrMkduZ1JFclE3SXZBbnkwVldHVkJ6MSI7
```  
  
  
这是因为会话数据可能包含空字节（例如，在对象表示中）以及其他控制字符。这些有时可能与所选的存储后端不兼容。因此，该字符串采用 base64 编码，解码后的形式如下：  
  
```
temp|b:1;language|s:5:"en_US";task|s:5:"login";skin_config|a:7:{s:17:"supported_layouts";a:1:{i:0;s:10:"widescreen";}s:22:"jquery_ui_colors_theme";s:9:"bootstrap";s:18:"embed_css_location";s:17:"/styles/embed.css";s:19:"editor_css_location";s:17:"/styles/embed.css";s:17:"dark_mode_support";b:1;s:26:"media_browser_css_location";s:4:"none";s:21:"additional_logo_types";a:3:{i:0;s:4:"dark";i:1;s:5:"small";i:2;s:10:"small-dark";}}request_token|s:32:"a9QJvJFAsk2GngRErQ7IvAny0VWGVBz1";
```  
  
  
我们可以看到，之前描述的行为重复了一遍，并且数据对应于通常的 PHP 会话文件内容。  
  
现在，我们可以使用框架本身，或者单独复制rcube_session→unserialize()函数，进行一些快速测试。幸运的是，我们不需要进行太多测试。如果我们使用以感叹号 (!) 开头的变量名，事情就会变得非常奇怪。以下是正常使用时的输出：  
  
```
temp|b:1;language|s:5:"en_US" … cut … request_token|s:32:"a9QJvJFAsk2GngRErQ7IvAny0VWGVBz1";
```  
  
  
将被转换成：  
  
```
a:5:{s:4:"temp";b:1;s:8:"language";s:5:"en_US" … cut … s:13:"request_token";s:32:"a9QJvJFAsk2GngRErQ7IvAny0VWGVBz1";}
```  
  
  
但是当我们将变量命名为!temp时，请注意会发生什么：  
  
```
!temp|b:1;language|s:5:"en_US" … cut … request_token|s:32:"a9QJvJFAsk2GngRErQ7IvAny0VWGVBz1";
```  
  
  
因此，我们将得到：  
  
```
a:5:{s:4:"temp";N;s:10:"1;language";s:5:"en_US" … cut … s:13:"request_token";s:32:"a9QJvJFAsk2GngRErQ7IvAny0VWGVBz1";}
```  
  
  
你发现语言是怎么被弄乱的了吗？或者更确切地说，它完全消失了，因为它现在变成了1;language 😲 。现在很明显，带有 ! 的条件逻辑被错误地评估了，并且没有包含任何针对边缘情况的额外检查。  
  
这种奇怪的逻辑究竟为何存在，至今仍是个谜。但我们确实知道的是，由于指针位置仅仅移动了一个字符，函数错误地标记了值的缺失，并顺利地跳过查找下一个键。瞧——欢迎来到令人愉悦的“会话损坏”  
($has_value = false;)世界！但这还不是全部，会话损坏与会话注入密切相关，直接指向PHP 对象注入！  
  
不过，先别急😄。在实现这个目标之前，我们得先避开一些陷阱，比如弄清楚如何以及在哪里利用它。我做的第一件事就是查找所有类型的构造函数  
$_SESSION[$under_control] = $controlled_value;，以及相关的数组合并函数，比如 array_merge。可惜的是，可用的变体要么通过白名单严格过滤输入，就像这样：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tad1tDwGSfhIjPWQicIHBdcDKtMmMVNm2ibN3dibxNMic7Vcl6icU8fY2NkQnWMAQX8ecv8gNhvp9Xgg2Gw/640?wx_fmt=webp&from=appmsg "")  
  
./program/actions/utils/save_pref.php  
  
...或者完全避免用户输入，暗示开发人员非常清楚并谨慎对待这种潜在的滥用。😅不幸的是，这里浪费了相当多的时间。  
  
继续搜索，我又回到了rcube_session.php。如果你有创意，就会发现这其实是个金矿。这里的许多方法直接与一个数组进行交互，该数组最终会变成$_SESSION，最终，控制权会移交给该类的继承者。  
  
找到入口点：当上传出现问题时  
  
经过一番挖掘，我们发现了三条值得进一步研究的有希望的途径：  
- rcube_session→append()  
  
- rcube_session→删除()  
  
- rcube_session→重新加载()  
  
快速筛选排除了两个候选方法：remove()从逻辑上来说不太合适，因为我们需要添加而不是删除；reload()缺乏用户可控制的参数，而且很少出现。最后只剩下append()了。Swift 代码grep显示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tad1tDwGSfhIjPWQicIHBdcDK1nxBhoRyMSqaxciaTfyicpxxia8IRqxX2QpJpRwWlqx3G2Cff3iaBzibQ5A/640?wx_fmt=webp&from=appmsg "")  
  
总比没有好！让我们看看./program/actions/settings/upload.php    文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tad1tDwGSfhIjPWQicIHBdcDKbtSEB3ibAJ9kPUv815BZhhqIibrn2LEKo4N5U14AI8EjQcKy4dyZGeNw/640?wx_fmt=webp&from=appmsg "")  
  
./program/actions/settings/upload.php  
  
中奖了！$_GET['_from']参数实际上没有经过任何过滤，完全符合我们的需求，并允许我们注入所需的有效载荷。  
  
让我们使用标准功能来检查一下。导航到http://roundcube.local/?_task=settings&_action=identities并上传一张图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tad1tDwGSfhIjPWQicIHBdcDK0td3jXesgA5F5pIiaXC8aAxCb8zHuKIILiahGpiaz66DFswJaXwrDcXxQ/640?wx_fmt=webp&from=appmsg "")  
  
这会触发类似如下的请求：  
  
```
POST /?_task=settings&_framed=1&_remote=1&_from=edit-identity&_id=&_uploadid=upload1747775811437&_unlock=loading1747775811438&_action=upload HTTP/1.1Host: roundcube.localX-Requested-With: XMLHttpRequest... cut ... Accept-Encoding: identityContent-Length: 242-----------------------------WebKitFormBoundaryContent-Disposition: form-data; name="_file[]"; filename="123.png"Content-Type: image/png__IMAGE_CONTENT_HERE__-----------------------------WebKitFormBoundary--
```  
  
  
 让我们看一下我们的会议并观察结果：  
  
```
language|s:5:"en_US"; ... cut ... identity|a:1:{s:5:"files";a:2:{s:20:"61747773691022408600";a:6:{s:4:"path";s:40:"/tmp/RCMTEMPattmnt682ce8fb36ab2855071037";s:4:"size";i:26347;s:4:"name";s:7:"123.png"; ... cut ... }}}
```  
  
  
答对了！🎉我们请求中的身份密钥出现了！通过修改 GET 参数，我们可以影响最终由rcube_session→unserialize()_from方法处理的内容。  
  
最初，我尝试创建另一个任意数组来嵌入一个对象。发送类似的payload后，_from=edit-!identity xxx|| b:0;test| O:4:"test":0:{}我感到很失望。该字符串没有包含在会话数据中。这可能是因为PHP会话数组的键不能包含该|字符。  
  
但会话仍然有可能被破坏，因此我们开始努力寻找解决方法。幸运的是，解决方案很快就出现了！记住，我们仍然可以控制上传文件的名称，就像我们之前使用123.png的示例一样。指针设置错误后，该方法会读取以下字符串，直到 | 字符为止，并将其作为另一个数组的键。因此，部分有效载荷可以注入到上传文件的名称中。结果如下：  
  
```
language|s:5:"en_US"; … cut … … !identity|a:1:{s:5:"files";a:2:{s:20:"61747773691022408600";a:6:{s:4:"path";s:40:"/tmp/RCMTEMPattmnt682ce8fb36ab2855071037";s:4:"size";i:26347;s:4:"name";s:39:"12xxx|b:0;test|O:4:"test":0:{}xxx|3.png"; … cut … }}}
```  
  
  
理论测试立即证实了它在实践中的成功！🎉 因此，我们可以将任意数据注入当前会话——这种情况受到 Roundcube 开发人员的严格保护，用户无法访问。  
  
按照最初的计划，我尝试了PHP 对象注入，并嵌入了类似 Guzzle 的 Payload。然而，我遇到了一个问题：直接利用这一点根本行不通，因为上传的文件名不能包含空字节，而空字节对于许多反序列化链来说至关重要。此外，Roundcube 会从用户输入中去除空字节和格式错误的 Unicode，而_from也帮不上什么忙。😔  
  
很长一段时间以来，我一直试图通过将s替换为S来利用此漏洞，但都没有成功，因为我以为字符串数据可以使用\00之类的转义序列来表示。但在rcube_session→unserialize()中，这种方法并没有实现，它会按字面意思处理每个字符，并且无法识别转义序列。因此，PHP 在尝试反序列化此类字符串时会抛出错误。所以，我们得再等等，找到绕过这个限制的方法。  
  
正如之前所述，我们可以将任意变量注入会话。但是，如果有一个参数的字符串值被强制包含编码的序列化字符串，该怎么办？也就是说，该值只是一个字符串，rcube_session→unserialize()会将其简单地赋值给一个变量，然后，这些数据稍后会被传递给另一个unserialize() 函数？幸运的是，这样的代码确实存在：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tad1tDwGSfhIjPWQicIHBdcDKhq5KjiaKzp6wuqibE3iaRLvRy0COcbpnKnrvAFmUu23T0n7prTNmkB3Tw/640?wx_fmt=webp&from=appmsg "")  
  
./program/lib/Roundcube/rcube_user.php  
  
武器化原语：制作有效载荷  
  
另外，值得庆幸的是，在意识到自己已经花了相当多的时间后，我开始思考：为什么不找另一个反序列化工具呢？用Guzzle写入文件固然不错，但立即实现 RCE 听起来更棒！🚀  
  
在这里，Roundcube 没有让人失望，它有一个来自PEAR库的精彩类可用：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tad1tDwGSfhIjPWQicIHBdcDKsp7OrF5shCnQkNvgvwI7MvV4agKIzP5SqNdn5xadGoVsWomcUC5n8A/640?wx_fmt=webp&from=appmsg "")  
  
./vendor/pear/crypt_gpg/Crypt/GPG/Engine.php  
  
因此，结合之前的研究，我们创建了一个函数，可以根据我们之前描述的场景精确计算有效载荷注入：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48tad1tDwGSfhIjPWQicIHBdcDKnpAESDqEdKicQDPElGaWxLblC2FvicIgRxDcCClj3pmh5IvvHiaBYcm0g/640?wx_fmt=webp&from=appmsg "")  
  
 首先，我们放置用于生成 RCE 小工具构造的类，将其序列化为字符串，然后开始构建我们的$payload 。 process_serialized函数确实是从PHPGGC偷来的😄，它正确地用转义序列替换了有效载荷中的空字节，从而绕过了无法通过任何其他方式传递原始有效载荷的问题。接下来，计算将作为序列化字符串传入首选项参数的数据部分的长度。这样，一个包含三个元素的数组就被放置在那里了：  
- 在第一个元素中，RC 生成的标准“垃圾”将被覆盖，我们提前知道它的长度并对其进行硬编码。  
  
- 首选项数组的第二个元素将保存我们的对象，并且$append的长度根据$payload的大小动态形成。  
  
- 第三个元素将用于销毁对象，类似于快速销毁，但仅用于确保有效载荷不会保存在数据库中，并且不会重复执行。仅执行一次，之后具有相同键的变量会将此对象从数组中删除。  
  
另外，为了以防万一，我们注入了代码preferences_time|b:0;以确保首选项不会被序列化。而且，正如我之前提到的，应用程序会从传入数据中去除所有损坏的 Unicode 字符，为什么不利用这一点来绕过 WAF 呢？只需preg_replace注入少量代码即可。  
  
说实话，当我写下这些文字的时候，我自己也开始好奇最终的请求会是什么样子😅毕竟，在写下这些文字之前，我从未见过完整的原始格式。既然我们已经看过上面的正常上传请求，现在我们可以将它与 RCE 变体进行比较，当然，这里没有混淆：  
  
```
POST / ...===================I’m withholding the code for now. Can’t have every script kiddie turning thisinto a party just yet. ===================...
```  
  
  
看起来很简单，不是吗？但现在我们知道它绝非易事😅   
  
顺便说一句，此 POST 请求没有 CSRF 保护，并且所描述的技术（有一些例外和不同的形式）可用于实现类似的结果😉  
  
最后的想法和建议：  
  
致防御者：如果您尚未修补，请立即修复。此漏洞现已被知晓、可利用且正在出售。请考虑监控文件上传、会话活动以及与此攻击向量相关的其他指标。  
  
致供应商：在大多数用户更新之前，请避免公开发布补丁，或者至少混淆提交信息，为维护者争取时间。GitHub 上的公开提交属于公开披露。  
  
致研究人员：当威胁形势发生变化时，不要害怕发布信息。负责任的披露始终是首选，但现实并不总是如此。如果黑帽黑客公开信息，白帽黑客也应该这样做——但要清晰透明、符合道德规范、技术精准。  
  
最终，这项研究的目标不仅仅是证明漏洞的存在，而是提高可利用性的标准，帮助开发人员改进，并使防御者保持领先一步。  
  
保持好奇心、保持敏锐、负责任地进行黑客攻击。  
  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
