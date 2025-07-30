#  记一次IDOR 和访问控制缺失漏洞挖掘   
白帽子左一  白帽子左一   2025-01-23 04:02  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFbaUgVwdsriauB77CgQS8lyBNAxtx9IMqJQdhuuoITunu8A5Gp7kFjF7BvEXSaLMuDTYhnu7Nicghg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
**来****Track安全社区投稿~**  
  
**赢千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
#### 测试 IDOR（不安全的直接对象引用） 漏洞时，我会使用一系列工具，确保不会遗漏任何问题。以下是我的测试方法：  
  
**设置 Firefox 和 Pwnfox：**  
  
1、我使用 **Firefox** 浏览器，并安装了 **Pwnfox 扩展**。Pwnfox 允许我隔离并管理不同的浏览上下文，方便在测试账户之间切换。  
  
2、我将 Firefox 连接到 **BurpSuite**，用于捕获和监控浏览器与测试应用程序之间的所有网络流量。这种设置帮助我详细检查请求和响应。  
  
**后台运行 Autorize 工具：**  
  
1、同时，我在后台运行 **Autorize 工具**。这个工具持续检查可能被我在手动测试中忽略的访问控制漏洞。Autorize 特别有用，它会标记检测到的任何未授权访问，即使我已经从某个请求转移到其他地方。  
  
2、我还会通过 **BurpSuite 的 HTTP 历史记录选项卡**手动检查应用程序的请求和响应流量。  
  
**跟踪 ID 和对象：**  
  
1、在测试过程中，我会确保检查应用程序中所有可能涉及 **ID 和对象**（例如帖子 ID、用户 ID 等）的部分，因为这些通常是发现 IDOR 漏洞的关键。  
  
2、为了保持条理，我会将发现的所有 ID 和对象存储在一个名为 **Obsidian** 的应用中。Obsidian 可以帮助我以结构化的方式记录测试细节。  
  
3、我会为每个测试的应用程序创建一个 Obsidian 文件，在其中存储重要信息，比如两个测试账户的 ID，以及应用使用的任何 **Cookies 或 JWT 令牌**（如果涉及身份验证）。  
  
**功能测试：** 在使用应用程序时，我会全面测试它是否存在 **IDOR 漏洞**，尝试所有可能的方式访问或操作用户本不该接触的资源。  
  
例如，当应用允许用户执行 **CRUD 操作**（创建、读取、更新、删除）时，我会测试每个操作是否可能被未经授权的用户利用：  
  
1、**创建（Create）：** 我能否以其他用户的身份创建帖子？  
  
2、**读取（Read）：** 我能否通过修改帖子 ID 读取其他用户的帖子？  
  
3、**更新（Update）：** 我能否更改不属于我的帖子内容？  
  
4、**删除（Delete）：** 我能否删除其他用户的帖子？  
  
虽然该应用看似有一些访问控制措施，但这些措施在所有功能上的实现并不完善。这种访问控制的缺失使我发现了一个与生成帖子报告相关的漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFoZZzALQr9rmNjiabK6fGicKhF3eTV1OianiaM7ONernNxcBQQTucl78nicfQTQBO4sTaB01e8qp50u6A/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
在测试过程中，我注意到该平台允许用户对帖子进行 **创建、读取、更新和删除（CRUD）** 操作。于是，我针对这些操作测试了 IDOR 漏洞，重点检查访问控制是否得到了正确实施。很明显，访问控制在各个功能上都没有得到良好的执行。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFoZZzALQr9rmNjiabK6fGicKsaF5eP4QXbZGvzP228mrjiaKEQDosffEw6PBclBbl1POJXE2ecCcmQg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
我发现了一个功能，可以为所有帖子生成报告。我的第一个想法是：**“我是否能够访问或导出其他用户帖子生成的报告？”**  
  
我尝试通过更改帖子 ID 来修改请求，试图将其他用户的报告发送到我的邮箱。然而，这种情况下系统是安全的；报告会直接发送到与账户关联的邮箱，这使得仅通过修改 ID 来劫持其他用户的报告变得困难。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFoZZzALQr9rmNjiabK6fGicKUkGozwPMQxdfibZCQVSWiallOrTS9mdaobB2YU09rl9KddfmV7raPwVA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
**在彻底点击了所有按钮并测试了应用程序的每个功能后，**我偶然发现了另一个导出功能。这次，它允许将报告导出为 PDF。这时，我意识到可能存在另一个利用 IDOR 漏洞的机会。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFoZZzALQr9rmNjiabK6fGicKmbGP9s3b0MgBbaTUg6N3hHmrTHWEZc8NunTYwFfUKY8IdtSSj1ezSg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
起初，我并没有计划测试这个导出功能，但出于好奇，我点击了下载 PDF 的按钮。下载完成后，我决定查看背后发生了什么。于是，我打开了 **BurpSuite**，并导航到 **HTTP 历史记录**标签，查看已发出的请求。  
  
这成为了促使我进一步调查的关键时刻。通过检查这些 HTTP 请求，我能够了解应用程序如何处理 PDF 的生成以及相关的参数。这给了我一个机会去测试是否可以操控请求，尤其是 **post ID**，以尝试下载其他用户的报告。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFoZZzALQr9rmNjiabK6fGicKWcPBly1rK1jvLKtONHia2icn7U0zvyM9yhvSX0covD3kLwezh3GfXibgg/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
最后这两个请求非常适合测试 IDOR。让我们将它们发送到 Repeater 中，看看能发现什么！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFoZZzALQr9rmNjiabK6fGicKVuUktOduztu8lE3NmsRGoZZ8sXLibxbkAwc2O0ktDGMl8KWsez2pHHw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
在请求 (1) 中，我发现了两个具有 **CREATED** 状态的有趣 ID：  
```
“backgroundJobId”:”d69047b7–3a7a-4784–96be-6633b6d8bd45",”status”:”CREATED”
```  
  
这个 ID 引起了我的注意，所以我将它存储在 **Obsidian** 中以供参考。  
  
接着，我打开了另一个请求，发现还有更多内容可以探索……  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFoZZzALQr9rmNjiabK6fGicKnFpkxjljWbVGPoh83EjOdBqHCfup797eQ18X3F3acIC6OIZ1ib0JoxA/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
在 **请求 (2)** 中，我注意到它使用了我已经存储在 **Obsidian** 笔记中的同一个 **backgroundJobId**。响应中包含了用于下载内容的 URL，但仅针对**单个帖子**（而不是我所有的帖子）。这让我产生了一个想法——如果我能访问其他用户的报告呢？  
  
为了尝试这一点，我回到返回 **backgroundJobId** 的请求并将其发送到 **BurpSuite 的 Intruder**。由于平台对 ID 使用了顺序编号，我设置了一个范围为 **0 到 9,999,999** 的爆破，目的是通过依次测试每个数字来检索所有有效的帖子 ID。  
  
一旦我获得了其他用户帖子对应的有效 **backgroundJobId** 值，我手动将它们插入到以下 URL 中：  
```
https://s3.amazonaws.com/xxxxxcompanyname/report/xxxxxxx/20241013/{backgroundJobId}.pdf
```  
  
通过这样做，我可以未经授权访问其他用户的 PDF 报告，暴露了他们的私人帖子信息，我能够看到应用程序中的所有帖子。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFoZZzALQr9rmNjiabK6fGicKn22QPuFKA8pWqCibNdOd7S67QzzIChStRfficuwrqvrRRtkaavdibd5kQ/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
顺便提一下，我们实际上这里有 **两个漏洞**：  
  
1、**IDOR（不安全的直接对象引用）：** 第一个漏洞是 IDOR 漏洞，我们通过在请求中操控帖子 ID，成功获取了 **backgroundJobId**。这使我们能够访问其他用户的报告。  
  
2、**访问控制缺失：** 第二个问题是 **访问控制缺失** 漏洞。该应用仅通过使用 **UUID（通用唯一标识符）** 来保护报告的访问权限，但这不足以保证安全。由于没有额外的安全层（例如签名或适当的授权检查），攻击者仍然可以通过猜测或暴力破解 UUID 来利用该系统。这意味着未经授权的用户只需知道或猜测一个有效的 UUID 就能访问报告。  
  
简而言之，该应用未能实施适当的安全机制来防止未经授权的访问，使这两个漏洞都变得非常危险。  
  
**声明：⽂中所涉及的技术、思路和⼯具仅供以安全为⽬的的学********习交流使⽤，任何⼈不得将其⽤于⾮法⽤途以及盈利等⽬的，否则后果⾃⾏承担。所有渗透都需获取授权！**  
  
**如果你是一个网络安全爱好者，欢迎加入我的知识星球：zk安全知识星球,我们一起进步一起学习。星球不定期会分享一些前沿漏洞，每周安全面试经验、SRC实战纪实等文章分享，微信识别二维码，即可加入。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/CBJYPapLzSFIJlRFYoItlJDrScxuTPmfnqibC1ApJ2OKh5sF41qicCo5AvQ4icuG8kbqQxZ5HVypvJ8jZDzsmD37Q/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
