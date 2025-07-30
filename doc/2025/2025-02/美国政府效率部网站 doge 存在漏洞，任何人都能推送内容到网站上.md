#  美国政府效率部网站 doge 存在漏洞，任何人都能推送内容到网站上   
 独眼情报   2025-02-14 18:12  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSgNXsqv7MW8ByXicx36FbAmcTKnkicmqiakIOXmsEDiaibAFldLibZwxicbvmnkFauqAwGfrtH7Vm8To1BQ/640?wx_fmt=png&from=appmsg "")  
据两名发现该漏洞并与 404 Media 分享该漏洞的人士称，为追踪伊隆·马斯克削减联邦政府开支而建立的 doge.gov 网站并不安全，它提取的数据来自一个任何人都可以编辑的数据库。一名程序员添加了至少两个在实时网站上可见的数据库条目，并说“这是一个可笑的 .gov 网站”和“这些‘专家’让他们的数据库保持开放 -roro。”  
  
埃隆·马斯克周二告诉记者，他的政府效率部“正努力做到尽可能透明”，随后 Doge.gov 被匆忙部署。事实上，我们的行动——我们将我们的行动发布到 X 上的 DOGE 账户和 DOGE 网站上。当时，DOGE 基本上是一个空白网页。周三和周四，它进一步完善，现在显示了 @DOGE X 帐户帖子的镜像，以及有关美国政府联邦工作人员的各种统计数据。  
  
两位因调查联邦网站而要求匿名的 Web 开发专家告诉 404 Media，doge.gov 似乎是在 Cloudflare Pages 网站上构建的，而该网站目前并未托管在政府服务器上。该网站提取的数据可能由第三方写入，而且已经由第三方写入，并将显示在实时网站上。  
  
两位消息人士均向 404 Media 表示，他们注意到 Doge.gov 正在从 Cloudflare Pages 网站提取数据，而运行它的代码实际上是在该网站上部署的。  
  
一位消息人士告诉 404 Media，在研究了网站的架构并找到数据库的 API 端点后，他们能够将更新推送到政府就业信息数据库。  
  
该人向我展示了他们可以推送到网站上的两个数据库条目，在我撰写本文时，这两个条目仍在 doge.gov 上（存档于此处https://archive.is/XzvTY和此处https://archive.is/cMeco）：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSgNXsqv7MW8ByXicx36FbAmZRGkFhH3vibPqIdKHpeXpTac8aliaV62ZibQ21Wia6D9e8Lyt0ibgCAiaKFg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSgNXsqv7MW8ByXicx36FbAmVU0ICS0xnvWxdyqiahoibKSfAEWwYPVibRdvzQib5RvSnDPjFDUCQPyqyA/640?wx_fmt=png&from=appmsg "")  
  
“感觉就像是完全拼凑起来的，”他们补充道。“页面源代码中泄露了大量错误和细节。”  
  
两位消息人士均表示，该网站的设置方式表明它并非在政府服务器上运行。  
  
“基本上，doge.gov 有自己的代码库，可能是通过 GitHub 或其他方式，”另一位注意到不安全性的开发人员说。“他们从他们的代码库在 Cloudflare Pages 上部署网站，而 doge.gov 是他们的 pages.dev URL 设置的自定义域。因此，他们没有使用物理服务器或甚至像 Amazon Web Services 这样的服务器，而是使用支持自定义域的 Cloudflare Pages 进行部署。”  
  
周三，我们报道了 waste.gov，另一个用于跟踪政府浪费的网站，目前仍处于运行状态，其中包含占位符 Wordpress 默认模板页面和示例文本。我们的文章发表后，waste.gov 被置于密码墙后面。据广泛报道，DOGE 已获得包括财政部在内的各政府机构代码库的管理员访问权限。  
  
  
  
