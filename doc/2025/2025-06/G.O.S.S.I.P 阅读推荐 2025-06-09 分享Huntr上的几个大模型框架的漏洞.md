#  G.O.S.S.I.P 阅读推荐 2025-06-09 分享Huntr上的几个大模型框架的漏洞  
Shangzhi Xu  安全研究GoSSIP   2025-06-09 14:11  
  
**“**  
 穷学生终于交完论文了，最近想逛逛huntr，想看看能不能崩个蛋白粉  
钱 ![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/Expression/Expression_2@2x.png "")  
**。**  
  
**不得不说很多bug bounty项目上报出来的漏洞确实很有意思，首先是都有比较详细的root cause介绍，数据怎么进来的程序怎么崩溃的，其次是确实是有足够高的严重性才能被接收。**  
  
**很多CVE相比较起来往往没那么高的可利用性。”**  
  
****  
**“分享三个看着挺有意思的大模型框架上的漏洞，和我平时见到的，fuzzing或者静态分析得到的漏洞还是有挺大区别的”**  
  
  
## 1. CVE-2024-12910  
  
llama_index 是一个为LLM设计的“RAG 框架”，支持多种数据源读取器（Reader），比如从 PDF、Markdown、本地文件系统、甚至网页上读取知识库内容，并将其结构化为 LLM 可以检索的格式。  
  
  
漏洞出现在llama_index的KnowledgeBaseWebReader。这个是一个专门用于抓取网页知识库内容的模块，它内部包含一个核心函数 get_article_urls()，该函数的作用是递归地从网页链接中查找所有的文章 URL，并返回一个包含所有可用文章链接的列表。  
```
 def get_article_urls(
        self, browser: Any, root_url: str, current_url: str
    ) -> List[str]:
        page = browser.new_page(ignore_https_errors=True)
        ...
        # 查找当前页面里面所有的link (e.g. <a></a>
       for link_selector in self.link_selectors:
            ahrefs = page.query_selector_all(link_selector)
            links.extend(ahrefs)     
             
        for link in links:
            url = root_url + page.evaluate("(node) => node.getAttribute('href')", link)  
            # 递归调用访问每一个link
            article_urls.extend(self.get_article_urls(browser, root_url, url))
```  
  
  
这个漏洞，属于 **递归跳转死循环**  
 场景，在递归调用中，它会不断爬取页面中的 <a href="/">  
 之类的链接，而**没有深度限制，也没有 URL 去重机制**  
。  
  
  
因此，如果我们构建一个恶意的网站如下：  
```
class InfiniteLoopHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        ...
        # 返回一个网页内容：始终带有链接指向自身（/）
        # 每次访问任意 URL（如 /）
        # 都会返回一个 <a class="article-link" href="/"> 始终指向自身
        
        self.wfile.write(b"""
            <html>
                <body>
                    <h1>Test Article</h1>
                    <a class="article-link" href="/">Read more</a>
                </body>
            </html>
        """)
```  
  
每次访问任意 URL（如 /）都会返回相同的 HTML 页面，而这个页面中包含一条 <a class="article-link" href="/"> 链接，始终指向自身。浏览器/爬虫如果提取这个链接并继续访问，将陷入  
死循环。  
  
## 2. CVE-2025-1752  
  
上述的  
CVE-2024-12910被修复的方法是作者加了个递归访问的次数限制max_depth  
```
max_depth: int = 100
```  
  
结果，作者光硬编码了这个变量，忘了在循环里使用max_depth了....额，然后又被bug hunter发现了，然后  
$750又送给了bug hunter![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/newemoji/Yellowdog.png "")  
。这就形成了  
CVE-2025-1752。  
  
## 3. CVE-2024-43497  
  
在 Microsoft 的开源深度学习训练加速框架   
DeepSpeed  
 中  
，存在一个命令注入漏洞。  
  
check_for_libaio_pkg() 函数中，开发者使用了 subprocess.Popen(..., shell=True) 并拼接了用户可控输入，导致攻击者可以构造恶意命令并执行任意系统指令。  
###   
  
这个函数位于 DeepSpeed 安装或运行时的自动依赖检查逻辑中，其职责是检测当前系统中是否安装了名为 libaio  
 的底层 I/O 库（不同 Linux 发行版使用不同的包管理器）。函数的简化伪代码如下：  
```
def check_for_libaio_pkg():
    lib = "libaio"  # 目标依赖库名称
    pkgmgrs = [("dpkg", "-s"), ("rpm", "-q"), ("pacman", "-Q")]

    for pkgmgr, flag in pkgmgrs:
        cmd = f"{pkgmgr} {flag} {lib}"  # 拼接命令字符串
        try:
            subprocess.Popen(cmd, shell=True)  # 危险调用
        except:
            continue
```  
  
表面上看，lib 是固定写死的 "libaio"。但攻击者可通过 污染 PATH 路径、劫持 pkgmgr（如 dpkg、rpm） 来控制执行内容。  
  
一旦启用 shell=True，即使 cmd 结构看似正常，也会被当作一个完整的 shell 命令字符串解析。  
  
例如报告里面给出了一个利用场景：  
1. 攻击者写一个伪装的 dpkg  
 程序，内部植入恶意 payload  
  
1. 攻击者替换系统命令路径，将伪装的dpkg放在系统路径上  
  
1. DeepSpeed运行的时候，subprocess.Popen就会直接运行恶意的dpkg，造成漏洞。  
  
看到这里，还是有点疑惑。  
CVE-2024-43497的利用场景很苛刻，需要攻击者能改变系统默认路径配置等。  
  
个人感觉，这更多属于代码质量问题，漏洞利用价值没有很大（自己琢磨的不对还望指正）。当然微软还是确认了漏洞并给了赏金。  
  
  
## 4. 碎碎念  
  
其实翻遍了Huntr上大部分的项目之后，发现能拿到赏金的报告确实占少数，很多报告，在静态分析工具看来确实是一个漏洞，但是却没有被接受。  
  
  
主要原因是因为这些漏洞虽然可能触发，但是需要比较苛刻的实际应用条件，例如一个报告认为  
apache / spark里面存在一个路径遍历漏洞，用户在解包的时候，如果压缩包里面的文件名是奇怪的路径，例如  
```
 ../../../../etc/passwd
```  
  
源代码中下面的部分将会覆盖系统文件  
```
tar = tarfile.open(package_local_path, "r:gz")
for member in tar.getmembers():
    if member.name == package_name:
        # Skip the root directory.
        continue
    member.name = os.path.relpath(member.name, package_name + os.path.sep)
    tar.extract(member, dest)  # Vulnerable line
```  
  
但是Apache的开发人员认为这并不是一个漏洞，理由是这段代码只会在用户安装程序的时候调用，如果用户能安装程序，那么他已经有了较高的权限，他并不需要利用这个漏洞来获取更高的权限，  
因此没有利用场景  
。  
  
这个报告经过一年左右的拉扯之后被拒绝掉，被标记为Spam ![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/assets/Expression/Expression_18@2x.png "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ELicaicj3FtibmIUOOpqibdwzd9k8TrBGpcTgPvFsXicNaRIPctvPLTtbk2OC3CfLZdlIicfj4kr2vL2gYdnl6ZY91Bw/640?wx_fmt=png&from=appmsg "")  
  
  
  
多数成熟的静态分析工具（如 CodeQL 等）都是基于  
纯代码层面的分析  
，没有特殊考虑使用场景，因此都有可能对这个 tar 解压路径遍历场景发出告警造成误报。或许这也是以后写工具需要注意的一些点吧。  
  
  
  
[1] “  
CVE-2024-12910  
”:   
  
https://huntr.com/bounties/27883f22-35ff-49df-aaa5-05031c7d6ad8  
  
[2] “  
CVE-2025-1752  
”:   
  
https://huntr.com/bounties/cd7b9082-7d75-42e4-84f5-dbee23cbc467  
  
[3] “  
CVE-2025-1752  
”:   
  
https://huntr.com/bounties/57772f51-a788-4b81-9e65-bc40809ee026  
  
[4] “  
Arbitrary File Write via Tar Extraction (Path Traversal) in apache/spark  
”:   
  
https://huntr.com/bounties/dbef8d25-f45d-4b74-977e-0adf43583127  
  
  
  
