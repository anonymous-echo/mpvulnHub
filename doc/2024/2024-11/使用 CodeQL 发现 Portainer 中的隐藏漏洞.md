#  使用 CodeQL 发现 Portainer 中的隐藏漏洞   
 Ots安全   2024-11-02 10:31  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taeAthc8s9As0y7jZpK7V0fcWXj2bicAWWgepCA4O5mrn3R8zibZlmLJARUTHr0tLBIibml2Jr6FFB7uw/640?wx_fmt=webp&from=appmsg "")  
  
最近，我们研究了一个关于 Portainer 的项目，Portainer 是用于管理 Kubernetes 和 Docker 环境的首选开源工具。Portainer 在 GitHub 上拥有超过 3 万颗星，它为您提供了一个用户友好的 Web 界面，可让您轻松部署和监控容器化应用程序。  
  
由于 Portainer 是开源的，我们认为高级代码分析工具CodeQL非常适合检查其代码库是否存在任何安全问题。CodeQL 通过将代码转换为数据库来深入分析代码，您可以查询可能表明安全漏洞的模式。  
  
在此博客中，我们将展示如何使用 CodeQL 查找这些漏洞，甚至编写自定义查询来查找特定漏洞。让我们深入了解一下。  
  
**总结**  
  
在研究过程中，我们发现Portainer中有两个漏洞：  
- CVE-2024-33661：两个盲服务器端请求伪造 (SSRF) 漏洞。  
  
- CVE-2024-33662：AES-OFB 实施中的加密缺陷。  
  
**Portainer 概述**  
  
如上所述，Portainer 是一个开源管理工具，它提供了一个简单直观的界面来部署和管理 Docker 容器（图 1）。例如，无需使用复杂的 Docker 命令，只需单击几下即可轻松启动或停止容器。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taeAthc8s9As0y7jZpK7V0fcvRc7ibSMaibAQrrkrBqiabnaKf4tfia6uXj8ZR8ND0hscKCrPymhZaGylg/640?wx_fmt=webp&from=appmsg "")  
  
图 1 – Portainer Web 应用程序  
  
由于 Portainer 是一个用 Golang 编写的开源项目（由 CodeQL 支持），我们决定探索 CodeQL 是否可以像过去一样帮助我们发现安全问题。  
  
**关于 CodeQL**  
  
CodeQL 是一个强大的代码分析框架，最初由Semmle开发，现在由 GitHub 维护。它可免费用于开源项目。它允许开发人员和研究人员通过查询使用 CodeQL 生成的代码数据库来执行变体分析以查找安全漏洞。  
  
CodeQL 支持多种语言，例如 C/C++、C#、Java、JavaScript、Python 和 Golang。  
  
一旦我们生成了代码数据库，即包含所有相关代码文件及其关系的代码库的结构化表示，我们就可以使用由 GitHub 和社区开发的预制查询，或者编写和使用自定义查询。  
  
**设置CodeQL环境**  
  
我们首先在Visual Studio Code 中安装CodeQL 扩展。之后，我们下载了启动工作区。下一步是为我们的工作项目（在本例中为 Portainer）生成一个数据库。  
  
可以使用 CodeQL CLI 生成数据库；但是，在某些情况下（比如我们的情况），CodeQL 扩展中有一个更简单的选项，即通过粘贴存储库的 GitHub URL 来下载数据库（图 2）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taeAthc8s9As0y7jZpK7V0fcuATCxwZCPF2UNKMmLS8kMU627ibPM6OLIbkERFzMGB4Ln02oMaLHDuw/640?wx_fmt=webp&from=appmsg "")  
  
图 2 – 从 GitHub 下载 CodeQL 数据库  
  
在工作区中，我们可以访问许多预制的 CodeQL 查询（图 3）。例如，一个典型的查询可以检查SQL 注入漏洞。  
  
预制查询分为几类；其中一类是安全性，默认情况下，我们可以同时运行最多 20 个查询（可在扩展设置中调整）。这可以检测代码库中的潜在安全漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taeAthc8s9As0y7jZpK7V0fcgg9m6O6YG6Uia738Kk6fxwLuVnBX1s8wD1XzhHC977PkSM8EPAiaQGww/640?wx_fmt=other&from=appmsg "")  
  
图 3 – 针对 Go 的预制 CodeQL 查询  
  
**运行 CodeQL 查询**  
  
我们运行了所有预制的安全查询（CWE-020、CWE-022 等）以及实验查询，调查了每个发现并评估其中大多数是不可利用的 — — 有些是误报（图 4）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taeAthc8s9As0y7jZpK7V0fcE8denmJFIddiaJeeKsv9quYRvnSeoMDa0kQ0V2NloWdtj203njAK9CQ/640?wx_fmt=webp&from=appmsg "")  
  
图 4 – 运行查询后的查询历史记录  
  
经过一番调查，我们发现了两个值得注意的发现，导致了盲目的服务器端请求伪造（SSRF）漏洞。  
  
我们通过CWE-918 查询发现了这些漏洞，该查询使用请求伪造查询库来搜索在网络请求中应用不受信任的用户输入的情况。例如，查询可能会检测到将用户提供的 URL 直接传递给发出 HTTP 请求的函数的情况，这可能允许攻击者执行 SSRF。  
  
**双盲 SSRF（CVE-2024-33661）**  
  
SSRF是一种安全漏洞，它允许攻击者诱导服务器端应用程序向非预期目标发出 HTTP 请求，从而可能导致未经授权访问内部资源。盲 SSRF 是一种 SSRF 攻击，攻击者无法直接看到来自服务器的响应。  
  
我们对第一个漏洞的调查始于 CodeQL 查询结果，该结果突出显示了代码库中的潜在起点（源）和终点（接收器）（图 5）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taeAthc8s9As0y7jZpK7V0fcZE6FNrPRVO8OvUO6990e5cAQdY0saEEcXibpmdMJGUlcN6bMU1pJLlw/640?wx_fmt=webp&from=appmsg "")  
  
图 5 – CodeQL SSRF 结果  
  
这些结果将我们引向了/api/templates/helm端点。我们观察到处理对/api/templates/helm 的GET 请求的函数helmRepoSearch包含以下代码：  
  
```
func (handler *Handler) helmRepoSearch(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
    repo := r.URL.Query().Get("repo")
    ...
    result, err := handler.helmPackageManager.SearchRepo(searchOpts)
    ...
}
```  
  
  
代码片段 1 – helmRepoSearch 实现  
  
这里，从查询参数中提取repo变量，经过验证并转发到SearchRepo函数，然后该函数发出 HTTP GET 请求：  
  
```
func (hbpm *helmBinaryPackageManager) SearchRepo(searchRepoOpts options.SearchRepoOptions) ([]byte, error) {
   ...
  url.Path = path.Join(url.Path, "index.yaml")
  resp, err := client.Get(url.String())
  ...
}
```  
  
  
代码片段 2 – SearchRepo 实现  
  
这意味着当提供类似/api/templates/helm?repo=http://<IP>:<PORT> 的URL 时，它将请求http://<IP>:<PORT>/index.yaml（图 6）。此设置允许我们控制服务器请求的 URL。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taeAthc8s9As0y7jZpK7V0fcdzgibab9fv5e0TGvgYgD7IdiazXOqJg54hrZg6icVHxt0O76QV3b3XgeA/640?wx_fmt=webp&from=appmsg "")  
  
图 6 – Portainer 获取 Helm 索引 YAML 文件的常规行为  
  
尽管SearchRepo将index.yaml附加到 URL，但我们可以通过配置服务器将index.yaml重定向到我们控制的任意内部服务来绕过此预期行为。  
  
攻击者可以设置一个监听端口 8081 的服务器，并有一个名为/index.yaml的端点，可以重定向到攻击者想要的任何位置，例如同一网络内的内部服务（例如内部 API 或数据库）。  
  
攻击者可以通过制作 URL /api/templates/helm?repo=https://attacker.com:8081向该本地端点发送请求。  
  
反过来，Portainer 将接收请求并向https://attacker.com:8081/index.yaml发送 GET 请求。  
  
为了演示这一点，我们在 Portainer 的本地服务器上创建了一个 HTTP Web 服务器，该服务器监听端口 1337 并包含一个端点/web。  
  
然后，攻击者服务器将接收此请求，并且由于服务器有一个名为index.yaml的端点，它会将请求重定向到http://127.0.0.1:1337/web（图 7）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taeAthc8s9As0y7jZpK7V0fcDJ9drcoIyhbRic2ZHPXGAgEaTZ51AiaUrbQ7s97fY6Qq9IGEYt0Y7AkQ/640?wx_fmt=webp&from=appmsg "")  
  
图 7 – 盲 SSRF 将 Portainer 重定向到内部服务  
  
通过设置此重定向，我们能够演示攻击者如何利用此 SSRF 漏洞使服务器访问原本受到保护的内部服务。  
  
**第二个盲 SSRF**  
  
第二个盲 SSRF 漏洞与第一个类似。此漏洞存在于helmShow函数中，该函数处理对/api/templates/helm/{command:chart|values|readme} 的GET 请求，代码如下：  
  
```
func (handler *Handler) helmShow(w http.ResponseWriter, r *http.Request) *httperror.HandlerError {
  repo := r.URL.Query().Get("repo")
  ...
  chart := r.URL.Query().Get("chart")
  if chart == "" {
    return httperror.BadRequest("Bad request", errors.New("missing `chart` query parameter"))
  }

  cmd, err := request.RetrieveRouteVariableValue(r, "command")
  if err != nil {
    cmd = "all"
    log.Debug().Str("default_command", cmd).Msg("command not provided, using default")
  }

  showOptions := options.ShowOptions{
    OutputFormat: options.ShowOutputFormat(cmd),
    Chart: chart,
    Repo: repo,
  }
  result, err := handler.helmPackageManager.Show(showOptions)
  ...
}
```  
  
  
代码片段 3 – helmShow 实现  
  
helmShow函数以以下方式处理 URL 路径：  
  
```
/api/templates/helm/{command:chart|values|readme}?repo=http://<repository_url>&chart={chart_name}
```  
  
  
代码片段 4 – helmShow 处理 URL 路径  
  
该函数提取参数并将其发送给helmPackageManager.Show(..) 函数：  
  
```
// Show runs `helm show <command></command> --repo ` with specified show options.
// The show options translate to CLI arguments which are passed in to the helm binary when executing install.
func (hbpm *helmBinaryPackageManager) Show(showOpts options.ShowOptions) ([]byte, error) {
  if showOpts.Chart == "" || showOpts.Repo == "" || showOpts.OutputFormat == "" {
    return nil, errRequiredShowOptions
  }

  args := []string{
    string(showOpts.OutputFormat),
    showOpts.Chart,
    "--repo", showOpts.Repo,
  }

  result, err := hbpm.run("show", args, showOpts.Env)
  if err != nil {
    return nil, errors.New("the request failed since either the Helm repository was not found or the chart does not exist")
  }

  return result, nil
}
```  
  
  
代码片段 5 – 显示实现  
  
该函数将参数组装成 Helm CLI 命令，并调用hbpm.run（一个库）来使用以下命令运行 Helm CLI ：  
  
```
helm show <command:chart|values|readme> <chart_name> --repo http://<repository_url>
```  
  
  
代码片段 6 – helm CLI 命令  
  
helm 命令将通过向存储库 URL 发送 GET 请求，使用index.yaml文件搜索存储库 URL 。正如我们在第一种情况下所做的那样，我们可以将存储库 URL 设置为我们的服务器，并将对“index.yaml”的 GET 请求重定向到我们想要的任何地方。  
  
我们向 Portainer 报告了这些问题，他们在 2.20.0 版本上迅速修复了这个问题，并将其标记为CVE-2024-33661。  
  
以下是这两个漏洞的PoC利用演示：  
  
  
**不安全的 AES-OFB 实施（CVE-2024-33662）**  
  
在检查 Portainer 中的 API 时，我们发现了与备份功能相关的另一类漏洞。Portainer 允许用户下载其配置的备份文件，并使用可选密码进行加密（图 8）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taeAthc8s9As0y7jZpK7V0fc1plMOd9dRicms6lSibSZnwL7B85YBEgaaxKuoavicibpm1A9GlrlAMCBog/640?wx_fmt=webp&from=appmsg "")  
  
图 8-Portainer 下载备份功能  
  
此过程涉及对/backup 的POST 请求，该请求调用CreateBackupArchive函数。此函数使用 Portainer 服务器配置创建一个 tar.gz 存档，并通过调用encrypt函数使用提供的密码对其进行加密：  
  
```
func encrypt(path string, passphrase string) (string, error) {
  in, err := os.Open(path)
  if err != nil {
    return "", err
  }
  defer in.Close()

  outFileName := fmt.Sprintf("%s.encrypted", path)
  out, err := os.Create(outFileName)
  if err != nil {
    return "", err
  }

  err = crypto.AesEncrypt(in, out, []byte(passphrase))

  return outFileName, err
}
```  
  
  
代码片段 7 – 加密实现  
  
加密函数依次调用AesEncrypt，它使用带有输出反馈 (OFB) 模式的 AES-256 加密：  
  
```
// NOTE: has to go with what is considered to be a simplistic in that it omits any
// authentication of the encrypted data.
// Person with better knowledge is welcomed to improve it.
// sourced from https://golang.org/src/crypto/cipher/example_test.go

var emptySalt []byte = make([]byte, 0)

// AesEncrypt reads from input, encrypts with AES-256 and writes to the output.
// passphrase is used to generate an encryption key.
func AesEncrypt(input io.Reader, output io.Writer, passphrase []byte) error {
  // making a 32 bytes key that would correspond to AES-256
  // don't necessarily need a salt, so just kept in empty
  key, err := scrypt.Key(passphrase, emptySalt, 32768, 8, 1, 32)
  if err != nil {
    return err
  }

  block, err := aes.NewCipher(key)
  if err != nil {
    return err
  }

  // If the key is unique for each ciphertext, then it's ok to use a zero
  // IV.
  var iv [aes.BlockSize]byte
  stream := cipher.NewOFB(block, iv[:])

  writer := &cipher.StreamWriter{S: stream, W: output}
  // Copy the input to the output, encrypting as we go.
  if _, err := io.Copy(writer, input); err != nil {
    return err
  }

  return nil
}
```  
  
  
代码片段 8 – 显示实现  
  
然而，经过仔细检查 AesEncrypt实现，我们发现了几个安全问题：  
- 无加盐：密钥派生函数 (KDF) 不使用加盐。加盐对于防止预计算字典攻击和确保相同密码每次生成不同的密钥至关重要。  
  
- 零 IV：初始化向量 (IV) 设置为零。IV 在 OFB 等模式中至关重要，可确保相同的明文每次加密为不同的密文。  
  
- 没有消息认证：加密数据缺少 HMAC（基于哈希的消息认证码），而 HMAC 对于确保密文的完整性和真实性至关重要。攻击者可以修改密文，而系统无法检测到这种篡改。  
  
我们向 Portainer 报告了此问题，他们在 2.20.2 版本中修复了该问题，并将其编号为CVE-2024-33662。  
  
**危险的组合：Zero IV 和 AES-OFB 模式**  
  
现在让我们关注零 IV 和 AES-OFB 模式的组合。在任何需要它的 AES 模式下使用 NULL IV 都是有风险的，但在 OFB 模式下使用时尤其危险。为什么？  
  
让我们来看看：  
  
使用 AES 加密时，不同的加密模式定义了如何使用分组密码将明文块转换为密文。不同的模式提供不同的属性和安全级别。  
  
输出反馈 (OFB) 模式是一种流密码模式，要求每个加密会话都有一个唯一且不可预测的 IV。如果 IV 不唯一（例如 IV 为零的情况），则相同的明文块将始终加密为相同的密文块（图 9），这使其容易受到重放攻击和模式分析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taeAthc8s9As0y7jZpK7V0fcSWJEfbiaprWvY33diamgpM9ZgxV3UO3iawlaPiaGFqzVasIR18M1NecuPg/640?wx_fmt=webp&from=appmsg "")  
  
图 9 – 加密相同的文本会产生相同的加密流  
  
加密过程涉及生成独立于明文的密钥流（IV + 密钥/密码），然后将其与明文进行异或运算以生成密文（图 10）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/rWGOWg48taeAthc8s9As0y7jZpK7V0fcTLzb4zHB87ox9u57qzxUWL8gl9yo74FKeU1ibDzI3kFNfdpRG69ibplA/640?wx_fmt=webp&from=appmsg "")  
  
图 10 – 来自Wikipedia的 OFB 实现  
  
这种类似流密码的行为具有独特含义：  
  
如果使用相同的密钥和 IV，则任何明文都会生成相同的密钥流。这会带来很大的安全风险，因为如果使用相同的密钥和 IV 加密不同的明文，则生成的密文会显示出模式或相似之处，使攻击者更容易推断出原始数据或发起其他加密攻击。  
  
让我们检查一下当我们使用相同密钥流对使用 AES-OFB 加密的两个密文进行异或时会发生什么。  
  
鉴于：  
- c1——使用密钥流k得到的明文p1对应的密文。  
  
- c2——使用密钥流k得到的明文p2对应的密文。  
  
加密过程可以描述为：  
- c1 = p1 ⊕ k  
  
- c2 = p2 ⊕ k  
  
其中⊕表示XOR运算。  
  
如果我们对两个密文c1和c2进行异或运算：  
- c1 ⊕ c2 = ( p1 ⊕ k ) ⊕ ( p2 ⊕ k )  
  
利用 XOR 的结合律和交换律的性质：  
- c1 ⊕ c2 = p1 ⊕ k ⊕ p2 ⊕ k  
  
由于 k ⊕ k = 0（对任何值与其自身进行异或运算都会得出零）：  
- c1 ⊕ c2 = p1 ⊕ p2 ⊕ ( k ⊕ k )  
  
- c1⊕c2=p1⊕p2⊕0  
  
- c1⊕c2=p1⊕p2  
  
因此，当我们对两个密文c1和c2进行异或运算时，我们得到两个明文p1和p2的异或运算：  
- c1⊕c2=p1⊕p2  
  
- 这一结果凸显了使用 OFB 模式对多个明文使用静态密钥流时的潜在漏洞。如果攻击者知道或可以猜出某个明文的某个部分（比如p1），他们可以使用 c1⊕c2 推断出p2的部分内容。  
  
因此，对每个加密操作使用唯一的密钥流非常重要。通常，这是通过对每个加密流使用唯一的 IV 来实现的，以确保密钥流不同 — 即使密钥保持不变。  
  
**CodeQL 查询查找不安全的 AES-OFB**  
  
据我们所知，这种模式并未被“常用”的 CodeQL 查询所涵盖，因此我们决定编写两个可以找到类似漏洞的查询。虽然这些查询可能包含一些可以改进的误报，但我们发现它们目前已经足够了。  
  
如果您不熟悉 CodeQL，编写查询一开始可能会很困难。不过，有几种资源可以帮助您完成此过程：  
- 在 CodeQL Slack 社区中提问（特别感谢 GitHub 的 Owen Mansel-Chan，他帮助我们编写查询）  
  
- ChatGPT  
  
- Visual Studio 中的 CodeQL“快速评估”功能  
  
- CodeQL教程和代码示例  
  
**查找空盐的查询**  
  
我们要构建的第一个查询将使用空盐来查找实例（代码片段 9）：  
  
```
var emptySalt []byte = make([]byte, 0)

func AesEncrypt(input io.Reader, output io.Writer, passphrase []byte) error {
    key, err := scrypt.Key(passphrase, emptySalt, 32768, 8, 1, 32)
```  
  
  
代码片段 9 – AesEncrypt 调用 scrypt.Key  
  
查询通过查找作为第二个参数传递给 scrypt.Key 的空字节数组来实现其目的，对应于 salt 参数（emptySalt）。  
  
在 CodeQL 中，我们可以创建路径查询来直观地展示信息如何通过代码库从一个函数流向另一个函数。这些查询对于分析数据流特别有用，因为它们会跟踪变量从其潜在起点（源）到其可能终点（接收器）的旅程。要对这些路径进行建模，我们的查询必须指定源、接收器以及连接它们的中间数据流步骤。  
  
我们使用谓词（其行为类似于函数，接受输入并返回结果）来定义源和接收器。我们首先实现isSource谓词来识别所有空字节数组：  
  
```
predicate isSource(DataFlow::Node source) {
  exists(DataFlow::CallNode cn, CallExpr ce |
    ce = cn.getExpr() and
    ce.getTarget() = Builtin::make() and
    ce.getArgument(0).getType().(SliceType).getElementType() = Builtin::byte().getType() and
    ce.getArgument(1).getIntValue() = 0 and
    source = cn.getResult()
  )
}
```  
  
  
代码片段 10 – CodeQL isSource  
  
让我们讨论一下关键点：  
- ce.getTarget() = Builtin::make()：遍历所有函数调用并检查它们是否是内置的 Go“make”函数——一个在 Go 中初始化切片的函数。  
  
- ce.getArgument(0).getType().(SliceType).getElementType() = Builtin::byte().getType():确保第一个参数是字节切片。  
  
- ce.getArgument(1).getIntValue() = 0：检查第二个参数是否为值为 0 的整数（空数组）。  
  
我们可以通过包含通过包装函数初始化emptySalt变量的情况来改进它。  
  
第二个谓词 ( isSink ) 标识使用空字节数组（来自isSource谓词）作为 salt 参数调用scrypt.Key函数的位置：  
  
```
predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode cn |
      cn.getTarget().hasQualifiedName("golang.org/x/crypto/scrypt", "Key") and
      sink = cn.getArgument(1)
   )}
}
```  
  
  
代码片段 11 – CodeQL isSink  
  
谓词isSink详细信息：  
- cn.getTarget().hasQualifiedName(“golang.org/x/crypto/scrypt”, “Key”)：查找所有调用scrypt.Key函数的实例。  
  
- sink = cn.getArgument(1):将sink绑定到scrypt.Key函数调用的第二个参数（salt 参数）。  
  
最终的查询是：  
  
```
module FlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(DataFlow::CallNode cn, CallExpr ce |
      ce = cn.getExpr() and
      ce.getTarget() = Builtin::make() and
      ce.getArgument(0).getType().(SliceType).getElementType() = Builtin::byte().getType() and
      ce.getArgument(1).getIntValue() = 0 and
      source = cn.getResult()
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode cn |
      cn.getTarget().hasQualifiedName("golang.org/x/crypto/scrypt", "Key") and
      sink = cn.getArgument(1)
   )}
}

module Flow = DataFlow::Global;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where
  Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "Empty salt in scrypt call"
```  
  
  
代码片段 12 – CodeQL 查询查找空盐  
  
**查找空 IV 的查询**  
  
我们将要构建的第二个查询将搜索在cipher.NewOFB中使用空 IV 的实例（代码片段 13）：  
  
```
var iv [aes.BlockSize]byte
stream := cipher.NewOFB(block, iv[:])
```  
  
  
代码片段 13 – 使用空 IV 调用 OFB 模式  
  
查询通过查找作为第二个参数传递给cipher.NewOFB 的字节数组来实现此目的，该字节数组对应于 IV 字节数组。  
  
正如我们在上一个查询中所做的那样，我们首先实现isSource谓词来识别所有ArrayType变量的声明：  
  
```
predicate isSource(DataFlow::Node source) {
  exists(Type type, ArrayTypeExpr ate, Expr arrayElementTypeExpr |

    arrayElementTypeExpr = ate.getElement() and
    type instanceof ArrayType
  )
}
```  
  
  
代码片段 14 – CodeQL isSource  
  
谓词isSource详细信息：  
- arrayElementTypeExpr = ate.getElement()：获取数组类型列表。  
  
- type instanceof ArrayType：确保所检查的类型确实是数组类型。  
  
第二个谓词（isSink ）标识使用空字节数组（来自isSource谓词）作为IV参数调用cipher.NewOFB函数的位置：  
  
```
predicate isSink(DataFlow::Node sink) { 
  exists(DataFlow::CallNode cn | 
    cn.getTarget().hasQualifiedName("crypto/cipher", "NewOFB") and 
    sink = cn.getArgument(1) 
  )} 
}
```  
  
  
代码片段 15 – CodeQL isSink  
  
谓词isSink详细信息：  
  
- cn.getTarget().hasQualifiedName(“crypto/cipher “, “NewOFB”)：查找所有 cipher.NewOFB 函数调用。  
  
- sink = cn.getArgument(1)：将 sink 绑定到 cipher.OFB 函数调用的第二个参数（IV 参数）。  
  
最后，完整的查询如下：  
  
```
module FlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) {
    exists(Type type, ArrayTypeExpr ate, Expr arrayElementTypeExpr |
      arrayElementTypeExpr = ate.getElement() and
      type instanceof ArrayType
    )
  }

  predicate isSink(DataFlow::Node sink) {
    exists(DataFlow::CallNode cn |
      cn.getTarget().hasQualifiedName("crypto/cipher", "NewOFB") and
      sink = cn.getArgument(1)
   )}
}

module Flow = DataFlow::Global<FlowConfig>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where
  Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "Empty IV in NewOFB call"
```  
  
  
代码片段 16 – CodeQL 查询查找空 IV  
  
**最终见解**  
  
在这篇博文中，我们研究了 Portainer 中发现的两个漏洞。第一个漏洞是通过 CodeQL 发现的，是/api/templates/helm端点中的盲 SSRF 漏洞。  
  
通过手动静态分析发现的第二个漏洞是备份功能中不安全的 AES-OFB 实现，其中加密过程缺乏必要的安全措施，例如加盐、适当的初始化向量 (IV) 和 HMAC，从而使备份文件暴露于潜在的攻击。  
  
这些发现强调了严格的安全实践的重要性，尤其是在用于管理 Portainer 等敏感基础设施的工具中。通过利用 CodeQL 并通过自定义查询增强 CodeQL，安全研究人员/开发人员可以系统地发现和解决漏洞，从而为更安全、更可靠的软件生态系统做出贡献。  
  
**披露时间表**  
  
2024 年 2 月 13 日——向 Portainer 提交有关两个盲 SSRF 漏洞的初步报告；他们在同一天承认并创建了一个内部跟踪 ID：EE-6722。  
  
2024 年 2 月 20 日——向 Portainer 提交有关易受攻击的 AES-OFB 实施的初步报告。  
  
2024 年 2 月 21 日——Portainer 承认存在易受攻击的 AES-OFB 实施并创建了内部跟踪 ID：EE-6764。  
  
2024 年 2 月 22 日——Portainer 修复了盲 SSRF（EE-6764），但尚未发布。  
  
2024 年 3 月 3 日——我们要求对盲 SSRF 漏洞进行更新。  
  
2024 年 3 月 4 日——Portainer 答复说，盲 SSRF 漏洞的修复将在下一个 Portainer 版本中包含。  
  
2024 年 3 月 19 日-Portainer 发布了 2.20.0 版本，修复了盲 SSRF（分配有CVE-2024-33661）。  
  
2024 年 3 月 26 日——我们要求对这两个漏洞进行更新；Portainer 在同一天答复说，盲 SSRF（EE-6722）已在最新的 Portainer 版本 2.20 中修复，EE-6764 计划在 2.20.x Point 版本中修复。  
  
2024 年 5 月 1 日——Portainer 发布 2.20.2 版本，修复了存在漏洞的 AES-OFB 实现（分配有CVE-2024-33662）。  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
