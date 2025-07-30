#  GitHub MCP Server漏洞：通过MCP访问私有仓库   
 玄月调查小组   2025-05-28 11:10  
  
TL;DR  
  
Invariant近日发现了https://github.com/github/github-mcp-server的一个注入漏洞。攻击者可以通过创建恶意Issue劫持agent，从而泄露私有仓库数据。  
  
攻击场景  
  
用户拥有两个权限不同的仓库：  
- /public-repo：公开仓库，允许所有GitHub用户创建issue和bug报告  
  
- /private-repo：私有仓库（包含专有代码或公司数据）  
  
攻击者可在公开仓库创建含提示注入的恶意issue。用户使用Claude Desktop等MCP客户端并连接了GitHub MPC Server进行常规查询（如"查看public-repo的未解决issue"）时，agent获取issue内容即会触发注入攻击。如图所示，agent获取恶意issue后，会被诱导提取私有仓库数据，并通过自动创建的PR泄露至公开仓库。  
  
![](https://mmbiz.qpic.cn/mmbiz_svg/cGNScwnYvk5ic3J8YcQuyyC4zq7hg2oWwEtHR9KOYspk3CbX26fyibc7KJn79TVsNwAhFTg1X3camk5Nxvcp9NA8yWeZk4j4M5/640?wx_fmt=svg&from=appmsg "")  
  
攻击演示  
  
Invariant在github上创建了以下仓库  
- ukend0464/pacman（公开仓库）：  
https://github.com/ukend0464/pacman  
  
- 多个包含用户私密信息的私有仓库  
  
通过在公开仓库插入恶意issue：  
  
https://github.com/ukend0464/pacman/issues/1  
  
![A malicious GitHub issue injecting the agent](https://mmbiz.qpic.cn/sz_mmbiz_png/sQCvOetlPW3IVH2feMAU8nzEsSUg2JWxfa2sMaaibRg8AJbvg6cjtTC8uuEbmPySV6fXSWXHd0TfCcwBkx0tKog/640?wx_fmt=png&from=appmsg "")  
  
当用户要求Claude 4 Opus处理公开仓库issue时，agent会执行issue里注入的指令，并将私有仓库里的敏感信息提交到公开库的pr中，导致信息泄露。  
  
![commit where the agent leaks private data](https://mmbiz.qpic.cn/sz_mmbiz_png/sQCvOetlPW3IVH2feMAU8nzEsSUg2JWxQx9AYnhBZLkaNticYIQ8nf4E13tiaBdbvpyVVWk0vTRQkibG7kkI8ORFw/640?wx_fmt=png&from=appmsg "")  
  
  
  
