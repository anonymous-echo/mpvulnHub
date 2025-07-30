#  Azure 机器学习服务上已验证的 SSRF 漏洞   
枇杷五星加强版  黑伞安全   2023-06-27 18:03  
  
## 我们如何发现 SSRF 漏洞  
  
  
首先，我们通过https://ml.azure.com  
端点在 Azure 机器学习服务中创建了一个新工作区  
–  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGp9U96DdBbTIjzVElRNbSRZykGOIomLHyaZwcqPRa7oQLuWJBgU5CvZzgErVGW0elWrqLc6LzWskg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGp9U96DdBbTIjzVElRNbSRZGpw4mSK6NUOVUzb33zckibkyG3EwR8AIlCX63CSQGcv5qNan0Cq6Ifw/640?wx_fmt=png "")  
  
创建后，我们导航到“数据”  
仪表板，将各种资产上传到我的工作区。  
我们单击左侧窗格菜单中的数据仪表板，然后选择“创建”  
 -  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGp9U96DdBbTIjzVElRNbSRZRhMR1Riaic6q3GQIIzSQYlRia4j8qMe0EYDxD3vTXaYicR7WEQ8icyjz8TQ/640?wx_fmt=png "")  
  
在 Create Data asset Wizard 中，我们为新资产命名并选择 File(uri_file) 并点击 Next。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGp9U96DdBbTIjzVElRNbSRZ5oQGetzASSic3OEPad2icBQwymSUzhLcO2KYGE8fYibDltzia2gNE1G3Fg/640?wx_fmt=png "")  
  
我们继续选择“来自 URI”以上传我新指定的文件 –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGp9U96DdBbTIjzVElRNbSRZtLx1b5ZsL6xNicN2zpb0h2icub9C063FKD6NxkPzUibjxhBQcPAFJHQuQ/640?wx_fmt=png "")  
  
然后，我们指定了一个示例 HTTPS 端点（也可以是 HTTP）并点击下一步（在此之前我们切换了“跳过数据验证  
”——  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGp9U96DdBbTIjzVElRNbSRZamOknw6xBCdUWxL0gIoPTribx1c5xAbicXLugmibvQKF2ia01EvQ9dVrTQ/640?wx_fmt=png "")  
  
最后我们点击“创建”——  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGp9U96DdBbTIjzVElRNbSRZaRe24lLRYHU8EoZEtjqicA6rshicJVmEpLCA0BdgD7nofPTqYNKF1fqw/640?wx_fmt=png "")  
  
在点击 Create 之前，我们确保我的 Intercept 设置为 ON –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGp9U96DdBbTIjzVElRNbSRZVlUloWgxzc1MpUZyNnfPHMTG7byteH4hNKibpLSbzH3sadKeXFFUXJg/640?wx_fmt=png "")  
  
我们看到第一个请求是  
/saveddatasets/tieredpreview。  
   
我们寻找进一步的请求。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGp9U96DdBbTIjzVElRNbSRZ5WJULNoiac6VRQicU9NpXbJm7yguFenPNmBWBPgXFS2DzVEfNafQk5Qg/640?wx_fmt=png "")  
  
第二个请求是 – https://ml.azure.com/api/eastus2/data/v2.0/subscriptions/5cd1****-****-****-****-** ******c611/resourceGroups/lidor-rg/providers/Microsoft.MachineLearningServices/workspaces/ssrf/datacall/preview  
  
  
此请求正在通过/datacall/preview 传递。与我接下来将重点关注的流内容端点类似，预览端点在其响应中使用“路径”+“文件名”方案 -  
  
  
虽然  
流内容  
使用了“路径+内容”模式——  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGp9U96DdBbTIjzVElRNbSRZubyia2ibBia1C3rdqD08Gh0zntNfzy4yARjlypnkpdZuLh6pceCRmsSRQ/640?wx_fmt=png "")  
  
通过的最终端点是  
/datacall/streamcontent?streamInfoColumnName=Path&maxBytes=5000000  
  
我们可以看到发送的 POST 请求包含以下正文 -  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGp9U96DdBbTIjzVElRNbSRZWcfNF2hC1ntOAjJySLZcDwmM0uic1XPibFfzUb2QgNdjoarQWy3kEztg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGp9U96DdBbTIjzVElRNbSRZ3SPeRhxIVnVr8wUGJ76BBeclaSRAMFUQJSISOXEZGsg4MUaIwQjCMg/640?wx_fmt=png "")  
  
然后我们可以删除所有不相关的参数，除了“   
dataUri  
 ”——  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGp9U96DdBbTIjzVElRNbSRZ3H6ojWERr6VUaNQWkHRppbxv0wI1Hf3IXfnP5w7qzY9j6OFHZMq2eQ/640?wx_fmt=png "")  
  
我向服务器发送了上面的请求，并收到了下面的响应——  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGp9U96DdBbTIjzVElRNbSRZ6lAiagP8twIstwXDhz47SiczmnM88QGd96y0347RoZTBxXpKAJaXyHlw/640?wx_fmt=png "")  
  
响应内容是 Base64 格式，所以我们对其进行了解码——  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGp9U96DdBbTIjzVElRNbSRZkXDfbPyG4icue18flHf8NwFrbzRiaBE9CPVQKPtPKPzgO0IyUIAH7bXw/640?wx_fmt=png "")  
  
我们向https://orca.security  
端点发送了一个新请求  
——  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGp9U96DdBbTIjzVElRNbSRZOIIOujZcoQSjxrI5oFnG4XnLzygHuCqoiaZXtfXKxX52f1ia7rKpUX7A/640?wx_fmt=png "")  
  
再一次，解码响应为我们提供了网站的内容——  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGp9U96DdBbTIjzVElRNbSRZK1iaRVgFaRUBnzkkBjcW4AwKNibIQmujbib0r10Rjs9HLMlDt4PMFD4PQ/640?wx_fmt=png "")  
  
从上面的 base64 解码可以看出，我们能够通过 SSRF 漏洞检索任何端点。  
  
  
