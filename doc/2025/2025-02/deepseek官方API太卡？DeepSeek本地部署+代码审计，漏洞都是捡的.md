#  deepseek官方API太卡？DeepSeek本地部署+代码审计，漏洞都是捡的   
安全透视镜  网络安全透视镜   2025-02-06 03:19  
  
废话不说，先上效果图，有图有真相。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7yslyrhPsLbiamfbzPcreW7UdV8wib8Bam5SKmh5Y3WwibOCoU1PrRzf1dibyn94cYKNA8VR1eKtB80g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7yslyrhPsLbiamfbzPcreW7M1bxeyHLtTlVnW2AOK4JVEYMKVia6HjSOkDRAhsULXViaYv8apx33Nhg/640?wx_fmt=png&from=appmsg "")  
  
deepseek火了之后，诞生了很多相关的行业应用场景。这两天也有人尝试使用deepseek进行代码审计。但是官方的API实在太卡。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7yslyrhPsLbiamfbzPcreW7qUicbEqQudj9M7qwszTXWeVs12M8qYSKjl9hwtJf9SQGN19t2mk5uWw/640?wx_fmt=png&from=appmsg "")  
  
今天就给大家分享一个可离线的代码审计工具。**工具包，见文末**  
  
**deepseek部署**  
  
本地deepseek部署还是使用Ollama方案，部署方式很简单，可以参考我昨天发的文章  
  
**DeepSeek 本地部署**  
  
这里需要说一下，要根据自己本地电脑的配置选择不同参数的模型，对于有独显的电脑，部署8b模型应该是没问题的。性能好一点的可以尝试14B，甚至32B模型。  
  
这里我的电脑i9-14900HX，32G内存，4060 8G显存。 运行8B参数毫无压力，不到十分钟出结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7yslyrhPsLbiamfbzPcreW779PtP4daBeicycdQDzoOa7JdIGN5aNgfAWL9kyhTqoe2pVDW5b6Jn6w/640?wx_fmt=png&from=appmsg "")  
  
但是运行14B就卡了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7yslyrhPsLbiamfbzPcreW7jsorib0uMTuTicWnDq5KIHknwIxy1PPibPsqfLvT87ANbxBZLRcJ4FMlg/640?wx_fmt=png&from=appmsg "")  
  
使用Ollama方案部署deepSeek，大家也可以尝试无道德限制的deepseek模型。  
  
8B模型下载  
```
ollama run huihui_ai/deepseek-r1-abliterated:8b
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7yslyrhPsLbiamfbzPcreW7iaG9uv4P7ibibuJd9Gibf1ZmzhgG306577GqKEedSxDCXjZ1mujUePOYqA/640?wx_fmt=png&from=appmsg "")  
  
14B模型下载  
```
ollama run huihui_ai/deepseek-r1-abliterated:14b
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7yslyrhPsLbiamfbzPcreW7ExUy2rnwz8eiaVIzusR7V3MOeQfTJ3CibQxeXRS4SQabZ0Ns8A8k53zA/640?wx_fmt=png&from=appmsg "")  
  
  
**AI代码审计工具的使用**  
  
解压后双击运行 秋风AI代码审计.exe  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7yslyrhPsLbiamfbzPcreW73vGXmMPiaGzYQultz8ITPUiaDnvsYO729og9BXsF6P6Nw9FSuKibibZibTg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7yslyrhPsLbiamfbzPcreW7JicdZjtc77jKUO27XWl1MpXL3ByHP1MpZaFVjc4USGpeQkh5rOgCvjA/640?wx_fmt=png&from=appmsg "")  
  
打开后默认使用在线模式，点击设置-->可选择在线或者离线模式  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7yslyrhPsLbiamfbzPcreW7BaOQGQ7t2nibqsAHyzShn5nxMUOEInaJ2Y5lbnfJib0Vbk7sWogicaxOQ/640?wx_fmt=png&from=appmsg "")  
  
在线模式需要填写deepseek API地址以及key。  
  
离线模式需要填写模型名称，然后保存，即可。  
  
注意：这里填的模型名称，需要和Ollama里面运行的模型保持一致。  
  
可使用命令ollama list查看本地模型，ollama run [xxx模型], 然后填写当前运行的模型即可。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7yslyrhPsLbiamfbzPcreW7zKfjJoqwibNQwO94c7PSiczTXIn6PFc60HCgJR4mxFVrGqSfUoOzZ48Q/640?wx_fmt=png&from=appmsg "")  
  
**上传源码审计******  
  
保存配置后，左上方 文件-->打开文件，上传代码文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7yslyrhPsLbiamfbzPcreW7QL30C069xIVHiaNlLibQR4kibMuttskDI9Qu9MzibQBJibVPkAeHKkjfHdw/640?wx_fmt=png&from=appmsg "")  
  
  
这里还需要注意一下，因为很多人电脑性能有限，如果配置低，可以将项目中文件夹分开上传，不要全部上传。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7yslyrhPsLbiamfbzPcreW7RtMItWf8mlMGStsJVuZS423dydeWEtxCQrRHPib95RCGDvk7HA8yo7g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7yslyrhPsLbiamfbzPcreW7hyEezb9yicWCsd3k0qfxlq8bdpSMY32Ds0Flyl4wUzN7uhwlLBO3gwg/640?wx_fmt=png&from=appmsg "")  
  
****Ollama对CPU的资源占用还是挺多的。可以发现使用16B的模型，会卡死，跑一天可能也没有结果。还是建议大家选择适合自己本地电脑配置的模型，不要选大了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7yslyrhPsLbiamfbzPcreW7x9kHmltkbYAVP1Aruvla6NLeo8BvFFmtrc6L0YDQw2OhIP7NrNr12Q/640?wx_fmt=png&from=appmsg "")  
  
使用8B模型就很轻松了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7yslyrhPsLbiamfbzPcreW7jQicX6t6L3G9b7rEp6SsSZVfIhnQSj2SKbUKvTBV9v26DImvjMt9NHg/640?wx_fmt=png&from=appmsg "")  
  
分分钟出漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS7yslyrhPsLbiamfbzPcreW7p3Myo3ic0GSnTDzm3KhSSibcj4NKibIcz82A7dm1FxxUh8icnC6DsuUC6Q/640?wx_fmt=png&from=appmsg "")  
  
  
  
关注微信公众号：网络安全透视镜 回复  **deepseek代码审计**  
 即可获得相关工具  
  
  
  
