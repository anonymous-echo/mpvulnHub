#  使用deepseek进行代码审计漏洞挖掘？   
_7ingLian  偏远酒馆   2025-02-06 06:32  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcpYmfRrkHqtZOoLY55mXZWJ16u05arbB1jib4WwY60DN8u3RHWfgYZ3SsSfawBzxkwzjPyb1WibH0og/640?wx_fmt=png&from=appmsg "")  
  
  
--->目录<---  
  
  
0x01——前言  
  
0x02——  
deepseek-r1、  
deepseek-coder-v2  
大模型本地部署  
  
0x03——deepseek-r1、  
deepseek-coder-v2、  
llama3.1在代码审计上的效果  
  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><td data-colwidth="576" width="576" valign="top" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgb(76, 76, 76);max-width: 100%;box-sizing: border-box !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 255, 255);font-size: 14px;letter-spacing: 0.544px;text-decoration-style: solid;text-decoration-color: rgb(255, 255, 255);visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span textstyle="" style="background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);">0x01、</span></span><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;letter-spacing: 0.544px;text-decoration-style: solid;text-decoration-color: rgb(255, 255, 255);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;letter-spacing: 0.544px;text-decoration-style: solid;text-decoration-color: rgb(255, 255, 255);visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 255, 255);font-size: 14px;letter-spacing: 0.544px;text-decoration: none solid rgb(255, 255, 255);visibility: visible;"><span leaf=""><span textstyle="" style="background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);">前言</span></span></span></span></strong></span></strong></span></td></tr></tbody></table>  
--->  
由于2024年年底写了个框架，直接可以调用ollama的大模型进行单个文件或者框架压缩包进行分析。最近发现deepseek在ollama网站有了更新。想来看下能否将其直接用来进行漏洞挖掘。  
  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><td data-colwidth="576" width="576" valign="top" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgb(76, 76, 76);max-width: 100%;box-sizing: border-box !important;visibility: visible;"><section><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span textstyle="" style="font-size: 14px;background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);">0x02、</span></span><strong><strong><span leaf=""><span textstyle="" style="font-size: 14px;background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);">deepseek-r1、</span></span><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(255, 255, 255);font-size: 14px;letter-spacing: 0.544px;text-decoration-style: solid;text-decoration-color: rgb(255, 255, 255);visibility: visible;text-decoration: none solid rgb(255, 255, 255);"><span textstyle="" style="font-size: 14px;background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);">deepseek-coder-v2</span></span><span leaf=""><span textstyle="" style="font-size: 14px;background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);">大模型本地部署</span></span></strong></strong></section></td></tr></tbody></table>  
  
--->  
  
**这里说DeepSeek的第一代推理模型与OpenAI-O1相当**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcp305lfiaAs665CEMTngzUlvQHWy284sia9CSiaHIeaZS0q1kCqn5nbMjEFZ8keVELpJcsiaXgndjKS5Q/640?wx_fmt=png&from=appmsg "")  
  
****  
  
这是ollama网站上的新模型展示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcp305lfiaAs665CEMTngzUlvvKBJbLgHLeu2SYg9Qd6pqDCgOicBOibibHbeQH9xcE8xqOaq6tP6EHFGw/640?wx_fmt=png&from=appmsg "")  
  
  
为了方便比较在代码上的效果，直接将  
deepseek-r1和deepseek-coder-v2模型下载下来  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcp305lfiaAs665CEMTngzUlvYThgB2rIk8WFH52ibKPMlv155aUScfndEZJJgOV5rkzoiajiabtMPZoVQ/640?wx_fmt=png&from=appmsg "")  
  
大模型下载完成  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcp305lfiaAs665CEMTngzUlvpReFjskHw2GUyVEXibLWyaosk214sLgCKFwEA8BvcbViawbMd0yKVZdA/640?wx_fmt=png&from=appmsg "")  
  
我们将对下面三个模型进行简单的比较，目的是选择合适的模型来使用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcp305lfiaAs665CEMTngzUlvhZlSz9dSaluYkHTIf1eic5CGYhlicmVxiclBh8qtBzR5UibTldgjtBwic8w/640?wx_fmt=png&from=appmsg "")  
  
再看一眼deepseek-r1的声明  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcp305lfiaAs665CEMTngzUlvWAfJLza8qFo960FicMzpzB49YqGzM7FFqibdpVIbCMF6PicvCSImFVO5Q/640?wx_fmt=png&from=appmsg "")  
  
deepseek-coder-v2也是开源模型。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcp305lfiaAs665CEMTngzUlvL5pMgqiaS4uGX2es9ABibYCDv3a7lzHlIcAU0ibdHKvUxKor6p0D6ILbQ/640?wx_fmt=png&from=appmsg "")  
  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><td data-colwidth="576" width="576" valign="top" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 1px solid rgb(76, 76, 76);max-width: 100%;box-sizing: border-box !important;visibility: visible;"><section><span leaf=""><span textstyle="" style="font-size: 14px;background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);">0x03、</span></span><strong><strong><span leaf=""><span textstyle="" style="font-size: 14px;background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);">deepseek-r1、</span></span><span leaf=""><span textstyle="" style="font-size: 14px;background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);">deepseek-coder-v2、</span></span><span leaf=""><span textstyle="" style="font-size: 14px;background-color: rgb(255, 255, 255);color: rgb(255, 76, 0);">llama3.1在代码审计上的效果</span></span></strong></strong></section></td></tr></tbody></table>  
  
**--->**  
  
**简单对比三个模型，deepseek-coder-v2在代码审计应用上也是不错的。**  
  
****  
  
上传一个简易的框架压缩文件，让三个模型进行分析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcp305lfiaAs665CEMTngzUlvj0zzeTwfvvyK9sGajRocE2qnVibwSIxJpOd4E0l63DczBsAMRCOMP5g/640?wx_fmt=png&from=appmsg "")  
  
相同的提示词，看结果有什么不一样。(我的要求是找出漏洞，找出可控点、给出漏洞出现的位置、给出payload、给出修复建议)  
  
这台电脑没有GPU，我直接用CPU跑。  
  
  
先来看下llama3.1大模型的效果  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcp305lfiaAs665CEMTngzUlv0zdDu8zVmhibdAhTJ3S1YHwZeG86iaSRPpynxOiaWMD9MHoarxibiae2ibtg/640?wx_fmt=png&from=appmsg "")  
  
表现还是不错的，没有出现反骨行为。给出了详细的漏洞位置和payload等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcp305lfiaAs665CEMTngzUlvqXzGVLLhzBtjxLeqsYxTuuxibd9FEl2UKlCpQCKmTQ742y67DLGuBkQ/640?wx_fmt=png&from=appmsg "")  
  
再来看下deepseek-coder-v2的效果，也算不错。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcp305lfiaAs665CEMTngzUlvAJmVZEFcbiaic7yLZIaTGerUpHicJlLumnd5Qu6lHxWauw6vY2L23Wrrg/640?wx_fmt=png&from=appmsg "")  
  
反观deepseek-r1，它没有理会提示词，只是自顾自的说了一堆。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6ibqWGD93gcp305lfiaAs665CEMTngzUlv2iaLcCLe2KCEUoTpWkjqlfDjQRZF3flrXGRXLcIao37sZtL0A7PplRw/640?wx_fmt=png&from=appmsg "")  
  
  
end  
  
