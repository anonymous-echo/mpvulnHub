#  调用 KIMI AI 进行自动化越权漏洞检测的工具 -- PrivHunterAI   
Ed1s0nZ  Web安全工具库   2025-01-27 16:01  
  
===================================  
  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除，建议虚拟机运行。个人微信：ivu123ivu  
  
0x01 工具介绍  
利用工作之余（摸鱼）时间花 2 小时完成的小工具，简易版支持通过被动代理调用 KIMI AI 进行越权漏洞检测，检测能力依赖 KIMI API 实现。目前功能较为基础，尚未优化输出，也未加入扫描失败后的重试机制等功能。  
  
0x02 安装与使用  
  
一、工作流程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsyjclcHTLnhoGhFiaDoPlSyPBBcLPNatW1ffibDOWvLJ16hQFvSu9ZFdEmosK2EibxcobtvhMal0zUQ/640?wx_fmt=png&from=appmsg "")  
  
二、提示词  
```
{
    "role": "你是一个AI，负责通过比较两个HTTP响应数据包来检测潜在的越权行为，并自行做出判断。",
    "inputs": {
      "responseA": "账号A请求某接口的响应。",
      "responseB": "将响应A中的Cookie替换为账号B的Cookie后，重放请求得到的响应。"
    },
    "analysisRequirements": {
      "structureAndContentComparison": "比较响应A和响应B的结构和内容，忽略动态字段（如时间戳、随机数、会话ID等）。",
      "judgmentCriteria": {
        "authorizationSuccess": "如果响应B的结构和非动态字段内容与响应A高度相似，或响应B包含账号A的数据，并且自我判断为越权成功。",
        "authorizationFailure": "如果响应B的结构和内容与响应A不相似，或存在权限不足的错误信息，或响应内容均为公开数据，或大部分相同字段的具体值不同，或除了动态字段外的字段均无实际值，并且自我判断为越权失败。",
        "unknown": "其他情况，或无法确定是否存在越权，并且自我判断为无法确定。"
      }
    },
    "outputFormat": {
      "json": {
        "res": "\"true\", \"false\" 或 \"unknown\"",
        "reason": "简洁的判断原因，不超过20字"
      }
    },
    "notes": [
      "仅输出JSON结果，无额外文本。",
      "确保JSON格式正确，便于后续处理。",
      "保持客观，仅根据响应内容进行分析。"
    ],
    "process": [
      "接收并理解响应A和响应B。",
      "分析响应A和响应B，忽略动态字段。",
      "基于响应的结构、内容和相关性进行自我判断，包括但不限于：",
      "- 识别响应中可能的敏感数据或权限信息。",
      "- 评估响应与预期结果之间的一致性。",
      "- 确定是否存在明显的越权迹象。",
      "输出指定格式的JSON结果，包括判断和判断原因。"
    ]
  }
```  
  
三、使用方法  
  
1、下载源代码；  
  
2、编辑config.go文件，配置apiKey（Kimi的API秘钥） 和cookie2（响应2对应的cookie），可按需配置suffixes（接口后缀白名单，如.js）；  
  
3、go build编译项目，并运行二进制文件；  
  
4、BurpSuite 挂下级代理 127.0.0.1:9080（端口可在mitmproxy.go 的Addr:":9080", 中配置）即可开始扫描。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsyjclcHTLnhoGhFiaDoPlSyFRsC0coWRsCiaXI2GShchodic2ZPM6u2azibpzepic8ApgMg2icpV8qybmA/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
**·****今 日 推 荐**  
**·**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsyjclcHTLnhoGhFiaDoPlSy8IXfgZOsFvNVzP8qPsxRsiclB7UiciciaGJpohL3622rRo7DtsBF5ue1qg/640?wx_fmt=png&from=appmsg "")  
  
  
