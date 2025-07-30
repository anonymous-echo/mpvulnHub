> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU0NDI5NTY4OQ==&mid=2247486422&idx=1&sn=1950ae508c495b4f902accb605b1908e

#  从0到1大模型MCP自动化漏洞挖掘实践  
原创 比心皮卡丘  暴暴的皮卡丘   2025-07-02 14:45  
  
在传统的渗透测试过程中，信息收集、端口扫描、目录枚举、漏洞探测等步骤通常通过一系列 CLI 工具手动串联完成。工作繁琐、上下文割裂、结果不可组合，是所有红队、SRC 白帽、攻防从业者的痛点。而随着大模型能力的爆发，以及   
  
Model Context Protocol（MCP）  
 的提出，  
我们终于可以用一种结构化的方式，让 LLM 驱动整个渗透工具链，完成自动化漏洞发现。  
  
  
本篇文章将从 0 到 1 带你实现一个   
基于大模型+MCP 协议+开源信息收集工具  
 的自动化漏洞挖掘工具，真正迈入「模型驱动安全工具链」的新时代。  
AI批量刷洞的时代即将来临！！！  
  
   
  
什么是 MCP？  
  
  
Model Context Protocol (MCP)  
 是一种用于连接 LLM 与外部环境（工具、代码、数据等）的开放协议。它通过结构化的上下文定义（Context）与标准接口调用（Function Calls / Tools），允许模型「理解」自身所处的上下文，并「调用」外部能力完成复杂推理与自动化任务。  
<table><tbody><tr><td data-colwidth="552" width="552" valign="top" style="border-top: none;border-left: 2.25pt solid rgb(187, 191, 196);border-bottom: none;border-right: none;padding: 3pt 6pt 1.5pt;"><p style="margin-top:6.0pt;margin-bottom:6.0pt;text-align:left;margin-left:0.0pt;line-height:120%;"><span style="font-size:11.0pt;line-height:120%;font-family:等线;mso-ascii-font-family:Arial;mso-bidi-font-family:Arial;font-variant:normal;text-transform:none;color:#646A73;"><span leaf="">通俗地说，MCP 是一个让 LLM 不再“瞎猜”的机制，它知道自己在看什么，能调用哪些能力，当前任务目标是什么。详细参考https://modelcontextprotocol.io/introduction</span></span><span style="font-family:Times New Roman;mso-ascii-font-family:Times New Roman;mso-fareast-font-family:等距更纱黑体 SC;font-variant:normal;text-transform:none;"></span></p></td></tr></tbody></table>  
   
  
MCP漏洞挖掘实践  
  
  
   
  
ollama本地模型部署  
  
  
访问https://ollama.com/根据自己当前的操作系统选择对应的下载即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLUqDLXMVKTbjFXZf3aLdmuO3gKdQMgmu8tWc1cErrYLRY7aAl3dQ88kNYtWe8eSa7wFrGRC3GCqUA/640?wx_fmt=png "")  
  
下载之后，通过ollama语法进行本地部署，可根据自身性能来选择模型，访问https://ollama.com/search下载模型  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLUqDLXMVKTbjFXZf3aLdmuOju5EbymTezutoF8Zeib4MFGmvcn7AM3cn6ickBYjWQ8r4KLQdIqMZJVg/640?wx_fmt=png "")  
  
ollama语法为  
<table><tbody><tr><td data-colwidth="552" width="552" valign="top" style="background: rgb(245, 246, 247);border-width: 1pt;border-style: solid;border-color: rgb(222, 224, 227);padding: 3pt 6pt 1.5pt;"><p style="margin-top:6.0pt;margin-bottom:6.0pt;text-align:left;line-height:120%;"><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;color:#646A73;"><span leaf="">Bash                  </span><span leaf=""><br/></span></span><span style="font-size:11.0pt;line-height:120%;font-family:Consolas;mso-ascii-font-family:Consolas;mso-fareast-font-family:Consolas;mso-bidi-font-family:Consolas;font-variant:normal;text-transform:none;"><span leaf=""># 显示当前安装的 Ollama 版本                  </span><span leaf=""><br/></span><span leaf="">ollama --version                  </span><span leaf=""><br/></span><span leaf=""><br/></span><span leaf=""># 启动 Ollama 服务，默认监听在 http://localhost:11434                  </span><span leaf=""><br/></span><span leaf="">ollama serve                  </span><span leaf=""><br/></span><span leaf=""><br/></span><span leaf=""># 创建模型                  </span><span leaf=""><br/></span><span leaf="">ollama create</span><model_name><span leaf="">[-f</span><modelfile_path><span leaf="">]           </span><span leaf=""><br/></span><span leaf=""><br/></span><span leaf=""># 查看模型信息           </span><span leaf=""><br/></span><span leaf="">ollama show</span><model_name><span leaf=""><br/></span><span leaf=""><br/></span><span leaf=""># 运行指定的模型            </span><span leaf=""><br/></span><span leaf="">ollama run</span><model_name><span leaf=""><br/></span><span leaf=""><br/></span><span leaf=""># 停止正在运行的模型             </span><span leaf=""><br/></span><span leaf="">ollama stop</span><model_name><span leaf=""><br/></span><span leaf=""><br/></span><span leaf=""># 从注册表中拉取指定的模型              </span><span leaf=""><br/></span><span leaf="">ollama pull</span><model_name><span leaf=""><br/></span><span leaf=""><br/></span><span leaf=""># 将本地模型推送到注册表               </span><span leaf=""><br/></span><span leaf="">ollama push</span><model_name><span leaf=""><br/></span><span leaf=""><br/></span><span leaf=""># 列出所有已下载的模型                </span><span leaf=""><br/></span><span leaf="">ollama list                </span><span leaf=""><br/></span><span leaf=""><br/></span><span leaf=""># 列出所有正在运行的模型                </span><span leaf=""><br/></span><span leaf="">ollama ps                </span><span leaf=""><br/></span><span leaf=""><br/></span><span leaf=""># 将一个模型复制到另一个新命名的模型                </span><span leaf=""><br/></span><span leaf="">ollama cp</span><source_model><destination_model><span leaf=""><br/></span><span leaf=""><br/></span><span leaf=""># 删除指定的模型                  </span><span leaf=""><br/></span><span leaf="">ollama rm</span><model_name></model_name></destination_model></source_model></model_name></model_name></model_name></model_name></model_name></modelfile_path></model_name></span><span style="font-family:Times New Roman;mso-ascii-font-family:Times New Roman;mso-fareast-font-family:等距更纱黑体 SC;font-variant:normal;text-transform:none;"></span><o:page></o:page></p></td></tr></tbody></table>  
本次下载了两个模型，都是热门下载量的模型，其中Deepseek为推理模型，为什么要下载两个模型呢？  
后续会有答案，会让大家意识到不同模型带来的效果很明显不同  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLUqDLXMVKTbjFXZf3aLdmuOy9rJgfSHkeUiaErxjZTUjf4ZQbCfBVZWf9BdJo4L5ibgQpKiaTdpMb8jg/640?wx_fmt=png "")  
  
   
  
   
  
漏洞信息收集及利用工具  
  
  
本次使用到一些经典的渗透测试的开源工具，他山之玉 可以攻石，这里没必要自己实现了，毕竟菜且自知  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLUqDLXMVKTbjFXZf3aLdmuOnUdkDWFs3lGZV84oPicU8Y9uaFuaLaBq8XG4eggY8TkJwZic4hX98DZg/640?wx_fmt=png "")  
  
点击图片可查看完整电子表格  
  
   
  
MCP Server开发  
  
  
使用FastMCP框架进行开发，详细使用方式可参考https://gofastmcp.com/getting-started/welcome，站在巨人的肩膀上可以更省力，能靠别人就别靠自己了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLUqDLXMVKTbjFXZf3aLdmuOzjBRdz8Rx3xFVwZTibfiaVgiajzwxDf95IWn55iczxsicdr9MyAHV1LXlbA/640?wx_fmt=png "")  
  
基于这个开源框架，嘎嘎一顿开发  
  
首先咱们还是比较正规的做一个配置文档，不管三七二十一，代码写得好不好无所谓，最起码要规范  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLUqDLXMVKTbjFXZf3aLdmuO4W40HNU7luaC571p7dibibJowmvwBWH58u9vibRj82jbUmSfuLUgGZaYg/640?wx_fmt=png "")  
  
然后我们封装一个工具管理类，确保所有的工具调用都规范化，这里还是那句话，规范开发很重要（爷们要脸，手动狗头）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLUqDLXMVKTbjFXZf3aLdmuO0MRibQNuHorLcnb3eVRBibwM9QAbvnfp3rEPRUiaicP5BTtgohGl5EpGQA/640?wx_fmt=png "")  
  
之后再使用FastMCP调用起来，这里我们使用任务的方式，对于每一个安全工具每次调用，通过任务来进行，避免部分工具扫描很久，就会无法返回结果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLUqDLXMVKTbjFXZf3aLdmuOwOSKfGAgtKZicmhyDRzFHgFFNUtFjKKQxcB3mFvjZXXGaTeMvPjvCzw/640?wx_fmt=png "")  
  
当然还可以组成一个工具链路实现完整的全自动化  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLUqDLXMVKTbjFXZf3aLdmuOk8LIFibyiccnQcOc1E8nSoB5uxNtTuTvMzEUeaEj40o6LtxZicPk3ibjrg/640?wx_fmt=png "")  
  
就这么搞下吧，轮子也能跑起来了（记住开发的要点：又不是不能用）  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLUqDLXMVKTbjFXZf3aLdmuOhqO4uWficl0RwnCjTQzDNzic0dmn0kL9UrM5ia0JUOUula3nyeiaaQYuyw/640?wx_fmt=png "")  
  
   
  
   
  
MCP Client实战效果  
  
  
这里选择用Cherry Studio，可以访问 https://www.cherry-ai.com/来下载，个人感觉比较容易上手且好用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLUqDLXMVKTbjFXZf3aLdmuO81B9QrP5wSbIleviaCYia19JxCDH7RhLAvapibIZfibtGJFiawsvtjF7CPw/640?wx_fmt=png "")  
  
然后就配置好模型  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLUqDLXMVKTbjFXZf3aLdmuOLmibZFAfbMOzlGLQ9SY7PvOXIp08MbKU4gy7Q7uxgg4Im4dnGtLVlsA/640?wx_fmt=png "")  
  
配置MCP Server连接，现在也可以用流式HTTP的了，还是比较喜欢这种方式，比本地Stdio或者SSE更习惯点把  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLUqDLXMVKTbjFXZf3aLdmuOQ4kATwVLViaRLlrOMcNa0XgiaKD4VnvA2ib8DJdXBicsyHn1CJA0b7TlfQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLUqDLXMVKTbjFXZf3aLdmuOW3xwLjmiaRwNOVxXPTduRmrcufxcn3m5eNX4snPqsPqLqbfkvrsMiaSQ/640?wx_fmt=png "")  
  
那么就开始一场 一顿霹雳巴拉后的成果展示  
  
子域名信息收集  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLUqDLXMVKTbjFXZf3aLdmuOo6nr9RwVaqCJxOaUyt5e7qUiaDntSMdbM1Z7nGXPe6mrnKiajMPS3MkQ/640?wx_fmt=png "")  
  
Nmap端口扫描：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLUqDLXMVKTbjFXZf3aLdmuOa1T7Det822AX5SQ9IOJpqrqcqxVSiauGKjr8ZMuumbMy3VEFFAQRLwA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLUqDLXMVKTbjFXZf3aLdmuOxc5XRmwNRSsldllxDM8vb94nfuzCRL8EOZrwcXrdxF6GSnibukKplrg/640?wx_fmt=png "")  
  
之前有留过一个伏笔，就是我们还下载了deepseek r1模型，这里也展示下其模型的效果，实际上在这种单纯去理解调用mcp的时候，推理模型并不是很nice，会浪费比较多的时间，当然如果你把它引入到自我反思机制，做双模型架构那就很棒了  
  
下列deepseek模型结果： 好像自身理解调用不太起来，当然maybe是我的prompt太拉跨或者是其自身防御机制比较强  
  
![](https://mmbiz.qpic.cn/mmbiz_png/kJNsfULMnLUqDLXMVKTbjFXZf3aLdmuO2a5cibBhbbAf73JbNO2VnbyhtY6EosttJ7oicUB6Uow81PSsY4AxftWg/640?wx_fmt=png "")  
  
   
  
  
  
  
  
  
