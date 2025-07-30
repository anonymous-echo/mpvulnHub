> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247492274&idx=1&sn=e9ecde35f94e0fc28479875b6aab3b29

#  LLM驱动的UEFI固件漏洞智能分析实践  
原创 smile  联想全球安全实验室   2025-06-20 03:26  
  
**点击蓝字 关注我们**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5EiatoQN0lHJHT98uP8crydLrTujerjqMgiamhwd2QuaIxGFODbKCYX83cKA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5EiatzH15ib4YRmUQQ8NkROziaBAkrMsfHFsGcxmhIxv9e6CdkkBvPRAZsmJA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5EiatUVgcZ3bPWDgCO1vTMC579ibNxtUzulqdMgDiaafqaJEofibibpdb8lvib0g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5EiatjJ9LQCAGZqoxCaz5ia3XQqx2Mcmo2eoBLaAYHYELCmDllicosD3KwJrA/640?wx_fmt=png&from=appmsg "")  
  
**LLM驱动的UEFI固件**  
  
**漏洞智能分析实践**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5EiatzOwDnjLGG6BoyRm06N1dnDfWXEsiabu6JRLuGGjTShAXPaxicyA1Js0Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5Eiat5mNomgwSoOhyZ8Xhd3Rbsu9A9yBoiaT2qeTJhtGjeicIxec5LicJKJYfA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5EiatQXwDOWEy5O1xnqNxO5ep2micWiafj1kplb1Z0c6H4vcpnB1JZmSI4DRA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5Eiat2yRsnFuibCkXeT4XgydAr8NJ2qmAHtVuC99OibribJqeKyWsR7Sb3NjIA/640?wx_fmt=png&from=appmsg "")  
  
**引言**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5Eiat2yRsnFuibCkXeT4XgydAr8NJ2qmAHtVuC99OibribJqeKyWsR7Sb3NjIA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5EiatOEz1965NEsILUomtZIEzWgchwpfhbj1ywuqUSEcD97BZEnLfzm570w/640?wx_fmt=png&from=appmsg "")  
  
问题背景  
  
UEFI 固件安全面临多重挑战。漏洞普遍存在于 SMM 和 DXE 驱动中，尤其 SMM 中高风险漏洞集中。许多 UEFI 漏洞隐藏较深，涉及复杂的参数传播和数据交换，传统检测技术难以发现。现有检测工具依赖模糊测试或汇编指令匹配，缺乏数据流跟踪分析工具来自动检测 UEFI 安全漏洞。静态分析在分析复杂 UEFI 漏洞时也面临挑战。供应链问题，旧版本固件的使用，以及非厂商编译固件，导致已知未修补漏洞难以检测。  
  
然而，UEFI 固件安全也存在机遇。研究人员发现了大量 SMM 漏洞，提高了 UEFI 的鲁棒性。efiXplorer 等工具简化了逆向工程。数据流分析等先进方法可发现深层漏洞。EfiDrill 等新工具通过数据流跟踪、污点跟踪等功能增强了漏洞分析能力。EfiDrill 等工具的开源有助于安全研究人员分析 UEFI 漏洞，提升 UEFI 产品安全性。通过改进数值预测能力，可以进一步减少误报。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5EiatOEz1965NEsILUomtZIEzWgchwpfhbj1ywuqUSEcD97BZEnLfzm570w/640?wx_fmt=png&from=appmsg "")  
  
破局思路  
  
**·提出「安全智能体」概念****：**  
将大语言模型的语义理解能力与静态分析工具（efidrill）深度结合  
  
**·创新价值：**  
实现「漏洞情报检索 → 自动化分析 → 结果解释」的闭环工作流  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5Eiat2yRsnFuibCkXeT4XgydAr8NJ2qmAHtVuC99OibribJqeKyWsR7Sb3NjIA/640?wx_fmt=png&from=appmsg "")  
  
**系统架构设计**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5Eiat2yRsnFuibCkXeT4XgydAr8NJ2qmAHtVuC99OibribJqeKyWsR7Sb3NjIA/640?wx_fmt=png&from=appmsg "")  
  
  
**01**  
  
架构图  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5Eiat9rFgFNf3DVZiavVEJEZn8oJ1fxec2Mxj7gJaNKntVC1FQbAmibv5PFPA/640?wx_fmt=png&from=appmsg "")  
  
**02**  
  
架构说明  
  
本系统的设计旨在提升固件漏洞分析的效率和准确性，降低人工审计的工作量。同时，结合 LLM 的自然语言处理能力，使得固件漏洞分析更加智能化和自动化。整体安全智能体系统分为三部分：  
  
1. **用户交互模块**  
：负责路由用户输入的自然语言查询和系统输出的结果展示。  
  
（1）**自然语言处理**  
：将用户的自然语言查询转化为系统可理解的查询格式；  
  
（2）**结果展示**  
：将系统分析结果以易于理解的方式呈现给用户。  
  
2. **固件样本模块**  
：负责固件样本的静态分析和查询。  
  
（1）**固件样本分析**  
：使用 efidrill 工具进行静态分析，提取固件中的数据流和控制流信息；  
  
（2）**固件样本查询**  
：基于固件模块的数据库，提供固件样本的多条件模糊查询。  
  
3. **固件漏洞情报模块**  
：基于 LLM 的自然语言处理能力，提供漏洞情报问答、反编译代码的语义解释等功能。  
  
（1）**漏洞情报问答**  
：基于 RAG（Retrieval-Augmented Generation）模型，结合固件漏洞情报数据库，提供针对固件漏洞的智能问答；  
  
（2）**反编译代码的语义解释**  
：通过 LLM 对反编译代码进行语义分析和注释，帮助安全研究人员理解漏洞代码。  
  
**03**  
  
系统交互流程  
  
1. **用户通过自然语言输入查询**  
：用户通过自然语言输入查询可以是对固件漏洞的描述、对固件样本的分析请求和特定漏洞的编号等，因此用户提问的方式可以是多样化的。比如：  
  
**·**  
用户可以输入"有没有关于 CVE-2023-XXXX 漏洞的描述"  
  
**·**  
用户可以输入"最新的 UEFI 漏洞有哪些"  
  
**·**  
用户可以输入"SMM 缓冲区溢出漏洞的代码模式是什么"  
  
2. **系统将查询转化为对应模块的请求：**  
系统会将用户的自然语言查询转化为固件样本模块和固件漏洞情报模块可以理解的请求格式。根据查询的内容，系统会选择合适的模块进行处理。  
  
3. **固件样本模块进行静态分析：**  
固件样本模块使用 efidrill 工具对固件样本进行静态分析，提取固件中的数据流和控制流信息。efidrill 工具会对固件样本进行深入的分析，识别潜在的漏洞和安全隐患。  
  
4. **固件漏洞情报模块进行智能问答：**  
固件漏洞情报模块基于 RAG 模型，结合固件漏洞情报数据库，提供针对固件漏洞的智能问答。系统会根据用户的查询内容，从漏洞情报数据库中检索相关信息，并生成自然语言回答。  
  
5. **系统将分析结果以自然语言形式返回给用户：**  
系统将固件样本模块和固件漏洞情报模块的分析结果以自然语言形式返回给用户。用户可以通过系统提供的结果，了解固件样本的安全性和漏洞信息。  
  
6. **用户可以进一步查询或分析：**  
用户可以根据系统返回的结果，进一步查询或分析固件样本和漏洞信息。系统会根据用户的进一步查询，进行相应的处理和分析。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5Eiat2yRsnFuibCkXeT4XgydAr8NJ2qmAHtVuC99OibribJqeKyWsR7Sb3NjIA/640?wx_fmt=png&from=appmsg "")  
  
**技术实现细节**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5Eiat2yRsnFuibCkXeT4XgydAr8NJ2qmAHtVuC99OibribJqeKyWsR7Sb3NjIA/640?wx_fmt=png&from=appmsg "")  
  
  
**01**  
  
**固件漏洞情报检索**  
  
通过实践验证，简单的关键词检索无法满足固件漏洞情报的需求。采用了 RAG 模型之后，对于用户提问复杂或者模糊的情况，系统还是不能够给出准确的答案。这要求在简单的分块向量化语义检索的基础上，设计更加复杂的检索模型。笔者之前专门写过一篇关于 RAG 检索方法的文章，感兴趣的读者可以参考《RAG QA 系统的检索和生成调优》（https://mp.weixin.qq.com/s/PWvrtQtRealJnbNOcPzH8Q）。在本系统中，综合使用 BM25 检索、普通（朴素）检索、元数据检索、假设提问检索、总结检索、自我查询检索、父子检索方法，采用不同检索方法结果分配相应权重融合排名来提升检索的鲁棒性和准确性，这种方法的灵活性要高于 rerank 方法。  
  
针对上述文章未提及的假设提问检索和总结检索，在此做简要介绍。  
  
**·假设提问检索**  
：假设提问检索让 LLM 为每个块生成指定个数的问题，并将这些问题嵌入为向量中，在检索时对这个问题向量的索引执行查询搜索（将块向量替换为索引中的问题向量），然后在检索后路由到原始文本块并将它们作为 LLM 获取答案的上下文发送。  
  
**·总结检索**  
：总结检索让 LLM 为每个块生成一个总结，并将这些总结嵌入为向量中，在检索时对总结向量的索引执行查询搜索（将块向量替换为索引中的总结向量），然后在检索后路由到原始文本块并将它们作为 LLM 获取答案的上下文发送。  
  
以上两种检索方法的思路都是让 LLM 为原始分块进一步提炼出更加精炼的语义，尽可能在维持合理分块大小的基础上保留更多的语义信息，从而提升检索的语义准确性。比如一篇漏洞公告分块之后，漏洞编号、漏洞描述、漏洞修复方案、漏洞补丁记录等会散落在不同的分块中，往往漏洞描述会占据大部分的篇幅，如果多数用户查询的是漏洞描述中的某一小部分，就会受到嵌入向量表达语义有限的影响，那么使用假设提问检索或者总结检索，就可以提升语义检索的准确性。  
  
在本系统中使用两种不同的固件漏洞情报检索数据库，一是基于关键字查询的全文检索数据库，二是基于向量查询的语义检索数据库。在检索时，系统会对用户查询进行嵌入或适当的重写，根据嵌入或者重写后的查询向量，在语义检索数据库中进行检索，同时提取用户提问中的关键词或元数据，在全文检索数据库中进行检索。最后对两种来源的检索结果进行融合排序，最终返回给大模型用于生成答案的上下文。  
  
**02**  
  
固件模块分析  
  
鉴于目前大语言模型在处理固件漏洞分析时，存在处理二进制能力不足的问题，因此本系统使用 efidrill 工具对固件样本进行静态分析，提取固件中的数据流和控制流信息。此工具已经在 GitHub 开源并附有详细的白皮书，感兴趣的读者可以参考efidrill（https://github.com/cc-crack/efidrill）。简要来说，efidrill 是一款支持数据流追踪、污点跟踪、自动结构分析、变量数值预测及自动漏洞检测的 UEFI 固件工具。  
  
efidrill 工具的输出结果包括漏洞检测结果、漏洞偏移。同时使用 IDA 工具对固件样本进行反编译，提取对应函数的反编译代码。本系统将这些结果作为 LLM 的输入上下文，帮助 LLM 更好地理解固件样本，从而提升漏洞分析的准确性。  
  
**03**  
  
固件模块查询  
  
本系统使用 oss 存储收集的固件样本模块。数据库中包含固件样本的模块名称、模块偏移、模块大小、模块类型等字段。用户可以通过模块名称、模块偏移、模块大小、模块类型等条件进行查询。而这些字段属于精确匹配，因此本系统在对用户提问进行意图识别之后，使用自我查询提取关键词和元数据后，使用 BM25 检索方法来检索相应的固件样本模块提供给用户。  
  
**04**  
  
提示词设计  
  
本系统使用提示词来引导 LLM 进行固件漏洞分析。  
  
**·****关键字段提取**  
：将 oss 返回的临时下载链接用 LLM 提取出来，由于不同 LLM 的能力有差异，不同 LLM 对链接的语义分割有差异，因此需要使用提示词来引导 LLM 进行链接字段提取。  
  
比如使用：  

```
&#34;Searches and returns excerpts(especially download link) from DXE driver documents.&#34;
```

  
来引导 LLM 进行链接字段提取。  
  
**·****漏洞情报问答**  
：在本系统中 RAG 检索经常涉及检索到多个漏洞公告或者分块的情况，这些公告或者分块需要有明确的语义分割，防止 LLM 在生成答案时出现语义混乱的情况。使用提示词来引导 LLM 进行漏洞情报问答。  
  
比如使用：  

```
system_prompt = &#34;&#34;&#34;You are an assistant for question-answering tasks.
Use the  pieces of retrieved context to answer the question.
Each piece of fact is separated by @@@@@ and not mixed up with each other.
If you don't know the answer, just say that you don't know.
Guarantee the integrity of the URL link, include the amz credentials.
Keep the answer concise.&#34;&#34;&#34;
```

  
来引导 LLM 进行漏洞情报问答。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5Eiat2yRsnFuibCkXeT4XgydAr8NJ2qmAHtVuC99OibribJqeKyWsR7Sb3NjIA/640?wx_fmt=png&from=appmsg "")  
  
**LLM赋能的核心场景**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5Eiat2yRsnFuibCkXeT4XgydAr8NJ2qmAHtVuC99OibribJqeKyWsR7Sb3NjIA/640?wx_fmt=png&from=appmsg "")  
  
  
**01**  
  
**场景1：基于 RAG 的漏洞情报问答系统**  
  
1. **技术实现**  
：  
  
（1）**知识库构建**  
：固件知识图谱嵌入（漏洞 CVE 条目/代码模式/补丁记录）  
  
（2）**检索优化**  
：针对固件领域术语的 Prompt 工程（例如"SMM 通信缓冲区溢出"的专业表述）  
  
2. **案例演示**  
：输入自然语言查询"特定机型的 n-day 漏洞"，输出漏洞编号+漏洞描述+漏洞模块。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5EiatiavdHRHn7BticPdmoWNW5U4eHkgcPOkYEImcjO8sqUrHVnhFzKlCRWzg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5EiatUrYOhVAxZCpPAkOiataEvIudPibvdlibicGvZnRk5CibjibcCtqiaONwMQ7RQ/640?wx_fmt=png&from=appmsg "")  
  
**02**  
  
场景2：自动化 UEFI 固件漏洞扫描  
  
1. **痛点解决**  
：传统反编译输出（如 Hex-Rays）存在变量名丢失、控制流断裂等问题，人工分析难度大  
  
2. **实现路径**  
：  
  
**·**  
上下文增强：将 efidrill 的数据流追踪结果（如 taint propagation path）作为 LLM 的输入上下文  
  
3. **示例展示**  
：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5EiatxW2tOibeZ7ULaxvDe6RbkoEzcaYwJd5LhMVI5KweJgibE4xe8zQ9iafTg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5EiatuUBBFZiawQQFP9tSR6lLMRT7czfPgMcKwxaTH7KsH2ibpcrb2JUoLpyg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5Eiat2yRsnFuibCkXeT4XgydAr8NJ2qmAHtVuC99OibribJqeKyWsR7Sb3NjIA/640?wx_fmt=png&from=appmsg "")  
  
**挑战与未来方向**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5Eiat2yRsnFuibCkXeT4XgydAr8NJ2qmAHtVuC99OibribJqeKyWsR7Sb3NjIA/640?wx_fmt=png&from=appmsg "")  
  
  
**01**  
  
当前局限性  
  
1. **多架构支持**  
：当前主要聚焦 x86，需扩展 ARM UEFI 代码解析和 MIPS 代码解析；  
  
2. **数据集构建**  
：当前数据集规模较小，需要构建更大规模的固件漏洞数据集；  
  
3.**efidrill 工具的局限性**  
：efidrill 工具在处理复杂数据流路径时，存在处理能力不足的问题，需要进一步优化。  
  
**02**  
  
演进路线  
  
1. **动态分析融合**  
：结合 QEMU 虚拟化平台的运行时行为监控；  
  
2. **防御场景延伸**  
：漏洞模式知识库 → 自动生成漏洞缓解策略。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5Eiat2yRsnFuibCkXeT4XgydAr8NJ2qmAHtVuC99OibribJqeKyWsR7Sb3NjIA/640?wx_fmt=png&from=appmsg "")  
  
**结语**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PicDhHpwdzia8QZmEx3a3qicvEErMPA5Eiat2yRsnFuibCkXeT4XgydAr8NJ2qmAHtVuC99OibribJqeKyWsR7Sb3NjIA/640?wx_fmt=png&from=appmsg "")  
  
  
「AI+安全」的范式转变：从工具链（Toolchain）到智能体（Agent）的进化，提供可解释、可交互的漏洞分析体验。通过将传统 UEFI 分析工具（如 efidrill）与 LLM 的深度结合，我们不仅能够突破传统静态分析工具的局限性，还能显著提升漏洞分析的效率。这种创新性的结合为安全研究人员提供了更智能、更直观的分析体验：  
  
1. **效率提升：**  
LLM 能够快速理解并解释复杂的 UEFI 代码结构，帮助研究人员快速定位潜在漏洞点，大幅减少人工分析时间。  
  
2. **知识传承**  
：通过 RAG 技术，系统能够将历史漏洞分析经验转化为可复用的知识，帮助研究人员避免重复工作。  
  
3. **分析深度**  
：结合 efidrill 的数据流追踪能力和 LLM 的语义理解能力，能够发现传统工具难以检测的深层漏洞。  
  
4. **交互体验**  
：研究人员可以通过自然语言与系统交互，获得更直观的分析结果和解释，降低了 UEFI 固件分析的门槛。  
  
这种工具链到智能体的转变，不仅代表着技术范式的革新，更是对传统安全分析工作流程的一次重要升级。通过持续优化和扩展，我们相信这种结合将为 UEFI 固件安全研究带来更多突破性的进展。  
  
  
往期精彩合集  
  
  
  
● [2025网安大会高能看点！联想全球安全实验室揭秘大模型投毒攻击](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247492155&idx=1&sn=c8509dcc0eada09e55ce782e85275fba&scene=21#wechat_redirect)  
  
  
● [BurpSuiteMCPServer试用体验](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247492143&idx=1&sn=df4abb63a9a4383acc55c9857623201c&scene=21#wechat_redirect)  
  
  
● [通过Binder对Android系统服务进行Fuzz](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247492104&idx=1&sn=b41efbb525811878cc464174d7bba483&scene=21#wechat_redirect)  
  
  
● [User-Agent安全问题分析与实例](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247492028&idx=1&sn=44ac2da057fdbba45bddbb8817da2903&scene=21#wechat_redirect)  
  
  
● [ScreenCrab：蓝军悄无声息的窥探之举及其应对之策](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247492004&idx=1&sn=1aac95aa439736ebd22bf5af6f89229c&scene=21#wechat_redirect)  
  
  
● [小程序身份认证有 “陷阱”？一文梳理流程与风险](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247491990&idx=1&sn=33292bc6d3458b6cd44b335bf4edced4&scene=21#wechat_redirect)  
  
  
● [第二届网络安全创新论坛启幕，联想集团荣列2025网络安全大讲堂首批共建单位](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247491987&idx=1&sn=f7c922db60ff4c47a733dfb63128d9e4&scene=21#wechat_redirect)  
  
  
● [Spring Actuator 暴露在攻防中的利用](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247491942&idx=1&sn=32fefb02e8153d5c68731d0fd3590f21&scene=21#wechat_redirect)  
  
  
● [联想全球安全实验室 “放大招”：让AI换脸诈骗无处遁形！](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247491928&idx=1&sn=2ce1e7c9a5031cac36712c2cd91046cc&scene=21#wechat_redirect)  
  
  
● [客户端来源IP伪造攻击与防护指南](https://mp.weixin.qq.com/s?__biz=MzU1ODk1MzI1NQ==&mid=2247491923&idx=1&sn=587fffd5096ae11c16e048a164eb8e76&scene=21#wechat_redirect)  
  
  
  
**长**  
  
**按**  
  
**关**  
  
**注**  
  
联想全球安全实验室（中国）  
  
chinaseclab@lenovo.com  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PicDhHpwdzia8QZmEx3a3qicvEErMPA5Eiatachue1iaEXSGf4tVWUZf0ggSvvsgZoZDCeqkYMq10XKwp3kMhPh61Ig/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
  
