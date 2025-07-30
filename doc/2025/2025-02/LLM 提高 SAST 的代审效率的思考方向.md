#  LLM 提高 SAST 的代审效率的思考方向   
原创 A2Cai  隐雾安全   2025-02-14 01:01  
  
# LLM 提高 SAST 的代审效率的思考方向  
  
原创  
                                                        
                                     A2Cai                                    
                                                                
               
               隐雾安全                
                                          
                          
             2025年02月13日 09:00  
              四川  
                                                        
                        
> 插一段话：  
> 我其实也是最近才了解到用 SAST 来进行代审，然后只会 PHP 所以也只能基于 PHP 来思考  
> 因为前阵子的 AI Agent、提示工程、思维链、工作流啥的很火，就想着看能不能用 LLM 来提高代审的效率，就有了这篇文章  
> 如果有错误或者不完善的地方，还请大佬们多指点指点我 ;-)  
> 【PS：其实我比较擅长的还是黑盒的漏洞挖掘，一开始考虑是结合 LLM 提高 Web 漏洞挖掘的效率的，但考虑到产出不稳定就换了个方向试试】  
  
  
  
先来聊聊借助工具人工进行代码审计的步骤以及遇到的问题吧  
  
借助代码静态分析工具 Joern 后的人工代审步骤（以 PHP 为例）：  
1. 找到 Source，即用户可控的部分。框架类项目会有固定的一套，而非框架类项目则需要分析路由以及参数传递方式。  
  
1. 找到 Sink，即参数可控的情况下会导致漏洞的函数、关键字或结构。除了内置的高风险函数之外，还需要额外关注第三方扩展导致的安全风险。  
  
1. 借助自动化分析工具找到完整流向的 Information flow 后，人工分析代码，判断这条链是否真的可以利用，写 poc 尝试利用。  
  
各个部分的效果图展示  
  
找到所有参数传递的调用的入口函数 Source（以该项目封装的 get 函数为例）：  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zkukvvtrNTsLStFiauhVLcofVNiaGR9bLjHnGlvxesRmMmAwTO9iaSUezKaFNjdOyofiamtuMjkRIBrQ/640?wx_fmt=png&from=appmsg "")  
  
找到所有调用污点函数的 Sink（以 file_get_contents 为例）：  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zkukvvtrNTsLStFiauhVLcoIT2xlcJU9S9koBibygcMoEdqv1oPRrxDy2wY9jhmenOhUmJvYLXCjicA/640?wx_fmt=png&from=appmsg "")  
  
找到所有从入口函数到污点函数完整的数据流链：  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zkukvvtrNTsLStFiauhVLcormsI5mjYEdZ6MNRibdAdeU2gJ3ENxUOrCKcsic0r6rshWlnOiclGTF86g/640?wx_fmt=png&from=appmsg "")  
  
最后尝试去复现和利用。（PS：这套代码是某开源 OA 最新的源码，这条链确实有点问题，但前置条件过多就放弃了）  
  
各个步骤的需要关注的点：  
- 对于使用了框架的项目来说，我们没办法保证该项目完全按原版的来，可能会漏报。  
  
- 对于没有使用框架的项目来说，则需要人工花时间进行分析，费时费力且没办法沿用方案。  
  
- 对于可能会导致安全风险的污点函数而言，需要人工维护，且随着污点函数的增多，需要人工分析的代码也会变多。  
  
- 在分析完整流行的 Information flow 的时候，需要持续关注数据的变化，以免流入 Sink 的数据无法正常被利用。  
  
提高效率必须要做到的点：  
1. 确定是否存在全局过滤。  
  
1. 如果存在全局过滤，则对于定位污点函数的语句也要添加相应的过滤。  
  
1. Source 所指向的节点和污点函数的 Sink 要尽可能的全面，语句要尽可能高效。  
  
1. 对于被过滤和限制的污点函数，要在数据流分析之前就排除在外。  
  
1. 对于 Source 而言，除了常规的 GET、POST 方法之外，还要考虑到更多用户可控的地方，例如 User-Agent、Referer、Cookie 等。  
  
1. 人工分析代码要尽可能高效。  
  
1. 重点关注传入参数的流向以及值的变化，如果在途中的变化使其无法被利用，则放弃转而分析下一条链。  
  
**如何结合 LLM 提高代审效率呢？**  
  
重点放在第三步纯人工分析确定这一步骤。  
  
要明确的是要让 LLM 参与哪一类型的工作，而 LLM 的优点在于其数据分析、逻辑思维能力  
  
所以我大体上的思路是给 LLM 提供数据进行分析，并根据逻辑推理出相应的结论，最后按需生成 Poc 进行验证  
  
其中有很多的问题点需要被解决，其中最大的问题在于：  
1. **受限于 LLM 的上下文限制，无法一次性读完所有代码。**  
  
1. 使用 RAG 的方式允许 LLM 进行代码的查询，实现丰富功能的 Function calling tools 以便 LLM 可以模拟人工代审 Ctrl + 左键跳转的功能。  
  
1. 使用 RAG 的方式进行查询可能会丢失一些信息，例如：目录结构、文件名称。要解决这个问题则需要额外制定规则并告诉 LLM。  
  
1. **即便 LLM 可以查询所有的代码，但各部分之间联系薄弱，很难得出有效的信息。**  
  
1. 构造  
思维链让 LLM 以人工代审的思维进行分析，下面给出一个思维链的参考案例：  
  
     1. 确定是否存在参数传递的全局过滤。（见过有些 OA 直接全局 ' 替换成 \&#39; 的，忽略这步后面挠破头都不知道为啥一直不行）  
  
  
     2. 根据污点函数的类型，来确定可利用的输入数据类型。（XSS、SQL 注入需要单双引号逃逸，文件写入则需要内容可控路径可知...）  
  
  
     3. 从污点函数到入口参数传递，反向分析数据的变化，由 LLM 判断其改变是否会影响数据的可用性。如果遇到内置函数，则直接分析即可；但如果遇到自定义的函数，则需要根据函数的具体实现进行分析，但大概率面临的情况是自定义函数里面依旧掺杂着自定义函数，我想到的解决方案是：记录各个函数的具体实现，分析出函数调用的树（每个节点需要记录函数名、函数的具体实现和函数所处的文件），利用 Joern 去找到最里层函数的实现并分析它的作用，再一层一层往上传递（途中所有涉及到的函数需要被记录下来）。这样做的好处在于，让 LLM 分析代码的时候不依赖于变量名称，而是更多在代码逻辑上进行分析，最终分析结果可能会更为可靠；坏处就是效率会很低，尤其涉及到复杂业务逻辑的分析。【这个步骤相当于是完全模拟人类的思维，LLM 只是起到分析数据和推理给出结论的过程，效率较低】  
  
  
     4. 上述思维链存在的问题：  
  
        - 随着分析的深入，所参考的数据量可能也会超出上下文大小。  
  
        - 同一函数的不同调用方法可能会导致工作量的增加。  
  
        - 随着业务逻辑的复杂程度提高而导致工作量激增。  
  
        - 难以发现潜在的组合拳漏洞。  
  
        - ...  
  
  
想了这么多，但最后发现实现起来还是不太容易的，就当抛砖引玉了  
  
  
......  
  
  
这篇文章发到 p 牛的 “代码审计” 知识星球后，洺熙大佬给了我不少想法建议让我颇有收获  
  
  
我也一并贴到后文，让文章有个结尾而不是止于猜想  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zkukvvtrNTsLStFiauhVLcoQAeBfSOpZYEZw43kfdA9OQonpbtkYG0FEHQWdQIWAU7iaf4lPkLhicPA/640?wx_fmt=png&from=appmsg "")  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zkukvvtrNTsLStFiauhVLcoypccRdlvk1Rwmn1RdgY6CZsmYZO6YCMPYJ3da0bzgheGHs4VXOquZQ/640?wx_fmt=png&from=appmsg "")  
  
最后的最后，我给大家贴上我一开始想整 LLM 辅助漏洞挖掘方向的小小小demo，可以看看效果怎么样  
  
如果感兴趣的人多的话，可以考虑再完善一下，如果感觉很鸡肋的话，大伙也可以在下面吐槽  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zkukvvtrNTsLStFiauhVLcojUm9iaItOrfg0ZnstMibJ38hYaicoNQALxhiaAibCyteoecBcyJ3r8QTSuw/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zkukvvtrNTsLStFiauhVLcoRQw9NhbzFiaDKwV4Zfx9h201AmyrmwnoG2VDf2eDqicib9YUrNV7P28Hw/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zkukvvtrNTsLStFiauhVLcohdpn00wrtZGloWVQWBILIDMEnjzTxB5DszCiaEAmHgwBXVuvn7D3d7w/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zkukvvtrNTsLStFiauhVLcoZVQibibfwmsokajqxU8RpBhf5bicjbicib81IcC2tn5YcrnbuQrianicGYfNQ/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/ELQKhUzr34zkukvvtrNTsLStFiauhVLco8VtJJCaLopysXcZTrraEaFOtulVFJ0PwiaNJlwgVtzXtwA6LBLsgqhQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
