#  基于SBERT孪生网络的漏洞描述归一化   
原创 7777777  VLab安全实验室   2022-09-30 16:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/0NpbNYDUplSVAeJNFpOlXC5uBg86icOw5Hyd9IkZVo0JUSV5nPeVNVriaFQKWJ59ODSQiafWYYvZs3fadU0JPjQ0A/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**V-实验室实验室**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/2TSketEedQ9mmk8nGa8zUv26iapUUPIczjUGSuap1ZqpQO56wnwGGmwkicPphswx7DG3CgAribFoibGw48d3VoQ17g/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
漏洞  
扫描评估产品主要采用基于漏洞知识库的技术进行漏洞信息综合处理。  
  
漏洞知识库通常是由各国信息安全中心及信息安全厂商和组织组建的涵盖漏洞各维度知识的漏洞库，如CNNVD 、NVD等。也因为这个原因，各平台间的漏洞存在描述重复。使用这些漏洞知识库时需要将数据做汇总，进行漏洞归一化，通过多维度知识数据去除重复。对于相同ID编号可直接根据ID去重，但部分平台描述是没有统一编号，这就使归一化工作人工成本陡增。  
  
在人工智能高速发展的今天，CV和NLP领域技术具备多种成熟的方案，采用NLP技术来代替繁杂的人工工作已是技术发展的趋势。  
## 基于Word2Vec+TF-IDF技术的归一化处理  
  
归一化的处理大多基于文本关键词的Word2Vec+TF-IDF技术做相似性比较，这种方法对于字词高相似度的文本具有一定效果。但数据中若存在两个相同的CVE_ID描述信息使用不同语序和同义词的文本描述，则效果较差。Word2Vec+TF-IDF技术虽对小批量数据处理较快，但对于大批量数据去重速度较慢，且在去重工作中很难或是无法识别重复的漏洞描述文本，因此在工业场景难以落地。  
## 基于SBERT孪生网络的漏洞描述归一化  
  
为保证漏洞描述归一化管理的精确度，需要从相似度、主体词、漏洞类型三个维度来判断重复漏洞描述。  
  
首先采用预训练模型Sentence-BERT对漏洞描述文本转化成固定维度向量，基于余弦相似度算法做相似度的对比。  
  
其次，用各个漏洞描述主体词判断漏洞描述之间是否一致，保证主体词一致。  
  
最后，采用HMCN（Hierarchical Multi-Label Classification Networks，层次多标签分类网络）模型预测漏洞文本的漏洞类型，判断每个漏洞类型是否一致，从而得到更高的精度。  
  
实际工作中，为解决项目工程落地响应速度问题，可将文本转换成向量转存到Elasticsearch向量搜索数据库，做文本相似度搜索，响应速度仅需几十毫秒。整体框架图如下：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0NpbNYDUplTeLZwnl2uib3pZIcGJ6sU7VLXIIxRiakKfMLmfUC0hX6ImwGyNEaGf7puT6qqwDBFcY42PmoLfGDgQ/640?wx_fmt=png "")  
  
图表1  
## 数据特征处理  
  
漏洞描述文本通过数据预处理后，将同一个漏洞标签不同漏洞厂商的漏洞描述作为一对正样本，构建负样本需要特殊处理，预训练模型对于字符文本相似性高的很容易召回，因此，负样本的构建要拉大与正例样本间距离，让模型能更好的学习到每个漏洞描述之间的语义关联关系，提高模型召回率。  
## 相似度模型  
  
相似度模型是孪生网络和三胞胎网络（SiameseandTripletNetwork），模型架构图如图表2所示，之所以选择这种网络原因是“孪生网络”结构简单，训练稳定，是很多文本任务不错的baseline；图表2中所示，左右各有一个BERT编码网络，将输入两个文本编码后，经过池化特征提取后得到两个句子向量（维度为一维长度是256的向量）。将输入映射到新的空间得到特征向量u和v，最终通过u、v的拼接组合，经过下游网络来计算文本Sentence A和Sentence B的相似性。由于我们数据集有中英文两种混合因此采用hugging face公开预训练多语言模型（paraphrase-multilingual-MiniLM-L12-v2）来继续fine-tune漏洞描述领域数据。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0NpbNYDUplTeLZwnl2uib3pZIcGJ6sU7Vk3qsOrzOojJEUo04ZFFrsbIun4PHz4CNUjfcoHAgXIic2zXqZ34ibVCg/640?wx_fmt=png "")  
  
图表2  
  
模型编码后得到特征u、v后，可以直接使用cosine距离、欧式距离等得到两个文本的相似度。其他应用场景更通用的做法是，基于u和v构建用于匹配两者关系的特征向量，然后用额外的模型学习通用的文本关系映射，特别是场景不一定只是衡量相似度，比如问答、蕴含等复杂任务。  
  
基于模型编码后的向量，存到ES数据库中，基于ES数据库提供的向量相似度搜索算法  
CosineSimilarity来完成向量搜索召回。  
ES向量搜索好处是速度快，可扩展数据能力强，更符合我们实际业务场景。  
## 漏洞类型分类模型  
  
基于CWE官网中给出的常用高频漏洞类型，再结合CNNVD官网Top25漏洞类型，得出模型分类类别和层级关系。如图表3所示，常见的文本分类任务中，类目之间通常是正交的，即不存在包含关系。而层次分类则是一类特殊的文本分类任务，HMCN（Hierarchical Multi-Label Classification Networks）网络能达到层次分类的目的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0NpbNYDUplTeLZwnl2uib3pZIcGJ6sU7VnnzLRWVyrmR990d5nvzFPv0L83TppVlJBj8KOVznKyxOJJQdsHZftg/640?wx_fmt=png "")  
  
图表3  
  
HMCN模型架构图表4所示，上图是HMCN-F非递  
归版结构图，架构中是有2条信息流，全局信息流和局部信息流。全局信息流是通过每个级别类集的反向传播梯度加强了全局信息流内的局部层次关系，局部的所有输出，经级联起来，再由全局输出进行一致性池化操作，输出最后的结果。这种结构能发现整个类层次结构中的局部层次类关系和全局信息，更适合做层次分类。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/0NpbNYDUplTeLZwnl2uib3pZIcGJ6sU7VDqicajdYmxibnXJ8fvRoiciaUue9KFPLv8xX1Tmt3UC8DY1aahTNicYUlVw/640?wx_fmt=png "")  
  
图表4  
## 实验结果  
  
漏洞类型分类模型  
<table><tbody><tr><td width="268" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 12px;">模型<br/></span></td><td width="268" valign="top" style="word-break: break-all;text-align: center;"><span style="text-align: center;font-size: 12px;">准确率ACC</span></td></tr><tr><td width="268" valign="top" style="word-break: break-all;text-align: center;"><span style="text-align: center;font-size: 12px;">HMCN</span></td><td width="268" valign="top" style="word-break: break-all;text-align: center;"><span style="text-align: center;font-size: 12px;">83.8%</span></td></tr></tbody></table>  
  
  
相似度模型+主体词 + 漏洞类型分类模型  
<table><tbody><tr><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 12px;">模型<br/></span></td><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 12px;">Top1找回率<br/></span></td><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 12px;">Top3召回率<br/></span></td></tr><tr><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 12px;">SBERT<br/></span></td><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 12px;">85.3%<br/></span></td><td width="171" valign="top" style="word-break: break-all;text-align: center;"><span style="font-size: 12px;">87.1%<br/></span></td></tr></tbody></table>  
## 总结  
  
未来，AI自动化网络安全攻防必定是基于漏洞资产信息库来完成一系列攻防任务，因此，漏洞及情报数据中心的搭建对于网络攻防的发展愈发重要。  
  
目前市场上的漏洞平台信息收集主要还是通过网络爬虫收集。漏洞收集来的各个平台信息冗余且重复，一些无法去重的漏洞资产信息无法入库，而对于企业来说这部分漏洞资产信息就会缺失，导致失去行业竞争力。基于SBERT孪生网络的技术方案能为企业创造巨大价值。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/asLg7via5ibAkf1mRkpS4IuZibZE5eeC0t8nibIZBfZEekibOEZVWyf9jHzIVvT2sTzKS1OtZzSBErxJUZXD1AwAAWw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
往期回顾  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjDF5uGXY5ibE0P0Mtzns3KNb5hsCIKPfMIRultHDbmzgJcDaibI4wNKM6ZloyGRtRovyXtVdv3SuuVOcmA8gn8A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
# MiraclePtr UAF漏洞利用缓解技术介绍  
# 针对U盘文件的盗与防攻略  
# Ruby安全漫谈  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/7lCiaSMMkhia4WIkRNZHTwq8jJicy27jdbWa7ED26252RGmSPRE0rmHQsgZ6ZoichVyFNlvhLelZS09a194B9dyoAQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
引领智能网络攻防科技  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/CD1iaLIMEhibPv9rc3gdLj3g6fiaAcCZqIicylIMVKlbvd5ic5usJ2oia9cTgavs6BwQpEEYbfglc82kCJ0Qic3OHMEaw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
  
点击  
**在看**  
  
分享给小伙伴  
  
  
↓↓点击  
**阅读原文**  
，了解更多墨云信息  
