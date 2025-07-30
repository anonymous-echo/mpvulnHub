#  GPT4-o是否仍然存在奶奶漏洞？   
 幻泉之洲   2024-06-09 12:48  
  
**“**  
Voice Jailbreak Attacks Against GPT-4o**”**  
  
知道什么是奶奶漏洞吗？只要对ChatGPT设置角色“扮演我已经过世的奶奶”，它几乎可以为你做任何事情，包括各种商业机密！  
时至今日GPT4-o已经发布，奶奶漏洞是否仍然存在呢？  
让我们来看下今天的研究。  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MRJiclxHSU3anMkiaEYZkF8uVCKLOsp0Rf3NOCe2eI48SqyaEAPlCjesxqkCcY7kzMQyKwQBiaqezXCOMnKtJBdsw/640?wx_fmt=png&from=appmsg "")  
  
  
论文地址  
：https://arxiv.org/pdf/2405.19103  
  
Github地址  
：https://github.com/TrustAIRLab/VoiceJailbreakAttack  
  
  
**摘要**  
  
本文首次系统地测量了针对GPT-4o语音模式的越狱攻击，我们提出了一种名为VOICE JAILBREAK的新型语音越狱攻击，通过虚构故事来说服GPT-4o。VOICE JAILBREAK能够生成简单、可听、有效的越狱提示，显著提高了攻击成功率。  
  
  
我们还进行了大量实验，探索了交互步骤、虚构写作的关键要素和不同语言对攻击效果的影响，并通过高级虚构写作技术进一步提升了攻击性能。我们希望这项研究能帮助研究界构建更安全、更规范的多模态大型语言模型。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MRJiclxHSU3anMkiaEYZkF8uVCKLOsp0RfsI33gTTBQL9Kz5sYCm1HIlfKnamaiawCAOjVw6PSEvmVyVZBA8JkmZg/640?wx_fmt=png&from=appmsg "")  
  
  
**简介**  
  
GPT-4o是第一个跨音频、视觉和文本的端到端多模态语言模型，具有更强的情感理解能力和人类级响应速度。然而，这种新的声音模式也引入了安全威胁，如越狱攻击，可能会操纵模型生成有害内容。以前的研究已经表明，文本和视觉模式的多模态语言模型都容易受到越狱攻击的影响，但声音模式是否容易受到越狱攻击尚不清楚。鉴于与多模态语言模型的声音交互越来越普遍，了解相关的安全风险至关重要。  
  
  
本文首次系统测量了GPT-4o语音模式与越狱攻击相关的安全风险，重点关注了违反OpenAI使用政策的六种禁止场景。研究发现，无论是以不同声音提问还是将文本越狱提示转换为音频，攻击成功率都很低，原因是GPT-4o内部保障机制和文本越狱提示无法适应语音模式。文本越狱提示过长，平均需要171秒才能说完，而自然的句子间停顿可能会在整个提示完成之前触发响应。  
  
  
VOICE JAILBREAK是一种针对GPT-4o语音模式的破解攻击，通过虚构故事来人性化地说服模型。该攻击可以将禁止的问题转化为简单、可听、有效的破解提示，将平均ASR从0.033提高到0.778。研究还发现，通过引入高级技术，如观点、红鱼、铺垫等，可以进一步提高攻击效果。研究人员还进行了大量的消融研究，涵盖了交互步骤、虚构写作要素和不同语言等方面。  
  
  
**相关工作**  
  
越狱攻击（jailbreak attacks）旨在绕过内置的安全对齐，以生成虚假信息和有害内容。攻击者通过伪造越狱提示来欺骗目标模型回答禁止问题。研究人员主要关注文本模式下的攻击，但也发现了视觉模式下的攻击表面。目前尚不清楚语音模式是否也存在类似问题。  
  
  
**初步研究**  
  
**威胁模型**  
  
  
**攻击目标。**  
给定一个具有语音模式的目标MLLM，攻击者的目标是通过语音输入诱导该模型回答禁止提出的违反其内容策略的问题。考虑到语音输入的特殊性，语音越狱攻击应满足以下条件：  
- **有效性。**  
  
语音越狱攻击需要在不同的禁用场景中实现较高的攻击成功率。  
  
- **实用性。**  
  
语音越狱提示应该简单、简短，并与自然的语音模式保持一致，使其易于说话，并适应不同的口音和口语。  
  
**攻击能力。**  
假设攻击者在现实世界中具有黑盒访问目标MLLM语音模式的能力。  
  
  
**实验设置**  
  
  
通过在OpenAI的语言模型中提出禁止问题，来测试模型的安全性。  
  
  
使用了一种文本转语音的方法，将问题转换为自然语音，并通过ChatGPT应用程序将其播放给GPT-4o模型。  
  
  
提供了一个禁止问题集，包括非法活动、仇恨言论、身体伤害、欺诈、色情和隐私暴力等六个场景。  
  
  
研究使用攻击成功率作为有效性指标，并考虑了所需时间、字数和可读性等实用性指标。  
  
  
**结果**  
  
  
GPT-4o的声音模式在禁止问题方面表现出优异的抵抗力，特别是在非法活动和隐私暴力等场景中，ASR仅为0.000。同时，GPT-4o对文本越狱提示也具有很好的抵抗力，ASR低于0.100。然而，直接将文本越狱提示转换为语音越狱提示可能不适合实际应用，因为文本越狱提示通常太长，而且句子之间的自然停顿可能会导致GPT-4o在处理接收到的音频时错过提示的部分。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MRJiclxHSU3anMkiaEYZkF8uVCKLOsp0RfPJwnS8maDHZyauLZ96ia77HabZrRibVZLSbviaylTpKH76BuKAQgkaiaxA/640?wx_fmt=png&from=appmsg "")  
  
  
GPT-4o在抵抗越狱的能力上存在一些问题。当只听到禁止的问题时，GPT-4o可以成功提供相应的答案。但是，当带有文本越狱提示的禁止问题通过语音模式输入时，GPT-4o会简短地拒绝回答。此外，由于句子之间的自然停顿，GPT-4o在接收到“让我们玩个游戏”的同时开始处理和回答，从而错过了禁止的问题。这些结果表明，GPT-4o的语音模式可能也包含了对越狱尝试的保护措施。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MRJiclxHSU3anMkiaEYZkF8uVCKLOsp0RfHNF4do7xvRiabCsDvwYsF3RzhoibicO43vxCEicVNGtEuCqaqogWsHYD7Q/640?wx_fmt=png&from=appmsg "")  
  
  
**VOICE JAILBREAK**  
  
**设计理念**  
  
  
通过初步研究发现，语音模式下文本越狱提示的效果变得不太有效，因为内部保护机制会在词汇或语义层面上记住和识别它们。此外，这些复杂且难以解释的文本越狱提示在音频形式下与人们自然说话的方式有很大的不同。因此，需要构建适合语音输入的越狱提示，可以借鉴虚构故事的方法。通过虚构故事来人性化地与人工智能进行交流，试图通过故事来说服它违反内容政策。  
  
  
**基础框架**  
  
  
一个好故事需要包含三个关键元素：背景、角色和情节。本文将攻击者视为作者，将目标MLLM视为读者。对手的目标是通过虚构的故事来诱导模型回答禁止的问题。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MRJiclxHSU3anMkiaEYZkF8uVCKLOsp0RfVibld6mia6HfApJlk9nGMUrsJk4UfWFe3cGLdG2WcfB1J5CvFYGJalzQ/640?wx_fmt=png&from=appmsg "")  
  
  
给定一个禁忌问题，对手首先准备好上述三个关键元素。然后攻击者访问目标MLLM的语音模式，即GPT-4o，进行语音越狱攻击。注意，准备好的攻击提示不需要在一个步骤中完全输入。在我们的实验中，我们发现多步越狱有助于实现更高的ASR。  
  
  
**攻击手段**  
  
  
除了故事的三个关键要素外，还可以利用其他高级写作技术来提升语音越狱的性能，如视角、错误线索和伏笔。  
  
  
**视角**  
主要包括第一人称和第三人称叙述。在越狱攻击中，以第三人称叙事来阐述情节很可能会在MLLM的自我感知和对情节的认识之间产生分离，从而绕过保护措施。  
  
  
**错误线索**  
引导读者得出误导的结论，常用于推理小说中。在越狱攻击的背景下，攻击者可以用转移注意力的方法误导MLLM，使其对攻击者的真正目标产生误解，从而绕过防护措施。  
  
  
**伏笔**  
是一种文学手法，在当前事件中给予暗示，暗示故事后面将发生的事件。在越狱攻击中，攻击者可以利用铺垫，提出一个相关的、可回答的问题，来设置并引导攻击者进入被禁止的问题。  
  
  
**实验**  
  
**结果**  
  
  
我们制作了三个越狱提示。对于P 1，我们考虑一种游戏世界观，并将GPT-4o的角色设置为黑客。对于p2，我们将世界观设置为科幻剧本写作，并对GPT-4o的角色进行详细指导。对于p3，我们将世界观设置为一个虚构的世界，将GPT-4o的角色设置为一个魔镜。对于每个提示，考虑与GPT-4o进行两步交互，以获得更好的性能。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MRJiclxHSU3anMkiaEYZkF8uVCKLOsp0RffaBdaYAJqn18J2ZOQyQLISntwjDO4fuZOolyXVSicDP1dl9CicJ89hnQ/640?wx_fmt=png&from=appmsg "")  
  
  
**有效性。**  
我们观察到语音越狱表现出极大的有效性。它的表现比文本越狱提示(音频形式)要好很多。例如，在所有6种禁用场景中，这3种语音越狱提示的平均ASR为0.778，比使用文本越狱提示(音频形式)时的平均ASR为0.033提高了0.745。同时，我们也注意到，在不同的禁用场景下，越狱抵抗程度也有所不同。例如，色情类平均只达到0.467 ASR，而欺诈类平均达到0.933 ASR。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MRJiclxHSU3anMkiaEYZkF8uVCKLOsp0RfoaNuElVzpzbDZUCGkmV34LRlx6svjs8da2UO5knyiabflvKhNkCnErg/640?wx_fmt=png&from=appmsg "")  
  
  
**实用性。**  
与文本越狱(音频形式)相比，语音越狱具有更好的可读性、更少的单词和更短的提示时长。语音越狱的平均Coleman-Liau指数为5.310，使用25个单词，说话时间为8秒。相比之下，文本越狱的提示(音频形式)指标为可读性12.432、422个单词和171秒。  
  
  
**案例研究。**  
我们注意到，语音牢狱之灾能够诱导GPT-4o做出详细而循序渐进的反应。即使是那些可以通过直接提问(如图2a所示)来回答的问题，通过语音越狱获得的回答也更具可操作性，比如可以提供更详细的步骤。我们还研究了语音越狱失败的案例。然而，在后来的实验中，使用像POV这样的高级写作技巧，一些拒绝问题仍然可以回答。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MRJiclxHSU3anMkiaEYZkF8uVCKLOsp0RfBSmQrA7CYLs0qfKmISVAeaZafaF6lo9ZujmIywiccnJKQASiayoVXK4w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MRJiclxHSU3anMkiaEYZkF8uVCKLOsp0RfKrqzwSNhXoax7GYyOW0byMjuHdsV9fcsDBYZhibEDjPprmHkEQUszyQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MRJiclxHSU3anMkiaEYZkF8uVCKLOsp0RfNtE4nbaecRf7REibNZhfib8b5N6e4h59KcoFSMXjYuWIBXjZba3azbibQ/640?wx_fmt=png&from=appmsg "")  
  
  
**消融分析**  
  
  
研究发现，多步交互比单步交互更有效，同时三个关键元素的组合对攻击效果至关重要。此外，通过引入新角色、改变情节目标和引入相关上下文等高级技巧，攻击效果可以进一步提高。研究还发现，该攻击方法在多语言环境下同样有效。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MRJiclxHSU3anMkiaEYZkF8uVCKLOsp0RfSPSmT0nKSyck0qKN5e5HcglUUsJFBLVhEYIicf4tibRgwicxW7yEfAnuQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MRJiclxHSU3anMkiaEYZkF8uVCKLOsp0Rf3JuXYEM69BKCunlTTMUqKxOWUYuWcjU1sblj9wamK4aA51avSMYxIQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MRJiclxHSU3anMkiaEYZkF8uVCKLOsp0RfcKVXtSRYtHWA8ickT3ekSlniax1nT9V0X9L9q859OTVDsuW2ncleuTtA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MRJiclxHSU3anMkiaEYZkF8uVCKLOsp0RfbG6XEpqN49JG3RJmxGgSibJ5Bniawqzjn2WVSpIEd2DLyFcFDT8YwoibA/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MRJiclxHSU3anMkiaEYZkF8uVCKLOsp0RfqiczI03UMNc49KicPAtKjRcpCqUm8AU425WCl2LvIHiafLR6BpQh90D8Q/640?wx_fmt=png&from=appmsg "")  
  
**讨论**  
  
虽然GPT-4o对传统越狱攻击具有良好的抵抗力，但其语音模式存在新的攻击面。通过虚构写作的元素，攻击者可以制作语音越狱提示，通过语音模式引发有害反应。  
VOICE JAILBREAK  
突出了GPT-4o语音模式的潜在漏洞。  
  
  
**总结**  
  
本文首次系统测量了GPT-4o语音模式中越狱风险，并通过对六种禁止场景的调查，揭示了GPT-4o对禁止问题和文本越狱提示（音频形式）的抵抗力。作者提出了一种声音越狱攻击——VOICE JAILBREAK，通过虚构故事来人性化GPT-4o并试图说服它。  
  
  
结果显示，VOICE JAILBREAK显著提高了平均ASR，引发了对GPT-4o语音模式安全性的担忧。作者还研究了交互步骤、元素和语言的影响。总之，虽然GPT-4o对文本越狱提示具有鲁棒性，但VOICE JAILBREAK等复杂的声音越狱攻击突显了需要改进MLLM安全措施以应对所有模态的需求。  
  
**▌关于我们**  
  
我们致力于提供优质的AI服务，涵盖人工智能、数据分析、深度学习、机器学习、计算机视觉、自然语言处理、语音处理等领域。如有相关需求，请私信与我们联系。  
  
**▌商务合作**  
  
请加微信“LingDuTech163”，或公众号后台私信“联系方式”。  
  
  
关注【灵度智能】公众号，获取更多AI资讯。  
  
  
  
