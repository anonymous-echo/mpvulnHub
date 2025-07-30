#  「 特别预警」这个新iMessage 0-Click漏洞可能影响你   
原创 深蓝洞察  DARKNAVY   2023-09-22 20:38  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6aFicjrXnvggfeeAm8oZ8QfFZ9asOEiafk9gC55eZkunaiajTMsaFskRdkbgMs2ZFPg3PrYpbyQIfJE7HuAV6QgXg/640?wx_fmt=png "")  
  
  
两周前的2023 年 9 月 7 日，Apple发布了一个紧急安全更新，警告已有“频繁的外部攻击报告”，敦促Apple产品用户尽快安装。  
  
  
但这条更新和警告并未引起过多关注。事实上这涉及一个  
**iPhone上危险程度最高级别的在野漏洞利用 - iMessage 0-Click （零点击/无感知）**  
攻击  
事件。  
  
  
本周一，DARKNAVY 重现了该更新所涉及的漏洞利用。综合分析研判结果表明，该漏洞（  
CVE-2023-41064   
& 4863  
）影响面巨大、攻击投递方式丰富。  
  
  
经  
 D  
ARKNAVY 快速实测发现，除了尚未安装修复程序的iPhone、iPad和Mac用户存在被 0-Click攻击的风险，甚至包括  
Windows和Android  
系统下使用受影响组件的其他软件（如  
Chrome、Firefox、微信、钉钉、QQ等）  
的用户  
，  
都  
面临被攻击的风险。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/6aFicjrXnvggfeeAm8oZ8QfFZ9asOEiafkCa0cYkQheMYQouuTZJe4SL5ELGXFzW9IIN2SQzGqiblIJ6oQDF5qib1g/640?wx_fmt=gif "")  
  
Android   
平台  
下钉钉  
受此漏洞影响  
  
  
9月11-12日，Google和Mozzila相继发布了针对此漏洞的补丁。**但更多受此漏洞组件影响的软件厂商，目前仍未发布安全修复程序**  
。  
  
  
今天，9月22日，针对该漏洞的PoC已在网络上被公开。同时，鉴于该漏洞在今年年初已被部署在著名网络军火商 NSO 研发的 Pegasus 间谍软件中，多名俄罗斯记者在今年夏天已遭受该漏洞的攻击、其  
iPhone手机被监听，**DARKNAVY特发布本预警，敦促相关受影响的厂商尽早发布安全修复程序，受影响产品的用户需第一时间安装更新**  
。  
  
  
这不是 iMessage 第一次被发现零点击漏洞。  
  
在 2021 年 9 月中旬，苹果也发布了一次紧急安全更新，用于修补一个针对 iMessage 的零点击漏洞ForcedEntry（CVE-2021-30860）。  
  
该漏洞能绕过 Apple 的 BlastDoor，被用于NSO公司开发的Pegasus间谍软件，实施监视活动。  
  
0-Click， 零点击攻击，可以在没有任何用户交互（如点击链接、打开恶意文件等）的情况下进行攻击，在受害者的设备上静默安装恶意软件、执行其他恶意操作，攻击过程不会留下任何痕迹。  
  
这也意味着，即使被攻击的目标有很强的安全意识，不会随意点击陌生链接，也会在不知不觉中受到攻击。  
  
正因如此，0-Click 被认为是复杂度最高、难度最大、最高级的漏洞利用攻击方法之一：  
“高度复杂，开发成本达数百万美元，而且通常有效期很短”，相关攻击“利用特殊资源来针对极少数特定个人及其设备，难以检测和预防”。  
  
  
  
本次漏洞利用链 (  
CVE-2023-41064  
 与 CVE-2023-41061）是由加拿大多伦多大学 Citizen Lab 团队发现。  
  
事情源于2023年夏天。  
一位  
俄罗斯女记者加林娜·蒂姆琴科 (Galina Timchenko) 收到苹果公司的提醒：  
她的iPhone已经成为间谍软件的攻击目标，而她本人却对此毫不知情。  
  
  
随后几天，其他几名俄罗斯记者也陆续收到了通知，他们同样被蒙在鼓里。  
有记者反映：  
手机有时会发热或自行群发消息。于是加林娜委托监管和安全机构对手机进行分析。  
  
  
9月初，Access Now和Citizen Lab的调查结果揭露了真相。  
  
  
Citizen Lab团队在被攻击的手机上，发现并确认了针对iMessage的零点击攻击BLASTPASS。该攻击能绕过Apple的BlastDoor，对受害者手机实施无感知监视活动。  
  
  
DARKNAVY分析发现，与2021年相比，这次  
的漏洞利用影响范围更广。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/6aFicjrXnvggfeeAm8oZ8QfFZ9asOEiafktIKCtKNMbd8D0HN3NuwHhR89sVuE5qgT0mtDuXnibcYaHXciayk0DOcQ/640?wx_fmt=png "")  
  
Windows 平台下微信亦受影响  
  
  
本次漏洞根源，位于webp图片的处理代码逻辑中。当解析一个无损格式的webp图片时，解码器采用了范式霍夫曼编码 (Canonical Huffman Code) 算法，首先从图片流中读取前缀编码的数据，基于此数据构建一个完整的霍夫曼编码表，随后依照这个编码表对图片流中的压缩数据进行解码，得到原始的图像。  
  
  
  
霍夫曼编码（Huffman Coding），是一种用于无损数据压缩的熵编码（权编码）算法。  
  
在计算机资料处理中，霍夫曼编码使用变长编码表对源符号（如文件中的一个字母）进行编码。  
  
变长编码表通过一种评估来源符号出现概率的方法得到，出现概率高的字母使用较短的编码，反之出现概率低的则使用较长的编码。  
  
这可以使编码后的字符串平均长度、期望值降低，从而达到无损压缩数据的目的。  
  
  
  
根据范式霍夫曼算法，在构建一个霍夫曼表时，首先会使用一级表，用于查询长度小于 N bit (N 默认为 8) 的霍夫曼编码；随后，若出现了长度超过 N bit 的编码，解码器会为其分配二级表，用于查询超过 N bit 的编码部分。  
  
  
在分配霍夫曼编码表的内存空间时，解码器提前会将所有一级表和二级表的空间一并分配出来，其内存大小是固定的：  
  
```
#define FIXED_TABLE_SIZE (630 * 3 + 410)
static const uint16_t kTableSize[12] = {
  FIXED_TABLE_SIZE + 654,
  FIXED_TABLE_SIZE + 656,
  FIXED_TABLE_SIZE + 658,
  FIXED_TABLE_SIZE + 662,
  FIXED_TABLE_SIZE + 670,
  FIXED_TABLE_SIZE + 686,
  FIXED_TABLE_SIZE + 718,
  FIXED_TABLE_SIZE + 782,
  FIXED_TABLE_SIZE + 912,
  FIXED_TABLE_SIZE + 1168,
  FIXED_TABLE_SIZE + 1680,
  FIXED_TABLE_SIZE + 2704
};

const int table_size = kTableSize[color_cache_bits];
huffman_tables = (HuffmanCode*)WebPSafeMalloc(num_htree_groups * table_size,
                                                sizeof(*huffman_tables));
```  
  
  
问题在于，解码器默认图片中保存的霍夫曼编码表数据是合理的，因此提前计算了这一情况下能够容纳的最大内存长度。而霍夫曼编码表数据是来自不受信任源的，是可以由攻击者任意构造的，且编码器不会对这些数据进行有效性检查。  
  
```
    // Fill in 2nd level tables and add pointers to root table.
    for (len = root_bits + 1, step = 2; len <= MAX_ALLOWED_CODE_LENGTH;
         ++len, step <<= 1) {
      num_open <<= 1;
      num_nodes += num_open;
      num_open -= count[len];
      if (num_open < 0) {
        return 0;
      }
      if (root_table == NULL) continue;
      for (; count[len] > 0; --count[len]) {
        HuffmanCode code;
        if ((key & mask) != low) {
          table += table_size;
          table_bits = NextTableBitSize(count, len, root_bits);
          table_size = 1 << table_bits;
          total_size += table_size;
          low = key & mask;
          root_table[low].bits = (uint8_t)(table_bits + root_bits);
          root_table[low].value = (uint16_t)((table - root_table) - low);
        }
        code.bits = (uint8_t)(len - root_bits);
        code.value = (uint16_t)sorted[symbol++];
        ReplicateValue(&table[key >> root_bits], step, table_size, code); // overflow here
        key = GetNextKey(key, len);
      }
    }
```  
  
  
因此，如果攻击者能够构造出一个非法的霍夫曼表，包含了大量的长编码，这将导致解码器将分配过多的二级表，使得霍夫曼表的总内存大小超过分配大小，发生堆缓冲区溢出。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/6aFicjrXnvggfeeAm8oZ8QfFZ9asOEiafk12shZH9BJVLT3UUm2OeSPuzdtxicibnovo7uFQylUiadUndSHRb5zPVaQ/640?wx_fmt=jpeg "")  
  
DARKNAVY在Chrome上的漏洞重现  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/6aFicjrXnvggfeeAm8oZ8QfFZ9asOEiafk3YorxBTHibVyxZPn94SqQLDpjuRdBGXXoBOwiaMrCBXJLp7sSCQ95HZQ/640?wx_fmt=jpeg "Black White Grey Simple Fashion Style Poster Instagram Story (3).jpg")  
  
  
  
本案例中，漏洞发生在一个常用基础库中，实际受影响的软件产品数量超乎想象，但能及时修复漏洞的厂商微乎其微。  
  
  
管中窥豹，与Chrome、FireFox等团队相比，国内软件开发团队在漏洞信息获取、漏洞研判、漏洞修复、应急响应等诸多环节存在明显不足。  
  
  
只有安全应急从被动走向主动，才能让“安全”更真实。  
  
  
  
  
**参  考：**  
  
[1] https://citizenlab.ca/2023/09/blastpass-nso-group-iphone-zero-click-zero-day-exploit-captured-in-the-wild/  
  
[2] https://support.apple.com/en-us/HT213905  
  
[3] https://chromereleases.googleblog.com/2023/09/stable-channel-update-for-desktop_11.html  
  
[4] https://www.mozilla.org/en-US/security/advisories/mfsa2023-40/  
  
[5] https://www.accessnow.org/publication/hacking-meduza-pegasus-spyware-used-to-target-putins-critic/  
  
  
**GEEKCON 2023**  
  
  
[](http://mp.weixin.qq.com/s?__biz=Mzk0NzQ5MDYyNw==&mid=2247484381&idx=1&sn=47e1bdd787895acc7dc06958f9d29ca1&chksm=c37759f1f400d0e78049554ba1c4aafa90a451c0c0e5178ab26ebbf1c8638c83ebd1b69fdd3f&scene=21#wechat_redirect)  
  
  
DARKNAVY·深蓝旗下全新前沿安全极客技术活动平台 GEEKCON·新极棒 2023 中国站将于 10 月 24 日在上海西岸举行，早鸟票限时售卖中。  
  
  
All in 极致技术，这场面向未来的极客专属活动，欢迎你的加入！  
  
  
