#  Cyber Apocalypse 2023 硬件 CTF 题解   
原创 yichen  陈冠男的游戏人生   2025-01-03 04:17  
  
**AI 速读**  
  
**1、Timed Transmission**  
  
  
通过分析逻辑分析仪的波形图，识别出波形组成的文字，得到 flag  
  
**2、Critical Flight**  
  
  
解析 Gerber 文件，找到隐藏的字符串，拼接成 flag  
  
**3、Debug**  
  
  
通过分析 UART 通信的波特率，解码得到 flag  
  
**4、HM74**  
  
  
分析 Verilog 代码，对干扰的数据进行汉明码解码，通过统计分析得到 flag  
  
**5、Secret-Code**  
  
  
结合逻辑分析仪记录和 Gerber 文件，分析数码管的显示内容，通过通道与数码管的连接关系，还原出数码管显示的字符，最终得到 flag  
  
  
##   
  
**Timed Transmission**  
  
  
  
  
  
  
  
##   
  
下载附件得到一个 sal 文件，这个是逻辑分析仪 saleae 的配套软件 logic2 保存的文件格式，因此使用 logic2 打开，打开之后看着乱七八糟的波形有点懵，当要缩放一下看看细节的时候发现好像是波形组成了文字... flag 为：  
  
HTB{b391N_tH3_HArdWAr3_QU3St}  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/df1X0NvQ5KlrXZ75mYapGnFCEwlfzFo5Kxmsn16DZAqAsWyHKDrJvIibPs7EYP0EqGFLpX1icsxcWPONTamxayag/640?wx_fmt=png&from=appmsg "")  
  
  
**Critical Flight**  
  
  
  
  
  
  
  
  
下载后得到一堆 GBR 文件，这是 Gerber 格式，用来给 PCB 厂商打板子的，有些在线网站可以解析 gerber 压缩包格式  
  
```
https://viewer.digipcba.com/viewer/https://www.pcbway.com/project/OnlineGerberViewer.html
```  
  
  
  
直接上传题目压缩包后点击 layers 可以看到不同的层，然后点击小眼睛关闭某些层的干扰，能够找到两部分字符串，拼接起来为 flag：  
  
HTB{533_7h3_1nn32_w02k1n95_0f_313c720n1c5#$@}  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/df1X0NvQ5KlrXZ75mYapGnFCEwlfzFo5cHA13EFvDeTgLyDGqemeMjy1QNqibfxj18u6Eiaknw2ibZ2Kcib8n93UmQ/640?wx_fmt=png&from=appmsg "")  
  
  
**debug**  
  
  
  
  
  
  
  
  
下载附件得到一个 sal 文件，使用 logic2 打开，发现是通道 0 和 通道 1 标记着 TX 和 RX，那应该是 UART，鼠标放到波形图上，找个最窄的脉冲宽度，其时间为 8.68us 也就是 0.00000868s，1 / 0.00000868 ≈ 115200  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/df1X0NvQ5KlrXZ75mYapGnFCEwlfzFo51iaby4dk0ygyvNTseDR6ADvDveDpaIqzA6ow3taT8ibq3ZtMRMJ56VXw/640?wx_fmt=png&from=appmsg "")  
  
  
因此选择波特率 115200 尝试解码，得到 flag：  
  
HTB{547311173_n37w02k_c0mp20m153d}  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/df1X0NvQ5KlrXZ75mYapGnFCEwlfzFo5O5qJc2w5163ic0ednuyHiaTfjDeYG3P4abkGpq9ahicVKDZ6XdaTcbk5Q/640?wx_fmt=png&from=appmsg "")  
  
  
**HM74**  
  
  
  
  
  
  
  
  
下载后查看附件，发现是 verilog 代码  
  
```
module encoder(    input [3:0] data_in,    output [6:0] ham_out    );    wire p0, p1, p2;    assign p0 = data_in[3] ^ data_in[2] ^ data_in[0];    assign p1 = data_in[3] ^ data_in[1] ^ data_in[0];    assign p2 = data_in[2] ^ data_in[1] ^ data_in[0];        assign ham_out = {p0, p1, data_in[3], p2, data_in[2], data_in[1], data_in[0]};endmodulemodule main;    wire[3:0] data_in = 5;    wire[6:0] ham_out;    encoder en(data_in, ham_out);    initialbegin        #10;        $display("%b", ham_out);    endendmodule
```  
  
  
  
嗯？我是不是缺了点信息？看了看原题是这样描述的  
  
As you venture further into the depths of the tomb, your communication with your team becomes increasingly disrupted by noise. Despite their attempts to encode the data packets, the errors persist and prove to be a formidable obstacle. Fortunately, you have the exact Verilog module used in both ends of the communication. Will you be able to discover a solution to overcome the communication disruptions and proceed with your mission?当你进一步冒险进入坟墓深处时，你与团队的沟通会越来越受到噪音的干扰。尽管他们尝试对数据包进行编码，但错误仍然存在，并被证明是一个巨大的障碍。幸运的是，您在通信两端都使用了完全相同的 Verilog 模块。您能否找到解决方案来克服通信中断并继续执行您的任务？  
  
  
嗯，应该是还有个地址，nc 过去会获得一串数据，但是那串数据其实是有错误 bit 的，需要尝试对包含错误比特的数据进行解码，从 github 上搜到有人保存了 nc 获得的数据，那就以这段数据作为输入吧：  
  
https://github.com/MicheleMosca/CTF/blob/main/Cyber%20Apocalypse%202023/Hardware/HM74/signals.txt  
  
  
先来分析一下 verilog 代码，module main 主要就是实例化了 encoder 这个模块，然后打印比特，因此主要逻辑是在 encoder 模块的，通过这个模块的声明可以看到他接收 4bit 输入，产生 7bit 输出，我们应该能够通过其异或结果与原始数据对比，找出没有受到干扰的原始数据  
  
  
把从 nc 获取到的数据保存下来，根据 verilog 逻辑，应该是每 7bit 为一组，每组中除了原始数据，还有原始数据异或的结果，一开始想的是按照 verilog 逻辑，p0、p1、p2 与 data[0]、data[1]、data[2]、data[3] 异或的结果完全匹配则记为有效，结果算完发现有效的没几个...  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/df1X0NvQ5KlrXZ75mYapGnFCEwlfzFo5EzhDayKg3LiaZDPVCXVgialgwq4z5xWWIJTzgtg5KL0ic65JpsHyhPJnQ/640?wx_fmt=png&from=appmsg "")  
  
  
其实根据不同的异或结果，可以筛选出到底是哪一个 bit 错位了，然后再直接反转那个 bit 就好了  
  
```
def bit_check(data):    p0 = int(data[0])    p1 = int(data[1])    data_in3 = int(data[2])    p2 = int(data[3])    data_in2 = int(data[4])    data_in1 = int(data[5])    data_in0 = int(data[6])    p0_error = False    p1_error = False    p2_error = False    if (p0 != data_in3 ^ data_in2 ^ data_in0):        p0_error = True    if (p1 != data_in3 ^ data_in1 ^ data_in0):        p1_error = True    if (p2 != data_in2 ^ data_in1 ^ data_in0):        p2_error = True    if (p0_error == True) and (p1_error == True) and (p2_error == True):  # 如果三个都错了，说明data_in0错了        data_in0 = int(not data_in0)    if (p0_error == True) and (p1_error == True) and (p2_error == False): # 如果p2是对的，说明data_in3错了        data_in3 = int(not data_in3)    if (p0_error == True) and (p1_error == False) and (p2_error == True): # 如果p1是对的，说明data_in2错了        data_in2 = int(not data_in2)    if (p0_error == False) and (p1_error == True) and (p2_error == True): # 如果p0是对的，说明data_in1错了        data_in1 = int(not data_in1)    return str(data_in3)+str(data_in2)+str(data_in1)+str(data_in0)
```  
  
  
  
但问题是错的可能不只有一位，这就导致即使通过异或检查过后还是会有错误的结果，可以看到代码中经过检查后打印出来即使是有些符合 flag 规则的，也全都是错误  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/df1X0NvQ5KlrXZ75mYapGnFCEwlfzFo5w4tVJMG6OP9UcLJ2wUkmN8CJpicOHbAnWf9O9eDmfUC0VT3R6gznOcQ/640?wx_fmt=png&from=appmsg "")  
  
  
这时候可以考虑对结果进行统计，取其中出现频率最高的字符拼接出来，得到真实的 flag：  
  
HTB{hmm_w1th_s0m3_ana1ys15_y0u_c4n_3x7ract_7h3_h4mmin9_7_4_3nc_fl49}  
  
```
file = open("signals.txt",'r').readlines()def bit_check(data):    p0 = int(data[0])    p1 = int(data[1])    data_in3 = int(data[2])    p2 = int(data[3])    data_in2 = int(data[4])    data_in1 = int(data[5])    data_in0 = int(data[6])    p0_error = False    p1_error = False    p2_error = False    if (p0 != data_in3 ^ data_in2 ^ data_in0):        p0_error = True    if (p1 != data_in3 ^ data_in1 ^ data_in0):        p1_error = True    if (p2 != data_in2 ^ data_in1 ^ data_in0):        p2_error = True    if (p0_error == True) and (p1_error == True) and (p2_error == True): # 如果三个都错了，说明data_in0错了        data_in0 = int(not data_in0)    if (p0_error == True) and (p1_error == True) and (p2_error == False): # 如果p2是对的，说明data_in3错了        data_in3 = int(not data_in3)    if (p0_error == True) and (p1_error == False) and (p2_error == True): # 如果p1是对的，说明data_in2错了        data_in2 = int(not data_in2)    if (p0_error == False) and (p1_error == True) and (p2_error == True): # 如果p0是对的，说明data_in1错了        data_in1 = int(not data_in1)    data = str(data_in3)+str(data_in2)+str(data_in1)+str(data_in0)    return dataoutputs = [] # 包含所有输出的列表for line in file:    line = line[10:].strip()    s = ''    for i in range(0,len(line),7):        data = line[i:i+7]        data_checked = bit_check(data)        my_data = hex(int(data_checked,2))[2:]        s += my_data    try:        outputs.append(bytes.fromhex(s))        print(bytes.fromhex(s))    except:        passchar_counts = {} # 初始化一个字典，用于存储每个位置上的字符出现次数for output in outputs:  # 遍历每个输出    s = output.decode('latin1')  # 将字节串转换为字符串    for i, char in enumerate(s):   # 遍历字符串中的每个字符和它们的位置        if i notin char_counts:            char_counts[i] = {}    # 如果位置不在字典中，添加进去        if char in char_counts[i]:  # 如果字符已经在字典中，增加它的计数，否则设置为1            char_counts[i][char] += 1        else:            char_counts[i][char] = 1most_common_chars = ''for i in range(len(char_counts)):  # 找出每个位置上出现次数最多的字符    most_common_chars += max(char_counts[i], key=char_counts[i].get)print(most_common_chars)  # 打印结果
```  
  
  
  
**Secret-Code**  
  
  
  
  
  
  
  
  
下载下来之后打开，发现有一个逻辑分析仪的记录文件和一堆 Gerber 文件，打开逻辑分析仪记录文件，抓取了 8 个通道的波形，但不知道是什么含义  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/df1X0NvQ5KlrXZ75mYapGnFCEwlfzFo5byEXWzExGacHwKNIVSxYuRzsogUuX49zy4h3L0JkLJ4j4ySNz4qjnA/640?wx_fmt=png&from=appmsg "")  
  
  
Gerber 文件在线查看是一个圆形的 PCB，中间有一个数码管，数码管的各个引脚连接到了周围的触点上，触点还标记了 channelx 应该要与逻辑分析仪抓取的通道对应起来，那应该是要解析这些通道的高低电平，对应到不同的触点连接到的数码管的位置，从而还原出数码管显示的不同的字符  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/df1X0NvQ5KlrXZ75mYapGnFCEwlfzFo58mczBFNGVYhSJlBydg1tQCanaw1V9N9Zv1RqCC8DpkZtIlL918knQw/640?wx_fmt=png&from=appmsg "")  
  
  
首先梳理通道与数码管的连接关系，在立创商城随便找一个数码管的手册  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/df1X0NvQ5KlrXZ75mYapGnFCEwlfzFo5F16gttYcOskmNLjnoC1BjqyZTACrKdOmxGRP9U6YTau8IQ7TmgBlbQ/640?wx_fmt=png&from=appmsg "")  
  
  
根据手册，这个数码管的引脚定义可能是  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/df1X0NvQ5KlrXZ75mYapGnFCEwlfzFo5aNn4CibWC1m5CiadjPWliaEqjTk6ox6DBBwTrUttvVTI7jUeYVNYxXkKQ/640?wx_fmt=png&from=appmsg "")  
  
  
再根据电路走线，对应到各个通道就是：  
  
```
e <-> channel 6d <-> channel 0c <-> channel 4dp <-> channel 1b <-> channel 5a <-> channel 2f <-> channel 7g <-> channel 3
```  
  
  
  
观察逻辑分析仪波形，dp（即 channel1）非常规律，像是分割每个显示字符的，因此尝试以 dp 作为分割，根据其他通道的电平画出数码管的显示图案  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/df1X0NvQ5KlrXZ75mYapGnFCEwlfzFo5kjibOicoibWUQll6HJib5wicZmicTEkS1u98pvlkHib7hD9n6tly8zsEJW1Tg/640?wx_fmt=png&from=appmsg "")  
  
  
例如刚开始是：G、C、B、F 亮，在数码管上标记出来就是字符：4  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/df1X0NvQ5KlrXZ75mYapGnFCEwlfzFo5R0abg8WCIQRnE3R1H2jf8I5X3wzUFrmwo2IOdxQNGA7uzuRnDqe06Q/640?wx_fmt=png&from=appmsg "")  
  
  
如此整理完后得到：  
  
```
4854427b70307733325F63306d33355F6632306d5F77313768316E4021237d
```  
  
  
  
转为ascii 为：  
  
HTB{p0w32_c0m35_f20m_w17h1n@!#}  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/df1X0NvQ5KmRJHevRI20RJSCAwhewDo3sQtTKfAIJ5DxWahqdX3ialtb5ib4DSbqnxwVgtNicW3tHvdODO0R2VCxQ/640?wx_fmt=png "")  
  
  
