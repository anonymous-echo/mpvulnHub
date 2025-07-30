#  研究者利用OpenAI o3模型发现Linux内核远程零日漏洞   
原创 JunYi  毅心安全   2025-05-27 07:42  
  
   
# 研究者利用OpenAI o3模型发现Linux内核远程零日漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/kzkqdAEDfXdxianJtPUA7bFKbTTibteIg4C1ibuMp9srJSnIDmiaTq0GgNK0wW63Qshl67Lkw8ia6tz6bPWrwGCHInQ/640?wx_fmt=jpeg&from=appmsg "")  
### 文章背景  
  
文章的主角是 Sean Heelan，一位资深安全研究员，他在审计 Linux 内核的 SMB 实现 ksmbd  
 时，利用 OpenAI 最新推出的 o3 模型，成功发现了一个远程零日漏洞 CVE-2025-37899。ksmbd  
 是 Linux 内核中用于实现 SMB（Server Message Block）协议的模块，主要用于文件共享服务。由于 SMB 协议广泛应用于企业环境中，这个漏洞的发现具有重要意义。  
### 漏洞概览：CVE-2025-37899  
### 漏洞类型  
  
CVE-2025-37899 是一个 use-after-free（UAF，使用后释放） 漏洞，位于 ksmbd  
 的 logoff  
 命令处理程序 中。  
  
UAF 漏洞定义：当一个内存对象被释放后，程序仍然尝试访问或操作该内存地址时，就会触发 UAF 漏洞。这种情况可能导致未定义行为，包括程序崩溃甚至远程代码执行。  
### 漏洞位置  
  
漏洞出现在 ksmbd  
 处理 SMB 协议的 logoff  
 命令时。logoff 命令通常由客户端发送，用于通知服务器断开当前会话。  
## 漏洞细节分析  
### 成因分析  
  
漏洞的核心问题是 引用计数管理不当，结合 SMB 服务器的并发连接特性，导致了 UAF 的发生。以下是具体成因：  
### 1、对象释放  
  
在处理 logoff  
 命令时，ksmbd  
 会释放某个关键对象（例如会话或连接相关的结构体）。这个对象在释放后，其内存地址应该被标记为不可用。  
### 2、并发访问  
  
SMB 服务器支持多线程处理并发连接。当一个线程释放了该对象后，另一个线程可能仍在处理与该对象相关的操作，并尝试访问已被释放的内存。  
### 3、引用计数缺失  
  
该对象没有正确实现引用计数机制。正常情况下，引用计数用于跟踪对象的活跃引用数，只有当计数为零时，对象才会被安全释放。但在 ksmbd  
 中，设计缺陷导致对象在仍有线程引用时就被提前释放。  
### 推测的代码问题  
  
文章中未直接提供漏洞的代码片段，但根据描述，我推测问题可能出现在类似以下的逻辑中（伪代码表示）：  
```
struct session {
    int ref_count; // 引用计数    void *data;    // 数据指针};
void process_logoff(struct session *s) {    free(s->data); // 释放数据    free(s);       // 释放会话对象}void handle_connection(struct session *s) {    // 假设另一个线程仍在使用 s->data    process_data(s->data);}
```  
  
在上述伪代码中：  
  
process_logoff 函数释放了 s->data 和 s，但没有检查 ref_count 是否为零。  
如果 handle_connection 在并发线程中仍在访问 s->data，就会触发 UAF。  
## 漏洞利用方式  
  
文章未详细披露具体的利用方法，但基于 UAF 漏洞的特性，我可以推测一个可能的利用路径：  
### 1、触发对象释放  
  
攻击者通过发送精心构造的 logoff  
 命令，触发目标对象的释放。  
### 2、并发访问  
  
在对象释放后，攻击者立即通过另一个 SMB 连接访问同一对象。此时，内存可能仍未被覆盖，指向已被释放的地址。  
### 3、内存重用与控制  
- • 被释放的内存可能被操作系统重新分配给其他用途。  
  
- • 攻击者通过发送特定的 SMB 请求，控制重新分配的内存内容（例如堆喷射技术），从而覆盖关键数据（如函数指针）。  
  
- • 如果成功控制内存布局，可能实现任意代码执行。  
  
### 利用难度  
  
挑战：利用 UAF 需要精确控制内存分配和线程时序，属于高难度利用。  
可能性：由于 ksmbd  
 运行在内核态，成功利用可能导致远程提权或系统崩溃。  
## 漏洞发现方法  
### 使用 OpenAI o3 模型  
  
Sean Heelan 使用了 OpenAI 的 o3 模型，这是一个强大的大型语言模型（LLM），具备理解和分析代码的能力。发现过程如下：  
### 1、代码输入  
  
作者将 ksmbd  
 的相关代码（约 12,000 行）输入到 o3 模型中。这包括 logoff 命令处理程序及相关并发逻辑。  
### 2、模型分析  
  
o3 模型通过静态分析和语义理解，识别出潜在的漏洞点。特别地，它能够：  
理解并发连接的复杂性。  
检测未正确管理引用计数的对象。  
### 3、结果验证  
  
作者运行 o3 模型 100 次，其中 1 次成功发现了 CVE-2025-37899。虽然成功率仅 1%，但这表明 o3 在漏洞挖掘中的潜力。  
### 其他发现  
  
在分析过程中，o3 模型还重新发现了作者之前手动找到的漏洞 CVE-2025-37778（Kerberos 认证路径中的 UAF 漏洞），进一步验证了模型的有效性。  
### 代码示例  
  
由于文章未提供具体代码，我根据描述构造了一个可能的漏洞场景，供读者参考：  
```
#include <stdlib.h>
#include <pthread.h>

struct smb_session {    int active;     // 会话状态    char *buffer;   // 数据缓冲区};void *process_logoff(void *arg) {    struct smb_session *s = (struct smb_session *)arg;    free(s->buffer);  // 释放缓冲区    free(s);          // 释放会话对象    return NULL;}void *handle_request(void *arg) {    struct smb_session *s = (struct smb_session *)arg;    if (s->buffer) {  // 可能访问已释放的内存        s->buffer[0] = 'A';    }    return NULL;}int main() {    struct smb_session *session = malloc(sizeof(struct smb_session));    session->buffer = malloc(100);    session->active = 1;    pthread_t t1, t2;    pthread_create(&t1, NULL, process_logoff, session);    pthread_create(&t2, NULL, handle_request, session);    pthread_join(t1, NULL);    pthread_join(t2, NULL);    return 0;}
```  
### 代码说明  
  
process_logoff 线程释放 session 和 buffer。  
handle_request 线程可能在释放后访问 buffer，触发 UAF。  
缺少同步机制（如锁或引用计数）是漏洞的关键。  
## 总结与思考  
### 漏洞意义  
  
CVE-2025-37899 展示了 Linux 内核 SMB 实现中的潜在风险，尤其是在并发场景下。作为一个远程零日漏洞，它可能被恶意利用来攻击支持 SMB 的 Linux 服务器。  
### o3 模型的潜力  
  
OpenAI 的 o3 模型在漏洞发现中的应用令人振奋。尽管当前成功率较低，但其理解复杂代码和并发逻辑的能力，预示着 AI 在安全研究中的广阔前景。未来，随着模型优化，AI 辅助漏洞挖掘可能成为主流。  
### 安全建议  
  
开发者  
：在 ksmbd 中引入引用计数或锁机制，确保对象生命周期安全。用户  
：及时更新 Linux 内核，应用针对 CVE-2025-37899 的补丁。  
这篇文章不仅是一次技术突破的记录，也是 AI 与安全研究结合的里程碑。期待更多类似的创新案例！  
  
  
   
  
  
