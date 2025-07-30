#  Chrome ipcz TOCTOU 漏洞分析与利用   
3bytes  3072   2024-08-29 22:44  
  
在这篇博客文章中，我们将深入探讨Chrome中新的IPC机制ipcz的一个有趣的漏洞，并看看如何从一个被攻破的渲染器中利用这个漏洞逃离Chrome的沙盒。以下分析和描述的利用技术基于Chromium 113.0.5672.77。  
## 背景  
  
漏洞代码是在2022年11月加入Chrome时引入的，目的是为Chrome添加对ipcz的支持。2023年3月31日，Google Project Zero的Mark Brand在问题40063855中报告了该漏洞，并最终在Chrome 114的稳定版本中修复了该问题。  
## 简介  
  
ipcz是Chrome使用的新IPC实现。它旨在替代mojo核心，解决一些与路由和数据传输相关的现有不足。  
  
在将ipcz添加到Chrome的过程中，加入了对Parcels的支持。  
```
commit da5cd04508573976a35a81780ef12f57bfc9bee9
Author: Ken Rockot <rockot@google.com>
Date:   Wed Nov 16 01:16:25 2022 +0000

    ipcz: Introduce parcel objects

    This introduces parcel objects as a first-class concept of the public
    ipcz API, replacing the concept of validators. In particular,
    applications have the option to Get() parcel objects from portals
    rather than getting the parcel's data and handles directly.

    Data and handles can then be retrieved from a parcel object in the
    same way they can be retrieved from portals, i.e. with the usual
    Get/BeginGet/EndGet APIs.

    This allows applications to consume individual parcel contents with
    two-phase I/O operations (i.e. with direct access to the parcel
    memory) without tying up the receiving portal in the meantime.

    MojoIpcz exploits this new API feature to avoid copying parcel data
    into its own type of MojoMessage objects, instead retaining a parcel
    handle and exposing message data via a two-phase get.

    Bug: 1299283
    Fixed: 1384208
    Change-Id: Iafd2efb16a1aa150dffb9baba9fe445ef01763e6
    Reviewed-on: https://chromium-review.googlesource.com/c/chromium/src/+/4023329
    Commit-Queue: Ken Rockot <rockot@google.com>
    Reviewed-by: Alex Gough <ajgo@chromium.org>
    Cr-Commit-Position: refs/heads/main@{#1071963}

```  
  
Parcels是用于在_Portals_之间传输应用数据和ipcz句柄的数据单元。Portals是_Nodes_之间的通信端点。每个进程，如浏览器、GPU或渲染器进程，都由一个节点表示。基本上，每次在ipcz中发生mojo方法调用时，底层数据都在一个parcel中传输。  
  
作为参考提交的一部分，代码被添加以根据通过parcel接收到的数据构建MojoMessage。  
```
bool MojoMessage::SetParcel(ScopedIpczHandle parcel) {
  DCHECK(!data_storage_);
  DCHECK(!parcel_.is_valid());

  parcel_ = std::move(parcel);

  const void* data;
  size_t num_bytes;
  size_t num_handles;
  IpczResult result = GetIpczAPI().BeginGet(
      parcel_.get(), IPCZ_NO_FLAGS, nullptr, &data, &num_bytes, &num_handles);
  if (result != IPCZ_RESULT_OK) {
    return false;
  }

  // Grab only the handles.
  handles_.resize(num_handles);
  result = GetIpczAPI().EndGet(parcel_.get(), 0, num_handles, IPCZ_NO_FLAGS,
                               nullptr, handles_.data());
  if (result != IPCZ_RESULT_OK) {
    return false;
  }

  // Now start a new two-phase get, which we'll leave active indefinitely for
  // `data_` to reference.
  result = GetIpczAPI().BeginGet(parcel_.get(), IPCZ_NO_FLAGS, nullptr, &data,  // [1]
                                 &num_bytes, &num_handles);
  if (result != IPCZ_RESULT_OK) {
    return false;
  }

  DCHECK_EQ(0u, num_handles);
  data_ = base::make_span(static_cast<uint8_t*>(const_cast<void*>(data)),  // [2]
                          num_bytes);
}

```  
  
在[1]处，代码调用了BeginGet，该函数获取了指向parcel数据的指针，使得data直接引用了底层共享内存。最后，代码在[2]处将一个覆盖该内存的span存储在其data_成员中。  
  
这将导致每次对序列化的mojo消息的操作都在底层共享内存上进行，使其容易受到检查时间与使用时间（TOCTOU）问题的影响，渲染器可以利用这些问题进行攻击。  
## 选择一个良好的利用原语  
  
这一变化破坏了Chrome代码库中其他部分的基本假设，即mojo消息的内容在反序列化和验证期间不能被更改。  
  
这打开了一个巨大的可能性窗口，展示了如何将此漏洞转化为一个稳定的沙盒逃逸方式。以下章节记录了一些想法，并最终描述了我们用来将该漏洞转化为受控堆损坏原语的技术。  
### 绕过通用的Mojo验证  
  
该漏洞允许绕过对mojo消息本身的任何验证。例如，可以通过在MessageHeader的name字段和0xffffffff之间来回切换来绕过任何发送的mojo消息的通用mojo验证方法。  
  
通用的mojo验证方法以以下代码开始，然后调用接口特定的验证方法：  
```
template <typename T>
bool ValidateRequestGenericT(Message* message,                             const char* class_name,                             base::span<const T> info) {
  if (!message->is_serialized() ||
      ControlMessageHandler::IsControlMessage(message)) {
    return true;
  }
}

```  
  
如果IsControlMessage返回true，它将跳过所有进一步的验证。仔细观察此方法，可以看到它仅对消息头的内容进行检查：  
```
bool ControlMessageHandler::IsControlMessage(const Message* message) {
  return message->header()->name == interface_control::kRunMessageId ||
         message->header()->name == interface_control::kRunOrClosePipeMessageId;
}

```  
  
如果MessageHeader的name字段被设置为kRunMessageId（0xffffffff）或kRunOrClosePipeMessageId（0xfffffffe），IsControlMessage将返回true，跳过任何进一步的验证。  
  
如果我们快速将其恢复为原始值，则消息将正常处理，执行mojo方法实现，但不会对消息进行任何验证。  
  
在以下章节中，我们将看看反序列化代码中的一些假设，这些假设是由mojo验证方法之一验证的。  
#### 针对Map反序列化的目标  
  
通过mojo传输的map反序列化代码隐含假设键和值的数量总是匹配的。  
```
static bool Deserialize(Data* input, UserType* output, Message* message) {
    if (!input)
      return CallSetToNullIfExists<Traits>(output);

    std::vector<UserKey> keys;
    std::vector<UserValue> values;

    if (!KeyArraySerializer::DeserializeElements(input->keys.Get(), &keys,
                                                 message) ||
        !ValueArraySerializer::DeserializeElements(input->values.Get(), &values,
                                                   message)) {
      return false;
    }

    DCHECK_EQ(keys.size(), values.size());                                          // [3]
    size_t size = keys.size();
    Traits::SetToEmpty(output);

    for (size_t i = 0; i < size; ++i) {
      if (!Traits::Insert(*output, std::move(keys[i]), std::move(values[i])))       // [4]
        return false;
    }
    return true;
  }
};

```  
  
如果这个假设不成立，代码将使[3]处的调试断言无效，并将在[4]处超出keys或values向量的范围。  
  
确保此假设始终成立的代码可以在相应的mojo验证方法中找到：  
```
class Map_Data {
 public:
  // |validate_params| must have non-null |key_validate_params| and
  // |element_validate_params| members.
  static bool Validate(const void* data,                       ValidationContext* validation_context,                       const ContainerValidateParams* validate_params) {
    if (!data)
      return true;
  [...]

    if (object->keys.Get()->size() != object->values.Get()->size()) {
      ReportValidationError(validation_context,
                            VALIDATION_ERROR_DIFFERENT_SIZED_ARRAYS_IN_MAP);
      return false;
    }

    return true;
  }

```  
  
由于我们可以绕过这些验证方法的使用，我们可以尝试在上面触发越界访问。不幸的是，libc++的硬化断言_LIBCPP_ASSERT_VALID_ELEMENT_ACCESS已在Chrome的std::vector实现中启用，这将阻止我们在这种情况下造成任何内存损坏。  
#### 数组反序列化代码  
  
Mojo数组反序列化代码如下所示：  
```
static bool DeserializeElements(Data* input,                                UserType* output,                                Message* message) {
    if (!Traits::Resize(*output, input->size()))
      return false;
    if (input->size()) {
      if constexpr (HasGetDataMethod<Traits, UserType>::value) {
        auto data = Traits::GetData(*output);
        memcpy(data, input->storage(), input->size() * sizeof(DataElement));
      } else {
        ArrayIterator<Traits, UserType> iterator(*output);
        for (size_t i = 0; i < input->size(); ++i)
          iterator.GetNext() = input->at(i);
      }
    }
    return true;
}

```  
  
这段代码存在一个TOCTOU（时间差错）问题，看起来非常有趣，因为它可能允许我们在浏览器和GPU进程中执行受控的堆溢出。不幸的是，memcpy的情况似乎没有被编译进去。所以我们总是会遇到使用std::vector::[]操作符的else情况，该操作符会写出边界，而这会被libc++的硬化断言捕获并导致崩溃。  
### 目标：MessagePipeReader的Channel接口中的Pickle  
  
MessagePipeReader::Receive方法为通过mojo传输的接收到的旧式IPC消息实现了一个unpickle操作。如果接收到一个被声明为IPC_MESSAGE_ROUTED的_routed_ IPC消息，将使用以下Pickle构造函数：  
```
Pickle::Pickle(const Pickle& other)
    : header_(nullptr),
      header_size_(other.header_size_),
      capacity_after_header_(0),
      write_offset_(other.write_offset_) {
  if (other.header_) {
    Resize(other.header_->payload_size);                                            // [5]
    memcpy(header_, other.header_, header_size_ + other.header_->payload_size);     // [6]
  }
}

```  
  
正如所见，在这种情况下，代码读取了mojo消息头other.header_->payload_size两次，使其容易受到TOCTOU问题的影响。在[5]处的Resize方法调用第一次读取了有效负载大小，通过PartitionAlloc分配了新缓冲区（而不是像在源Pickle中那样使用共享内存）。  
```
void Pickle::Resize(size_t new_capacity) {
  CHECK_NE(capacity_after_header_, kCapacityReadOnly);
  capacity_after_header_ = bits::AlignUp(new_capacity, kPayloadUnit);
  void* p = realloc(header_, GetTotalAllocatedSize());
  CHECK(p);
  header_ = reinterpret_cast<Header*>(p);
}

```  
  
在[6]处的后续memcpy操作第二次读取了有效负载大小，将数据从接收到的消息复制到分配的缓冲区中。因此，竞速mojo头的payload_size字段允许我们进行受控的堆损坏，具有受控的分配/溢出大小和受控的数据。竞速失败的话，只会将较小的数据量复制到过大的缓冲区中，不会产生任何副作用。  
  
由于这些良好的属性，我们决定利用这种堆损坏原语来利用该漏洞。  
### 创建堆溢出原语  
  
为了触发受控的堆溢出，我们利用了GinJavaBridgeHostMsg_ObjectWrapperDeleted IPC消息。这个消息是一个old-style IPC消息，接受一个32位整数作为参数，如下所示：  
```
IPC_MESSAGE_ROUTED1(GinJavaBridgeHostMsg_ObjectWrapperDeleted,
                    int32_t /* object_id */)

```  
  
由于此消息仅接受一个32位整数参数，其消息有效负载相对较小。由于我们的堆损坏原语基于发送消息的有效负载大小，我们需要在这种情况下增加发送的mojo消息的大小。  
  
我们可以使用渲染器钩子来扩展发送消息的大小，并附加将用于堆溢出的数据。然后，我们开始竞速消息头的有效负载大小字段，在期望的分配大小和用于堆溢出的大小之间来回切换。  
  
在浏览器进程中接收端可能会发生三种情况，它们会跳过堆损坏。  
  
在MessagePipeReader::Receive方法中，有以下检查：  
```
if (!message.IsValid()) {
    delegate_->OnBrokenDataReceived();
    return;
}

```  
  
竞速有效负载大小可能会导致IsValid方法返回false，从而导致早期退出，跳过执行分配/复制操作的Pickle构造函数。在这种情况下，消息只会被丢弃，我们可以重试。  
  
接下来，阻止堆损坏的两种情况可能出现在Pickle构造函数中：  
```
Resize(other.header_->payload_size);
memcpy(header_, other.header_, header_size_ + other.header_->payload_size);

```  
  
这里，代码可能会在Resize调用期间读取较大的大小，并在memcpy操作期间读取较小的大小，这只会进行短复制，没有任何不良后果。最后，Resize和memcpy操作可能都读取了相同的有效负载大小，这同样不会产生任何危险操作。  
  
所以我们可以反复尝试赢得竞速，直到我们成功触发堆损坏。  
### 扩展IPC块容量  
  
ipcz代码使用来自底层_缓冲池_的_blocks_来存储_fragments_。某些大小的块缓冲区会在NodeLinkMemory::NodeLinkMemory方法中预先创建，如下所示：  
```
const BlockAllocator allocators[] = {primary_buffer_.block_allocator_64(),
                                     primary_buffer_.block_allocator_256(),
                                     primary_buffer_.block_allocator_512(),
                                     primary_buffer_.block_allocator_1k(),
                                     primary_buffer_.block_allocator_2k(),
                                     primary_buffer_.block_allocator_4k()};

```  
  
如果我们试图发送超过这些大小的消息，代码会在NodeLinkMemory::AllocateFragment中尝试扩展块容量：  
```
// Use failure as a hint to possibly expand the pool's capacity. The
// caller's allocation will still fail, but maybe future allocations won't.
if (CanExpandBlockCapacity(block_size)) {
    RequestBlockCapacity(block_size, [](bool success) {
        if (!success) {
            DLOG(ERROR) << "Failed to allocate new block capacity.";
        }
    });
}

```  
  
CanExpandBlockCapacity方法检查IPCZ_MEMORY_FIXED_PARCEL_CAPACITY内存标志，并确保总块容量不会超过最大值。在Chrome 113的情况下，设置了此标志，这会阻止渲染器扩展发送数据包的块容量。  
  
当块容量无法扩展时，代码最终会将要发送的消息内容存储在PartitionAlloc分配中，而不是直接放置在共享内存中，从而阻止我们竞速它。  
  
为了仍然扩展消息所需大小的块容量，我们可以发送适当大小的消息，同时在渲染器中钩住CanExpandBlockCapacity方法以使其返回true。这将最终分配一个适当大小的共享内存段，并将其添加为未来消息传输的新块。  
  
这样我们就可以确保，即使是较大的大小，我们也可以始终竞速发送的消息。  
### 漏洞修复  
  
在被Google Project Zero的Mark Brand 报告 后，该漏洞在Chrome 114的稳定版本中得到了修复。  
  
以下提交修复了该问题：  
```
commit 93c6be3a42e702101af2f528bf79d624cd3bfed9
Author: Ken Rockot <rockot@google.com>
Date:   Mon Apr 3 19:43:13 2023 +0000

    MojoIpcz: Copy incoming messages early

    Fixed: 1429720
    Change-Id: Id6cb7269d3a3e9118cc6ff1579b56e18bf911c07
    Reviewed-on: https://chromium-review.googlesource.com/c/chromium/src/+/4390758
    Commit-Queue: Ken Rockot <rockot@google.com>
    Reviewed-by: Daniel Cheng <dcheng@chromium.org>
    Cr-Commit-Position: refs/heads/main@{#1125510}

diff --git a/mojo/core/ipcz_driver/mojo_message.cc b/mojo/core/ipcz_driver/mojo_message.cc
index da073af255795..e362f3db6003c 100644
--- a/mojo/core/ipcz_driver/mojo_message.cc
+++ b/mojo/core/ipcz_driver/mojo_message.cc
@@ -109,23 +109,20 @@ void MojoMessage::SetParcel(ScopedIpczHandle parcel) {
    // We always pass a parcel object in, so Begin/EndGet() must always succeed.
    DCHECK_EQ(result, IPCZ_RESULT_OK);

+  if (num_bytes > 0) {
+    data_storage_.reset(
+        static_cast<uint8_t*>(base::AllocNonScannable(num_bytes)));
+    memcpy(data_storage_.get(), data, num_bytes);
+  } else {


+    data_storage_.reset();
+  }
+  data_ = {data_storage_.get(), num_bytes};
+  data_storage_size_ = num_bytes;

  // Grab only the handles.
  handles_.resize(num_handles);
-  result = GetIpczAPI().EndGet(parcel_.get(), 0, num_handles, IPCZ_NO_FLAGS,
-                               nullptr, handles_.data());
-  DCHECK_EQ(result, IPCZ_RESULT_OK);

-  // Now start a new two-phase get, which we'll leave active indefinitely for
-  // `data_` to reference.
-  result = GetIpczAPI().BeginGet(parcel_.get(), IPCZ_NO_FLAGS, nullptr, &data,
-                                 &num_bytes, &num_handles);
+  result = GetIpczAPI().EndGet(parcel_.get(), num_bytes, num_handles,
+                               IPCZ_NO_FLAGS, nullptr, handles_.data());
  DCHECK_EQ(result, IPCZ_RESULT_OK);

-  DCHECK_EQ(0u, num_handles);
-  data_ = base::make_span(static_cast<uint8_t*>(const_cast<void*>(data)),
-                          num_bytes);
-
  if (!FixUpDataPipeHandles(handles_)) {
    // The handle list was malformed. Although this is a validation error, it
    // is not safe to trigger MojoNotifyBadMessage from within MojoReadMessage,

```  
  
现在，MojoMessage不再引用包裹的共享内存，而是复制数据，以便所有反序列化和验证都将在副本上进行。  
  
这成功修复了该问题，并使世界更加安全。  
  
  
