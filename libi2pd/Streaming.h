/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#ifndef STREAMING_H__
#define STREAMING_H__

#include <inttypes.h>
#include <string>
#include <unordered_map>
#include <set>
#include <queue>
#include <functional>
#include <memory>
#include <mutex>
#include <boost/asio.hpp>
#include "Base.h"
#include "I2PEndian.h"
#include "Identity.h"
#include "LeaseSet.h"
#include "I2NPProtocol.h"
#include "Garlic.h"
#include "Tunnel.h"
#include "util.h" // MemoryPool

namespace i2p
{
namespace client
{
	class ClientDestination;
}
namespace stream
{
	const uint16_t PACKET_FLAG_SYNCHRONIZE = 0x0001;
	const uint16_t PACKET_FLAG_CLOSE = 0x0002;
	const uint16_t PACKET_FLAG_RESET = 0x0004;
	const uint16_t PACKET_FLAG_SIGNATURE_INCLUDED = 0x0008;
	const uint16_t PACKET_FLAG_SIGNATURE_REQUESTED = 0x0010;
	const uint16_t PACKET_FLAG_FROM_INCLUDED = 0x0020;
	const uint16_t PACKET_FLAG_DELAY_REQUESTED = 0x0040;
	const uint16_t PACKET_FLAG_MAX_PACKET_SIZE_INCLUDED = 0x0080;
	const uint16_t PACKET_FLAG_PROFILE_INTERACTIVE = 0x0100;
	const uint16_t PACKET_FLAG_ECHO = 0x0200;
	const uint16_t PACKET_FLAG_NO_ACK = 0x0400;
	const uint16_t PACKET_FLAG_OFFLINE_SIGNATURE = 0x0800;

	const size_t STREAMING_MTU = 1730;
	const size_t STREAMING_MTU_RATCHETS = 1812;
	const size_t MAX_PACKET_SIZE = 4096;
	const size_t COMPRESSION_THRESHOLD_SIZE = 66;
	const int MAX_NUM_RESEND_ATTEMPTS = 9;
	const int WINDOW_SIZE = 6; // in messages
	const int MIN_WINDOW_SIZE = 1;
	const int MAX_WINDOW_SIZE = 128;
	const int WINDOW_SIZE_DROP_FRACTION = 10; // 1/10
	const double RTT_EWMA_ALPHA = 0.125;
	const int MIN_RTO = 20; // in milliseconds
	const int INITIAL_RTT = 8000; // in milliseconds
	const int INITIAL_RTO = 9000; // in milliseconds
	const int MIN_SEND_ACK_TIMEOUT = 2; // in milliseconds
	const int SYN_TIMEOUT = 200; // how long we wait for SYN after follow-on, in milliseconds
	const size_t MAX_PENDING_INCOMING_BACKLOG = 128;
	const int PENDING_INCOMING_TIMEOUT = 10; // in seconds
	const int MAX_RECEIVE_TIMEOUT = 20; // in seconds
	const uint16_t DELAY_CHOKING = 60000; // in milliseconds

	struct Packet // 数据包结构
	{
		size_t len, offset; // 数据包长度和偏移量
		uint8_t buf[MAX_PACKET_SIZE]; // 数据包缓冲区
		uint64_t sendTime; // 发送时间
		bool resent; // 重发标志

		Packet (): len (0), offset (0), sendTime (0), resent (false) {}; // 构造函数
		uint8_t * GetBuffer () { return buf + offset; }; // 获取缓冲区指针
		size_t GetLength () const { return len - offset; }; // 获取有效长度

		uint32_t GetSendStreamID () const { return bufbe32toh (buf); }; // 获取发送流ID
		uint32_t GetReceiveStreamID () const { return bufbe32toh (buf + 4); }; // 获取接收流ID
		uint32_t GetSeqn () const { return bufbe32toh (buf + 8); }; // 获取序列号
		uint32_t GetAckThrough () const { return bufbe32toh (buf + 12); }; // 获取确认号
		uint8_t GetNACKCount () const { return buf[16]; }; // 获取NACK计数
		uint32_t GetNACK (int i) const { return bufbe32toh (buf + 17 + 4 * i); }; // 获取指定NACK
		const uint8_t * GetNACKs () const { return buf + 17; }; // 获取所有NACKs
		const uint8_t * GetOption () const { return buf + 17 + GetNACKCount ()*4 + 3; }; // 获取选项
		uint16_t GetFlags () const { return bufbe16toh (GetOption () - 2); }; // 获取标志
		uint16_t GetOptionSize () const { return bufbe16toh (GetOption ()); }; // 获取选项大小
		const uint8_t * GetOptionData () const { return GetOption () + 2; }; // 获取选项数据
		const uint8_t * GetPayload () const { return GetOptionData () + GetOptionSize (); }; // 获取有效载荷

		bool IsSYN () const { return GetFlags () & PACKET_FLAG_SYNCHRONIZE; }; // 判断是否为SYN数据包
		bool IsNoAck () const { return GetFlags () & PACKET_FLAG_NO_ACK; }; // 判断是否无确认
		bool IsEcho () const { return GetFlags () & PACKET_FLAG_ECHO; }; // 判断是否为回声数据包
	};

	struct PacketCmp // 数据包比较器，用于排序
	{
		bool operator() (const Packet * p1, const Packet * p2) const
		{
			return p1->GetSeqn () < p2->GetSeqn (); // 比较序列号
		};
	};

	typedef std::function<void (const boost::system::error_code& ecode)> SendHandler; // 发送处理器类型
	struct SendBuffer // 发送缓冲区结构
	{
		uint8_t * buf; // 缓冲区指针
		size_t len, offset; // 缓冲区长度和偏移量
		SendHandler handler; // 处理器

		SendBuffer (const uint8_t * b, size_t l, SendHandler h):
			len(l), offset (0), handler(h) // 构造函数
		{
			buf = new uint8_t[len]; // 分配缓冲区
			memcpy (buf, b, len); // 拷贝数据
		}
		SendBuffer (size_t l): // 创建空缓冲区
			len(l), offset (0)
		{
			buf = new uint8_t[len]; // 分配缓冲区
		}
		~SendBuffer ()
		{
			delete[] buf; // 释放缓冲区
			if (handler) handler(boost::system::error_code ()); // 调用处理器
		}
		size_t GetRemainingSize () const { return len - offset; }; // 获取剩余大小
		const uint8_t * GetRemaningBuffer () const { return buf + offset; }; // 获取剩余缓冲区
		void Cancel () { if (handler) handler (boost::asio::error::make_error_code (boost::asio::error::operation_aborted)); handler = nullptr; }; // 取消发送
	};

	// SendBufferQueue 类用于管理发送缓冲区的队列。
	class SendBufferQueue
	{
		public:

			// 默认构造函数，初始化队列的大小为 0。
			SendBufferQueue (): m_Size (0) {};

			// 析构函数，调用 CleanUp 函数清理缓冲区。
			~SendBufferQueue () { CleanUp (); };

			// 将一个发送缓冲区添加到队列中。
			// @param buf 需要添加的发送缓冲区的智能指针。
			void Add (std::shared_ptr<SendBuffer> buf);

			// 从队列中获取数据并填充到提供的缓冲区中。
			// @param buf 用于存放从队列中读取的数据的缓冲区。
			// @param len 提供的缓冲区的长度。
			// @return 实际读取到的字节数。
			size_t Get (uint8_t * buf, size_t len);

			// 获取当前队列的大小（即发送缓冲区的数量）。
			// @return 当前队列的大小。
			size_t GetSize () const { return m_Size; };

			// 检查队列是否为空。
			// @return 如果队列为空则返回 true，否则返回 false。
			bool IsEmpty () const { return m_Buffers.empty (); };

			// 清理队列中的所有缓冲区，释放相关资源。
			void CleanUp ();

		private:

			// 存储发送缓冲区的列表，使用智能指针以自动管理内存。
			std::list<std::shared_ptr<SendBuffer>> m_Buffers;

			// 当前队列的大小（缓冲区的数量）。
			size_t m_Size;
	};

	enum StreamStatus
	{
		eStreamStatusNew = 0,
		eStreamStatusOpen,
		eStreamStatusReset,
		eStreamStatusClosing,
		eStreamStatusClosed,
		eStreamStatusTerminated
	};


	// 前向声明 StreamingDestination 类
	class StreamingDestination;
	// Stream 类，表示一个流的实现，继承自 std::enable_shared_from_this
	class Stream: public std::enable_shared_from_this<Stream>
	{
	public:
		// 构造函数，创建一个发起的流，使用指定的 io_service 和本地 StreamingDestination
		// remote 参数是远程 LeaseSet 的共享指针，port 默认为 0
		Stream (boost::asio::io_service& service, StreamingDestination& local,
				std::shared_ptr<const i2p::data::LeaseSet> remote, int port = 0);

		// 构造函数，创建一个接收的流，使用指定的 io_service 和本地 StreamingDestination
		Stream (boost::asio::io_service& service, StreamingDestination& local);

		// 析构函数
		~Stream ();

		// 获取发送流 ID
		uint32_t GetSendStreamID () const { return m_SendStreamID; };
		
		// 获取接收流 ID
		uint32_t GetRecvStreamID () const { return m_RecvStreamID; };
		
		// 获取远程 LeaseSet
		std::shared_ptr<const i2p::data::LeaseSet> GetRemoteLeaseSet () const { return m_RemoteLeaseSet; };
		
		// 获取远程身份
		std::shared_ptr<const i2p::data::IdentityEx> GetRemoteIdentity () const { return m_RemoteIdentity; };

		// 检查流是否打开
		bool IsOpen () const { return m_Status == eStreamStatusOpen; };
		
		// 检查流是否已建立
		bool IsEstablished () const { return m_SendStreamID; };
		
		// 获取流状态
		StreamStatus GetStatus () const { return m_Status; };
		
		// 获取本地目标
		StreamingDestination& GetLocalDestination () { return m_LocalDestination; };

		// 处理下一个数据包
		void HandleNextPacket (Packet * packet);
		
		// 处理 Ping 数据包
		void HandlePing (Packet * packet);
		
		// 发送数据
		size_t Send (const uint8_t * buf, size_t len);
		
		// 异步发送数据
		void AsyncSend (const uint8_t * buf, size_t len, SendHandler handler);
		
		// 发送 Ping 消息
		void SendPing ();

		// 异步接收数据，提供接收缓冲区和处理程序
		template<typename Buffer, typename ReceiveHandler>
		void AsyncReceive (const Buffer& buffer, ReceiveHandler handler, int timeout = 0);

		// 读取部分数据，返回读取的字节数
		size_t ReadSome (uint8_t * buf, size_t len) { return ConcatenatePackets (buf, len); };
		
		// 接收数据，返回接收到的字节数，支持超时
		size_t Receive (uint8_t * buf, size_t len, int timeout);

		// 异步关闭流
		void AsyncClose() { m_Service.post(std::bind(&Stream::Close, shared_from_this())); };

		// 关闭流，注意此函数只能在目标线程中调用，其他线程请使用 AsyncClose
		void Close ();
		
		// 取消接收定时器
		void Cancel () { m_ReceiveTimer.cancel (); };

		// 获取已发送字节数
		size_t GetNumSentBytes () const { return m_NumSentBytes; };
		
		// 获取已接收字节数
		size_t GetNumReceivedBytes () const { return m_NumReceivedBytes; };
		
		// 获取发送队列大小
		size_t GetSendQueueSize () const { return m_SentPackets.size (); };
		
		// 获取接收队列大小
		size_t GetReceiveQueueSize () const { return m_ReceiveQueue.size (); };
		
		// 获取发送缓冲区大小
		size_t GetSendBufferSize () const { return m_SendBuffer.GetSize (); };
		
		// 获取窗口大小
		int GetWindowSize () const { return m_WindowSize; };
		
		// 获取往返时间（RTT）
		int GetRTT () const { return m_RTT; };

		// 终止流，可以选择是否从目标中删除
		void Terminate (bool deleteFromDestination = true);

	private:
		// 清理资源
		void CleanUp ();

		// 发送缓冲区
		void SendBuffer ();
		
		// 发送快速确认
		void SendQuickAck ();
		
		// 发送关闭消息
		void SendClose ();
		
		// 发送数据包
		bool SendPacket (Packet * packet);
		
		// 发送数据包集合
		void SendPackets (const std::vector<Packet *>& packets);
		
		// 发送更新的 LeaseSet
		void SendUpdatedLeaseSet ();

		// 保存数据包
		void SavePacket (Packet * packet);
		
		// 处理数据包
		void ProcessPacket (Packet * packet);
		
		// 处理选项
		bool ProcessOptions (uint16_t flags, Packet * packet);
		
		// 处理确认数据包
		void ProcessAck (Packet * packet);
		
		// 将多个数据包拼接成一个缓冲区
		size_t ConcatenatePackets (uint8_t * buf, size_t len);

		// 更新当前远程 Lease
		void UpdateCurrentRemoteLease (bool expired = false);

		// 处理接收定时器
		template<typename Buffer, typename ReceiveHandler>
		void HandleReceiveTimer (const boost::system::error_code& ecode, const Buffer& buffer, ReceiveHandler handler, int remainingTimeout);

		// 安排重新发送
		void ScheduleResend ();
		
		// 处理重新发送定时器
		void HandleResendTimer (const boost::system::error_code& ecode);
		
		// 安排确认发送
		void ScheduleAck (int timeout);
		
		// 处理确认发送定时器
		void HandleAckSendTimer (const boost::system::error_code& ecode);

	private:
		// 引用的 io_service 对象
		boost::asio::io_service& m_Service;

		// 发送和接收流 ID
		uint32_t m_SendStreamID, m_RecvStreamID, m_SequenceNumber;
		
		// 隧道变化序列号
		uint32_t m_TunnelsChangeSequenceNumber;
		
		// 最后接收到的序列号
		int32_t m_LastReceivedSequenceNumber;

		// 流状态
		StreamStatus m_Status;

		// 是否安排了确认发送
		bool m_IsAckSendScheduled;

		// 本地目标
		StreamingDestination& m_LocalDestination;

		// 远程身份
		std::shared_ptr<const i2p::data::IdentityEx> m_RemoteIdentity;

		// 用于离线密钥的临时验证器
		std::shared_ptr<const i2p::crypto::Verifier> m_TransientVerifier;

		// 远程 LeaseSet
		std::shared_ptr<const i2p::data::LeaseSet> m_RemoteLeaseSet;

		// 路由会话
		std::shared_ptr<i2p::garlic::GarlicRoutingSession> m_RoutingSession;

		// 当前远程 Lease
		std::shared_ptr<const i2p::data::Lease> m_CurrentRemoteLease;

		// 当前出站隧道
		std::shared_ptr<i2p::tunnel::OutboundTunnel> m_CurrentOutboundTunnel;

		// 接收队列
		std::queue<Packet *> m_ReceiveQueue;

		// 保存的数据包集合
		std::set<Packet *, PacketCmp> m_SavedPackets;

		// 发送的数据包集合
		std::set<Packet *, PacketCmp> m_SentPackets;

		// 定时器
		boost::asio::deadline_timer m_ReceiveTimer, m_ResendTimer, m_AckSendTimer;

		// 发送和接收的字节数
		size_t m_NumSentBytes, m_NumReceivedBytes;

		// 端口号
		uint16_t m_Port;

		// 发送缓冲队列
		SendBufferQueue m_SendBuffer;

		// 往返时间（RTT）
		double m_RTT;

		// 窗口大小
		int m_WindowSize, m_RTO, m_AckDelay;

		// 最后窗口大小增加的时间
		uint64_t m_LastWindowSizeIncreaseTime;

		// 重发尝试次数
		int m_NumResendAttempts;

		// 最大传输单元
		size_t m_MTU;
	};


	class StreamingDestination : public std::enable_shared_from_this<StreamingDestination>
	{
	public:
		// 定义接受器函数类型，用于处理新创建的流
		typedef std::function<void (std::shared_ptr<Stream>)> Acceptor;

		// 构造函数，初始化 StreamingDestination 对象
		StreamingDestination(std::shared_ptr<i2p::client::ClientDestination> owner, uint16_t localPort = 0, bool gzip = false);
		// 析构函数
		~StreamingDestination();

		// 启动该 StreamingDestination，开始处理流
		void Start();
		// 停止该 StreamingDestination，结束流处理
		void Stop();

		// 创建新的出站流，使用指定的远程 LeaseSet 和端口
		std::shared_ptr<Stream> CreateNewOutgoingStream(std::shared_ptr<const i2p::data::LeaseSet> remote, int port = 0);
		// 发送 Ping 消息到指定的远程 LeaseSet
		void SendPing(std::shared_ptr<const i2p::data::LeaseSet> remote);
		// 删除指定的流
		void DeleteStream(std::shared_ptr<Stream> stream);
		// 根据接收流 ID 删除流
		bool DeleteStream(uint32_t recvStreamID);
		// 设置接收器，用于处理流
		void SetAcceptor(const Acceptor& acceptor);
		// 重置接收器
		void ResetAcceptor();
		// 检查接收器是否已设置
		bool IsAcceptorSet() const { return m_Acceptor != nullptr; };
		// 接收一次流
		void AcceptOnce(const Acceptor& acceptor);
		// 处理单次接受流的函数
		void AcceptOnceAcceptor(std::shared_ptr<Stream> stream, Acceptor acceptor, Acceptor prev);
		// 同步接受流
		std::shared_ptr<Stream> AcceptStream(int timeout = 0);

		// 获取拥有该 StreamingDestination 的 ClientDestination
		std::shared_ptr<i2p::client::ClientDestination> GetOwner() const { return m_Owner; };
		// 设置拥有该 StreamingDestination 的 ClientDestination
		void SetOwner(std::shared_ptr<i2p::client::ClientDestination> owner) { m_Owner = owner; };
		// 获取本地端口
		uint16_t GetLocalPort() const { return m_LocalPort; };

		// 处理数据消息有效负载
		void HandleDataMessagePayload(const uint8_t* buf, size_t len);
		// 创建数据消息
		std::shared_ptr<I2NPMessage> CreateDataMessage(const uint8_t* payload, size_t len, uint16_t toPort, bool checksum = true, bool gzip = false);

		// 从数据包池中创建新数据包
		Packet* NewPacket() { return m_PacketsPool.Acquire(); }
		// 释放数据包回到数据包池
		void DeletePacket(Packet* p) { return m_PacketsPool.Release(p); }

	private:
		// 处理下一个接收到的数据包
		void HandleNextPacket(Packet* packet);
		// 创建新的入站流，使用接收流 ID
		std::shared_ptr<Stream> CreateNewIncomingStream(uint32_t receiveStreamID);
		// 处理待处理的入站计时器
		void HandlePendingIncomingTimer(const boost::system::error_code& ecode);

	private:
		std::shared_ptr<i2p::client::ClientDestination> m_Owner; // 该 StreamingDestination 的拥有者
		uint16_t m_LocalPort; // 本地端口
		bool m_Gzip; // 是否使用 gzip 压缩数据消息
		std::mutex m_StreamsMutex; // 互斥锁，用于保护流的访问
		std::unordered_map<uint32_t, std::shared_ptr<Stream>> m_Streams; // 存储发送流 ID 到流的映射
		std::unordered_map<uint32_t, std::shared_ptr<Stream>> m_IncomingStreams; // 存储接收流 ID 到流的映射
		std::shared_ptr<Stream> m_LastStream; // 最近使用的流
		Acceptor m_Acceptor; // 接收器函数
		std::list<std::shared_ptr<Stream>> m_PendingIncomingStreams; // 待处理的入站流
		boost::asio::deadline_timer m_PendingIncomingTimer; // 入站流计时器
		std::unordered_map<uint32_t, std::list<Packet*>> m_SavedPackets; // 接收流 ID 到在 SYN 之前到达的数据包的映射

		// 数据包池，用于高效管理 Packet 对象的内存
		i2p::util::MemoryPool<Packet> m_PacketsPool;
		// I2NP 消息缓冲区池，用于高效管理 I2NP 消息对象的内存
		i2p::util::MemoryPool<I2NPMessageBuffer<I2NP_MAX_SHORT_MESSAGE_SIZE>> m_I2NPMsgsPool;

	public:
		i2p::data::GzipInflator m_Inflator; // gzip 解压缩器
		i2p::data::GzipDeflator m_Deflator; // gzip 压缩器

		// 用于 HTTP 仅供参考的流
		const decltype(m_Streams)& GetStreams() const { return m_Streams; };
	};


//-------------------------------------------------

	template<typename Buffer, typename ReceiveHandler>
	void Stream::AsyncReceive (const Buffer& buffer, ReceiveHandler handler, int timeout)
	{
		auto s = shared_from_this();
		m_Service.post ([s, buffer, handler, timeout](void)
		{
			if (!s->m_ReceiveQueue.empty () || s->m_Status == eStreamStatusReset)
				s->HandleReceiveTimer (boost::asio::error::make_error_code (boost::asio::error::operation_aborted), buffer, handler, 0);
			else
			{
				int t = (timeout > MAX_RECEIVE_TIMEOUT) ? MAX_RECEIVE_TIMEOUT : timeout;
				s->m_ReceiveTimer.expires_from_now (boost::posix_time::seconds(t));
				int left = timeout - t;
				s->m_ReceiveTimer.async_wait (
					[s, buffer, handler, left](const boost::system::error_code & ec)
					{
						s->HandleReceiveTimer(ec, buffer, handler, left);
					});
			}
		});
	}

	template<typename Buffer, typename ReceiveHandler>
	void Stream::HandleReceiveTimer (const boost::system::error_code& ecode, const Buffer& buffer, ReceiveHandler handler, int remainingTimeout)
	{
		size_t received = ConcatenatePackets (boost::asio::buffer_cast<uint8_t *>(buffer), boost::asio::buffer_size(buffer));
		if (received > 0)
			handler (boost::system::error_code (), received);
		else if (ecode == boost::asio::error::operation_aborted)
		{
			// timeout not expired
			if (m_Status == eStreamStatusReset)
				handler (boost::asio::error::make_error_code (boost::asio::error::connection_reset), 0);
			else
				handler (boost::asio::error::make_error_code (boost::asio::error::operation_aborted), 0);
		}
		else
		{
			// timeout expired
			if (remainingTimeout <= 0)
				handler (boost::asio::error::make_error_code (boost::asio::error::timed_out), received);
			else
			{
				// itermediate interrupt
				SendUpdatedLeaseSet (); // send our leaseset if applicable
				AsyncReceive (buffer, handler, remainingTimeout);
			}
		}
	}
}
}

#endif
