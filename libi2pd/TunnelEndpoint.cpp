/*
* Copyright (c) 2013-2023, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "I2PEndian.h"
#include <string.h>
#include "Crypto.h"
#include "Log.h"
#include "NetDb.hpp"
#include "I2NPProtocol.h"
#include "Transports.h"
#include "RouterContext.h"
#include "Timestamp.h"
#include "TunnelEndpoint.h"
#include "Logger.h"

namespace i2p
{
namespace tunnel
{
	TunnelEndpoint::~TunnelEndpoint ()
	{
	}

// +----+----+----+----+----+----+----+----+
// |    Tunnel ID      |       IV          |
// +----+----+----+----+                   +
// |                                       |
// +                   +----+----+----+----+
// |                   |     Checksum      |
// +----+----+----+----+----+----+----+----+
// |          nonzero padding...           |
// ~                                       ~
// |                                       |
// +                                  +----+
// |                                  |zero|
// +----+----+----+----+----+----+----+----+
// |                                       |
// |       Delivery Instructions  1        |
// ~                                       ~
// |                                       |
// +----+----+----+----+----+----+----+----+
// |                                       |
// +       I2NP Message Fragment 1         +
// |                                       |
// ~                                       ~
// |                                       |
// +----+----+----+----+----+----+----+----+
// |                                       |
// |       Delivery Instructions 2...      |
// ~                                       ~
// |                                       |
// +----+----+----+----+----+----+----+----+
// |                                       |
// +       I2NP Message Fragment 2...      +
// |                                       |
// ~                                       ~
// |                                       |
// +                   +-------------------+
// |                   |
// +----+----+----+----+

	void TunnelEndpoint::HandleDecryptedTunnelDataMsg (std::shared_ptr<I2NPMessage> msg)
	{
		// 更新接收的字节数
		m_NumReceivedBytes += TUNNEL_DATA_MSG_SIZE;

		// 获得解密后的数据，找到其中0️字节的地方
		// 4: Tunnel ID
		// 16: IV
		uint8_t * decrypted = msg->GetPayload () + 20; // 4 + 16
		// 4： 校验和
		// zero是找padding，padding的最后一字节是0
		uint8_t * zero = (uint8_t *)memchr (decrypted + 4, 0, TUNNEL_DATA_ENCRYPTED_SIZE - 4); // without 4-byte checksum

		// 校验和验证
		if (zero)
		{
			uint8_t * fragment = zero + 1;
			// verify checksum
			memcpy (msg->GetPayload () + TUNNEL_DATA_MSG_SIZE, msg->GetPayload () + 4, 16); // copy iv to the end
			uint8_t hash[32];
			SHA256(fragment, TUNNEL_DATA_MSG_SIZE -(fragment - msg->GetPayload ()) + 16, hash); // payload + iv
			if (memcmp (hash, decrypted, 4))
			{
				LogPrint (eLogError, "TunnelMessage: Checksum verification failed");
				return;
			}
			// 之后是Delivery Instructions，长得如下(第一个)
			// +----+----+----+----+----+----+----+----+
			// |flag|  Tunnel ID (opt)  |              |
			// +----+----+----+----+----+              +
			// |                                       |
			// +                                       +
			// |         To Hash (optional)            |
			// +                                       +
			// |                                       |
			// +                        +--------------+
			// |                        |dly | Message
			// +----+----+----+----+----+----+----+----+
			//  ID (opt) |extended opts (opt)|  size   |
			// +----+----+----+----+----+----+----+----+
			// process fragments
			// 后续的
			// +----+----+----+----+----+----+----+
			// |frag|     Message ID    |  size   |
			// +----+----+----+----+----+----+----+
			// 处理消息的每个部分
			while (fragment < decrypted + TUNNEL_DATA_ENCRYPTED_SIZE)
			{
				uint8_t flag = fragment[0];	// 标志字段
				// flag每一位代表：
				// 位 7：设为0表示初始片段或未分解的消息
				// 位 6-5：交付类型
				// 0x0 = 本地
				// 0x01 = 隧道
				// 0x02 = 路由器
				// 0x03 = 未使用，无效

				fragment++;
				// LogToFile("这个消息的flag为 " + std::to_string(flag));

				bool isFollowOnFragment = flag & 0x80, isLastFragment = true;		// 是否是后续片段，是否是最后一个片段
				uint32_t msgID = 0;
				int fragmentNum = 0;		// 片段号
				if (!isFollowOnFragment)
				{
					// first fragment
					if (m_CurrentMsgID)
						// 检查未完成的消息
						AddIncompleteCurrentMessage (); // we have got a new message while previous is not complete

					m_CurrentMessage.deliveryType = (TunnelDeliveryType)((flag >> 5) & 0x03);	// 从flag的6-5位得到交付类型
					// 解析交付类型
					switch (m_CurrentMessage.deliveryType)
					{
						case eDeliveryTypeLocal: // 0
							// LogToFile("消息是Local的");
						break;
						case eDeliveryTypeTunnel: // 1
							// LogToFile("消息是Tunnel的");
							m_CurrentMessage.tunnelID = bufbe32toh (fragment);
							fragment += 4; // tunnelID
							m_CurrentMessage.hash = i2p::data::IdentHash (fragment);
							fragment += 32; // hash
						break;
						case eDeliveryTypeRouter: // 2
							// LogToFile("消息是Router的");
							m_CurrentMessage.hash = i2p::data::IdentHash (fragment);
							fragment += 32; // to hash
						break;
						default: ;
					}

					// 已分解为1，未分解为0，未分解之后跟着消息
					bool isFragmented = flag & 0x08;
					// 处理分片消息
					if (isFragmented)
					{
						// Message ID
						msgID = bufbe32toh (fragment);
						fragment += 4;
						m_CurrentMsgID = msgID;
						isLastFragment = false;
					}
				}
				else
				{
					// follow on
					// 处理后续片段
					// LogToFile("处理后续片段");
					msgID = bufbe32toh (fragment); // MessageID
					fragment += 4;
					fragmentNum = (flag >> 1) & 0x3F; // 6 bits
					isLastFragment = flag & 0x01;
				}


				// 以下开始处理I2NP
				uint16_t size = bufbe16toh (fragment);	// 获得片段大小
				fragment += 2;

				// handle fragment
				if (isFollowOnFragment)
				{
					// existing message
					// 不是第一个片段
					// LogToFile("这里是之后的片段");
					if (m_CurrentMsgID && m_CurrentMsgID == msgID && m_CurrentMessage.nextFragmentNum == fragmentNum)
						HandleCurrenMessageFollowOnFragment (fragment, size, isLastFragment); // previous
					else
					{
						HandleFollowOnFragment (msgID, isLastFragment, fragmentNum, fragment, size); // another
						m_CurrentMsgID = 0; m_CurrentMessage.data = nullptr;
					}
				}
				else
				{
					// new message
					msg->offset = fragment - msg->buf;		// 设置msg的偏转
					msg->len = msg->offset + size;			// 设置msg的长度，包含当前片段的大小
					// LogToFile("这里是新消息，当前片段的长度为 " + std::to_string(msg->len));
					// check message size
					if (msg->len > msg->maxLen)
					{
						// 长度太长
						LogPrint (eLogError, "TunnelMessage: Fragment is too long ", (int)size);
						m_CurrentMsgID = 0; m_CurrentMessage.data = nullptr;
						return;
					}
					// create new or assign I2NP message
					if (fragment + size < decrypted + TUNNEL_DATA_ENCRYPTED_SIZE)
					{
						// this is not last message. we have to copy it
						// 不是最后的消息片段
						m_CurrentMessage.data = NewI2NPTunnelMessage (true);
						*(m_CurrentMessage.data) = *msg;
					}
					else
						// 是最后一个片段
						m_CurrentMessage.data = msg;

					if (isLastFragment)
					{
						// single message
						// LogToFile("最后一个fragment");
						HandleNextMessage (m_CurrentMessage);
						m_CurrentMsgID = 0; m_CurrentMessage.data = nullptr;
					}
					else if (msgID)
					{
						// first fragment of a new message
						// 第一个fragment
						// LogToFile("first fragment");
						m_CurrentMessage.nextFragmentNum = 1;
						m_CurrentMessage.receiveTime = i2p::util::GetMillisecondsSinceEpoch ();
						HandleOutOfSequenceFragments (msgID, m_CurrentMessage);
					}
					else
					{
						LogPrint (eLogError, "TunnelMessage: Message is fragmented, but msgID is not presented");
						m_CurrentMsgID = 0; m_CurrentMessage.data = nullptr;
					}
				}

				fragment += size;
			}
		}
		else
			LogPrint (eLogError, "TunnelMessage: Zero not found");
	}

	void TunnelEndpoint::HandleFollowOnFragment (uint32_t msgID, bool isLastFragment,
		uint8_t fragmentNum, const uint8_t * fragment, size_t size)
	{
		auto it = m_IncompleteMessages.find (msgID);
		if (it != m_IncompleteMessages.end())
		{
			auto& msg = it->second;
			if (fragmentNum == msg.nextFragmentNum)
			{
				if (ConcatFollowOnFragment (msg, fragment, size))
				{
					if (isLastFragment)
					{
						// message complete
						HandleNextMessage (msg);
						m_IncompleteMessages.erase (it);
					}
					else
					{
						msg.nextFragmentNum++;
						HandleOutOfSequenceFragments (msgID, msg);
					}
				}
				else
				{
					LogPrint (eLogError, "TunnelMessage: Fragment ", fragmentNum, " of message ", msgID, "exceeds max I2NP message size, message dropped");
					m_IncompleteMessages.erase (it);
				}
			}
			else
			{
				LogPrint (eLogWarning, "TunnelMessage: Unexpected fragment ", (int)fragmentNum, " instead ", (int)msg.nextFragmentNum, " of message ", msgID, ", saved");
				AddOutOfSequenceFragment (msgID, fragmentNum, isLastFragment, fragment, size);
			}
		}
		else
		{
			LogPrint (eLogDebug, "TunnelMessage: First fragment of message ", msgID, " not found, saved");
			AddOutOfSequenceFragment (msgID, fragmentNum, isLastFragment, fragment, size);
		}
	}

	bool TunnelEndpoint::ConcatFollowOnFragment (TunnelMessageBlockEx& msg, const uint8_t * fragment, size_t size) const
	{
		if (msg.data->len + size < I2NP_MAX_MESSAGE_SIZE) // check if message is not too long
		{
			if (msg.data->len + size > msg.data->maxLen)
			{
			//	LogPrint (eLogWarning, "TunnelMessage: I2NP message size ", msg.data->maxLen, " is not enough");
				auto newMsg = NewI2NPMessage (msg.data->len + size);
				*newMsg = *(msg.data);
				msg.data = newMsg;
			}
			if (msg.data->Concat (fragment, size) < size) // concatenate fragment
			{
				LogPrint (eLogError, "TunnelMessage: I2NP buffer overflow ", msg.data->maxLen);
				return false;
			}
		}
		else
			return false;
		return true;
	}

	void TunnelEndpoint::HandleCurrenMessageFollowOnFragment (const uint8_t * fragment, size_t size, bool isLastFragment)
	{
		if (ConcatFollowOnFragment (m_CurrentMessage, fragment, size))
		{
			if (isLastFragment)
			{
				// message complete
				HandleNextMessage (m_CurrentMessage);
				m_CurrentMsgID = 0; m_CurrentMessage.data = nullptr;
			}
			else
			{
				m_CurrentMessage.nextFragmentNum++;
				HandleOutOfSequenceFragments (m_CurrentMsgID, m_CurrentMessage);
			}
		}
		else
		{
			LogPrint (eLogError, "TunnelMessage: Fragment ", m_CurrentMessage.nextFragmentNum, " of message ", m_CurrentMsgID, " exceeds max I2NP message size, message dropped");
			m_CurrentMsgID = 0; m_CurrentMessage.data = nullptr;
		}
	}

	void TunnelEndpoint::AddIncompleteCurrentMessage ()
	{
		if (m_CurrentMsgID)
		{
			auto ret = m_IncompleteMessages.emplace (m_CurrentMsgID, m_CurrentMessage);
			if (!ret.second)
				LogPrint (eLogError, "TunnelMessage: Incomplete message ", m_CurrentMsgID, " already exists");
			m_CurrentMessage.data = nullptr;
			m_CurrentMsgID = 0;
		}
	}

	void TunnelEndpoint::AddOutOfSequenceFragment (uint32_t msgID, uint8_t fragmentNum,
		bool isLastFragment, const uint8_t * fragment, size_t size)
	{
		std::unique_ptr<Fragment> f(new Fragment (isLastFragment, i2p::util::GetMillisecondsSinceEpoch (), size));
		memcpy (f->data.data (), fragment, size);
		if (!m_OutOfSequenceFragments.emplace ((uint64_t)msgID << 32 | fragmentNum, std::move (f)).second)
			LogPrint (eLogInfo, "TunnelMessage: Duplicate out-of-sequence fragment ", fragmentNum, " of message ", msgID);
	}

	void TunnelEndpoint::HandleOutOfSequenceFragments (uint32_t msgID, TunnelMessageBlockEx& msg)
	{
		while (ConcatNextOutOfSequenceFragment (msgID, msg))
		{
			if (!msg.nextFragmentNum) // message complete
			{
				HandleNextMessage (msg);
				if (&msg == &m_CurrentMessage)
				{
					m_CurrentMsgID = 0;
					m_CurrentMessage.data = nullptr;
				}
				else
					m_IncompleteMessages.erase (msgID);
				LogPrint (eLogDebug, "TunnelMessage: All fragments of message ", msgID, " found");
				break;
			}
		}
	}

	bool TunnelEndpoint::ConcatNextOutOfSequenceFragment (uint32_t msgID, TunnelMessageBlockEx& msg)
	{
		auto it = m_OutOfSequenceFragments.find ((uint64_t)msgID << 32 | msg.nextFragmentNum);
		if (it != m_OutOfSequenceFragments.end ())
		{
			LogPrint (eLogDebug, "TunnelMessage: Out-of-sequence fragment ", (int)msg.nextFragmentNum, " of message ", msgID, " found");
			size_t size = it->second->data.size ();
			if (msg.data->len + size > msg.data->maxLen)
			{
				LogPrint (eLogWarning, "TunnelMessage: Tunnel endpoint I2NP message size ", msg.data->maxLen, " is not enough");
				auto newMsg = NewI2NPMessage (msg.data->len + size);
				*newMsg = *(msg.data);
				msg.data = newMsg;
			}
			if (msg.data->Concat (it->second->data.data (), size) < size) // concatenate out-of-sync fragment	
				LogPrint (eLogError, "TunnelMessage: Tunnel endpoint I2NP buffer overflow ", msg.data->maxLen);
			if (it->second->isLastFragment)
				// message complete
				msg.nextFragmentNum = 0;
			else
				msg.nextFragmentNum++;
			m_OutOfSequenceFragments.erase (it);
			return true;
		}
		return false;
	}

	// 处理隧道消息
	void TunnelEndpoint::HandleNextMessage (const TunnelMessageBlock& msg)
	{
		if (!m_IsInbound && msg.data->IsExpired ())
		// 检查是否已过期，并且当前通道是不是不是入站
		{
			LogPrint (eLogInfo, "TunnelMessage: Message expired");
			return;
		}
		uint8_t typeID = msg.data->GetTypeID ();
		LogPrint (eLogDebug, "TunnelMessage: Handle fragment of ", msg.data->GetLength (), " bytes, msg type ", (int)typeID);
		
		switch (msg.deliveryType)
		{
			// 传递消息的类型
			case eDeliveryTypeLocal:
				// LogToFile("传递消息为eDeliveryTypeLocal类型");
				i2p::HandleI2NPMessage (msg.data);
			break;
			case eDeliveryTypeTunnel:
				// LogToFile("传递消息为eDeliveryTypeTunnel类型");
				if (!m_IsInbound) // outbound transit tunnel
					i2p::transport::transports.SendMessage (msg.hash, i2p::CreateTunnelGatewayMsg (msg.tunnelID, msg.data));
				else
					LogPrint (eLogError, "TunnelMessage: Delivery type 'tunnel' arrived from an inbound tunnel, dropped");
			break;
			case eDeliveryTypeRouter:
				// LogToFile("传递消息为eDeliveryTypeRouter类型");
				if (!m_IsInbound) // outbound transit tunnel
					i2p::transport::transports.SendMessage (msg.hash, msg.data);
				else // we shouldn't send this message. possible leakage
					LogPrint (eLogError, "TunnelMessage: Delivery type 'router' arrived from an inbound tunnel, dropped");
			break;
			default:
				LogPrint (eLogError, "TunnelMessage: Unknown delivery type ", (int)msg.deliveryType);
		};
	}

	void TunnelEndpoint::Cleanup ()
	{
		auto ts = i2p::util::GetMillisecondsSinceEpoch ();
		// out-of-sequence fragments
		for (auto it = m_OutOfSequenceFragments.begin (); it != m_OutOfSequenceFragments.end ();)
		{
			if (ts > it->second->receiveTime + i2p::I2NP_MESSAGE_EXPIRATION_TIMEOUT)
				it = m_OutOfSequenceFragments.erase (it);
			else
				++it;
		}
		// incomplete messages
		for (auto it = m_IncompleteMessages.begin (); it != m_IncompleteMessages.end ();)
		{
			if (ts > it->second.receiveTime + i2p::I2NP_MESSAGE_EXPIRATION_TIMEOUT)
				it = m_IncompleteMessages.erase (it);
			else
				++it;
		}
	}
}
}
