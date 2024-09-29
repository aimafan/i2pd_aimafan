/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include <atomic>
#include "Base.h"
#include "Log.h"
#include "Crypto.h"
#include "I2PEndian.h"
#include "Timestamp.h"
#include "RouterContext.h"
#include "NetDb.hpp"
#include "Tunnel.h"
#include "Transports.h"
#include "Garlic.h"
#include "ECIESX25519AEADRatchetSession.h"
#include "I2NPProtocol.h"
#include "version.h"
#include "Logger.h"
#include "Logger_transport.h"

using namespace i2p::transport;

namespace i2p
{
	std::shared_ptr<I2NPMessage> NewI2NPMessage ()
	{
		return std::make_shared<I2NPMessageBuffer<I2NP_MAX_MESSAGE_SIZE> >();
	}

	std::shared_ptr<I2NPMessage> NewI2NPShortMessage ()
	{
		return std::make_shared<I2NPMessageBuffer<I2NP_MAX_SHORT_MESSAGE_SIZE> >();
	}

	std::shared_ptr<I2NPMessage> NewI2NPMediumMessage ()
	{
		return std::make_shared<I2NPMessageBuffer<I2NP_MAX_MEDIUM_MESSAGE_SIZE> >();
	}

	std::shared_ptr<I2NPMessage> NewI2NPTunnelMessage (bool endpoint)
	{
		return i2p::tunnel::tunnels.NewI2NPTunnelMessage (endpoint);
	}

	std::shared_ptr<I2NPMessage> NewI2NPMessage (size_t len)
	{
		len += I2NP_HEADER_SIZE + 2;
		if (len <= I2NP_MAX_SHORT_MESSAGE_SIZE) return NewI2NPShortMessage ();
		if (len <= I2NP_MAX_MEDIUM_MESSAGE_SIZE) return NewI2NPMediumMessage ();
		return NewI2NPMessage ();
	}

	void I2NPMessage::FillI2NPMessageHeader (I2NPMessageType msgType, uint32_t replyMsgID, bool checksum)
	{
		SetTypeID (msgType);
		if (!replyMsgID) RAND_bytes ((uint8_t *)&replyMsgID, 4);
		SetMsgID (replyMsgID);
		SetExpiration (i2p::util::GetMillisecondsSinceEpoch () + I2NP_MESSAGE_EXPIRATION_TIMEOUT);
		UpdateSize ();
		if (checksum) UpdateChks ();
	}

	void I2NPMessage::RenewI2NPMessageHeader ()
	{
		uint32_t msgID;
		RAND_bytes ((uint8_t *)&msgID, 4);
		SetMsgID (msgID);
		SetExpiration (i2p::util::GetMillisecondsSinceEpoch () + I2NP_MESSAGE_EXPIRATION_TIMEOUT);
	}

	bool I2NPMessage::IsExpired (uint64_t ts) const
	{
		auto exp = GetExpiration ();
		return (ts > exp + I2NP_MESSAGE_CLOCK_SKEW) || (ts < exp - 3*I2NP_MESSAGE_CLOCK_SKEW); // check if expired or too far in future
	}	
	
	bool I2NPMessage::IsExpired () const
	{
		return IsExpired (i2p::util::GetMillisecondsSinceEpoch ());
	}

	std::shared_ptr<I2NPMessage> CreateI2NPMessage (I2NPMessageType msgType, const uint8_t * buf, size_t len, uint32_t replyMsgID)
	{
		auto msg = NewI2NPMessage (len);
		if (msg->Concat (buf, len) < len)
			LogPrint (eLogError, "I2NP: Message length ", len, " exceeds max length ", msg->maxLen);
		msg->FillI2NPMessageHeader (msgType, replyMsgID);
		return msg;
	}

	std::shared_ptr<I2NPMessage> CreateI2NPMessage (const uint8_t * buf, size_t len, std::shared_ptr<i2p::tunnel::InboundTunnel> from)
	{
		auto msg = NewI2NPMessage ();
		if (msg->offset + len < msg->maxLen)
		{
			memcpy (msg->GetBuffer (), buf, len);
			msg->len = msg->offset + len;
			msg->from = from;
		}
		else
			LogPrint (eLogError, "I2NP: Message length ", len, " exceeds max length");
		return msg;
	}

	std::shared_ptr<I2NPMessage> CopyI2NPMessage (std::shared_ptr<I2NPMessage> msg)
	{
		if (!msg) return nullptr;
		auto newMsg = NewI2NPMessage (msg->len);
		newMsg->offset = msg->offset;
		*newMsg = *msg;
		return newMsg;
	}

	std::shared_ptr<I2NPMessage> CreateTunnelTestMsg (uint32_t msgID)
	{
		auto m = NewI2NPShortMessage ();
		uint8_t * buf = m->GetPayload ();
		htobe32buf (buf + TUNNEL_TEST_MSGID_OFFSET, msgID);
		htobe64buf (buf + TUNNEL_TEST_TIMESTAMP_OFFSET, i2p::util::GetMonotonicMicroseconds ());
		m->len += TUNNEL_TEST_SIZE;
		m->FillI2NPMessageHeader (eI2NPTunnelTest);
		return m;
	}

	std::shared_ptr<I2NPMessage> CreateDeliveryStatusMsg (uint32_t msgID)
	{
		auto m = NewI2NPShortMessage ();
		uint8_t * buf = m->GetPayload ();
		if (msgID)
		{
			htobe32buf (buf + DELIVERY_STATUS_MSGID_OFFSET, msgID);
			htobe64buf (buf + DELIVERY_STATUS_TIMESTAMP_OFFSET, i2p::util::GetMillisecondsSinceEpoch ());
		}
		else // for SSU establishment
		{
			RAND_bytes ((uint8_t *)&msgID, 4);
			htobe32buf (buf + DELIVERY_STATUS_MSGID_OFFSET, msgID);
			htobe64buf (buf + DELIVERY_STATUS_TIMESTAMP_OFFSET, i2p::context.GetNetID ());
		}
		m->len += DELIVERY_STATUS_SIZE;
		m->FillI2NPMessageHeader (eI2NPDeliveryStatus);
		return m;
	}

	std::shared_ptr<I2NPMessage> CreateRouterInfoDatabaseLookupMsg (const uint8_t * key, const uint8_t * from,
		uint32_t replyTunnelID, bool exploratory, std::set<i2p::data::IdentHash> * excludedPeers)
	{
		int cnt = excludedPeers ? excludedPeers->size () : 0;
		auto m = cnt > 7 ? NewI2NPMessage () : NewI2NPShortMessage ();
		uint8_t * buf = m->GetPayload ();
		memcpy (buf, key, 32); // key
		buf += 32;
		memcpy (buf, from, 32); // from
		buf += 32;
		uint8_t flag = exploratory ? DATABASE_LOOKUP_TYPE_EXPLORATORY_LOOKUP : DATABASE_LOOKUP_TYPE_ROUTERINFO_LOOKUP;
		if (replyTunnelID)
		{
			*buf = flag | DATABASE_LOOKUP_DELIVERY_FLAG; // set delivery flag
			htobe32buf (buf+1, replyTunnelID);
			buf += 5;
		}
		else
		{
			*buf = flag; // flag
			buf++;
		}

		if (excludedPeers)
		{
			htobe16buf (buf, cnt);
			buf += 2;
			for (auto& it: *excludedPeers)
			{
				memcpy (buf, it, 32);
				buf += 32;
			}
		}
		else
		{
			// nothing to exclude
			htobuf16 (buf, 0);
			buf += 2;
		}

		m->len += (buf - m->GetPayload ());
		m->FillI2NPMessageHeader (eI2NPDatabaseLookup);
		return m;
	}

	std::shared_ptr<I2NPMessage> CreateLeaseSetDatabaseLookupMsg (const i2p::data::IdentHash& dest,
		const std::set<i2p::data::IdentHash>& excludedFloodfills,
		std::shared_ptr<const i2p::tunnel::InboundTunnel> replyTunnel, const uint8_t * replyKey,
			const uint8_t * replyTag, bool replyECIES)
	{
		int cnt = excludedFloodfills.size ();
		auto m = cnt > 7 ? NewI2NPMessage () : NewI2NPShortMessage ();
		uint8_t * buf = m->GetPayload ();
		memcpy (buf, dest, 32); // key
		buf += 32;
		memcpy (buf, replyTunnel->GetNextIdentHash (), 32); // reply tunnel GW
		buf += 32;
		*buf = DATABASE_LOOKUP_DELIVERY_FLAG | DATABASE_LOOKUP_TYPE_LEASESET_LOOKUP; // flags
		*buf |= (replyECIES ? DATABASE_LOOKUP_ECIES_FLAG : DATABASE_LOOKUP_ENCRYPTION_FLAG);
		buf ++;
		htobe32buf (buf, replyTunnel->GetNextTunnelID ()); // reply tunnel ID
		buf += 4;

		// excluded
		if (cnt > 512)
		{
			LogPrint (eLogWarning, "I2NP: Too many peers to exclude ", cnt, " for DatabaseLookup");
			cnt = 0;
		}
		htobe16buf (buf, cnt);
		buf += 2;
		if (cnt > 0)
		{
			for (auto& it: excludedFloodfills)
			{
				memcpy (buf, it, 32);
				buf += 32;
			}
		}
		// encryption
		memcpy (buf, replyKey, 32);
		buf[32] = 1; // 1 tag
		if (replyECIES)
		{
			memcpy (buf + 33, replyTag, 8); // 8 bytes tag
			buf += 41;
		}
		else
		{
			memcpy (buf + 33, replyTag, 32); // 32 bytes tag
			buf += 65;
		}

		m->len += (buf - m->GetPayload ());
		m->FillI2NPMessageHeader (eI2NPDatabaseLookup);
		return m;
	}

	std::shared_ptr<I2NPMessage> CreateDatabaseSearchReply (const i2p::data::IdentHash& ident,
		std::vector<i2p::data::IdentHash> routers)
	{
		auto m = NewI2NPShortMessage ();
		uint8_t * buf = m->GetPayload ();
		size_t len = 0;
		memcpy (buf, ident, 32);
		len += 32;
		buf[len] = routers.size ();
		len++;
		for (const auto& it: routers)
		{
			memcpy (buf + len, it, 32);
			len += 32;
		}
		memcpy (buf + len, i2p::context.GetRouterInfo ().GetIdentHash (), 32);
		len += 32;
		m->len += len;
		m->FillI2NPMessageHeader (eI2NPDatabaseSearchReply);
		return m;
	}

	std::shared_ptr<I2NPMessage> CreateDatabaseStoreMsg (std::shared_ptr<const i2p::data::RouterInfo> router,
		uint32_t replyToken, std::shared_ptr<const i2p::tunnel::InboundTunnel> replyTunnel)
	{
		if (!router) // we send own RouterInfo
			router = context.GetSharedRouterInfo ();

		if (!router->GetBuffer ())
		{
			LogPrint (eLogError, "I2NP: Invalid RouterInfo buffer for DatabaseStore");
			return nullptr;
		}

		auto m = NewI2NPShortMessage ();
		uint8_t * payload = m->GetPayload ();

		memcpy (payload + DATABASE_STORE_KEY_OFFSET, router->GetIdentHash (), 32);
		payload[DATABASE_STORE_TYPE_OFFSET] = 0; // RouterInfo
		htobe32buf (payload + DATABASE_STORE_REPLY_TOKEN_OFFSET, replyToken);
		uint8_t * buf = payload + DATABASE_STORE_HEADER_SIZE;
		if (replyToken)
		{
			if (replyTunnel)
			{
				htobe32buf (buf, replyTunnel->GetNextTunnelID ());
				buf += 4; // reply tunnelID
				memcpy (buf, replyTunnel->GetNextIdentHash (), 32);
				buf += 32; // reply tunnel gateway
			}
			else
			{
				memset (buf, 0, 4); // zero tunnelID means direct reply
				buf += 4;
				memcpy (buf, context.GetIdentHash (), 32);
				buf += 32;
			}
		}

		uint8_t * sizePtr = buf;
		buf += 2;
		m->len += (buf - payload); // payload size
		size_t size = 0;
		if (router->GetBufferLen () + (buf - payload) <= 940) // fits one tunnel message
			size = i2p::data::GzipNoCompression (router->GetBuffer (), router->GetBufferLen (), buf, m->maxLen -m->len);
		else
		{
			i2p::data::GzipDeflator deflator;
			size = deflator.Deflate (router->GetBuffer (), router->GetBufferLen (), buf, m->maxLen -m->len);
		}
		if (size)
		{
			htobe16buf (sizePtr, size); // size
			m->len += size;
		}
		else
			m = nullptr;
		if (m)
			m->FillI2NPMessageHeader (eI2NPDatabaseStore);
		return m;
	}

	std::shared_ptr<I2NPMessage> CreateDatabaseStoreMsg (const i2p::data::IdentHash& storeHash, std::shared_ptr<const i2p::data::LeaseSet> leaseSet)
	{
		if (!leaseSet) return nullptr;
		auto m = NewI2NPShortMessage ();
		uint8_t * payload = m->GetPayload ();
		memcpy (payload + DATABASE_STORE_KEY_OFFSET, storeHash, 32);
		payload[DATABASE_STORE_TYPE_OFFSET] = leaseSet->GetStoreType (); // 1 for LeaseSet
		htobe32buf (payload + DATABASE_STORE_REPLY_TOKEN_OFFSET, 0);
		size_t size = DATABASE_STORE_HEADER_SIZE;
		memcpy (payload + size, leaseSet->GetBuffer (), leaseSet->GetBufferLen ());
		size += leaseSet->GetBufferLen ();
		m->len += size;
		m->FillI2NPMessageHeader (eI2NPDatabaseStore);
		return m;
	}

	std::shared_ptr<I2NPMessage> CreateDatabaseStoreMsg (std::shared_ptr<const i2p::data::LocalLeaseSet> leaseSet, uint32_t replyToken, std::shared_ptr<const i2p::tunnel::InboundTunnel> replyTunnel)
	{
		if (!leaseSet) return nullptr;
		auto m = NewI2NPShortMessage ();
		uint8_t * payload = m->GetPayload ();
		memcpy (payload + DATABASE_STORE_KEY_OFFSET, leaseSet->GetStoreHash (), 32);
		payload[DATABASE_STORE_TYPE_OFFSET] = leaseSet->GetStoreType (); // LeaseSet or LeaseSet2
		htobe32buf (payload + DATABASE_STORE_REPLY_TOKEN_OFFSET, replyToken);
		size_t size = DATABASE_STORE_HEADER_SIZE;
		if (replyToken && replyTunnel)
		{
			if (replyTunnel)
			{
				htobe32buf (payload + size, replyTunnel->GetNextTunnelID ());
				size += 4; // reply tunnelID
				memcpy (payload + size, replyTunnel->GetNextIdentHash (), 32);
				size += 32; // reply tunnel gateway
			}
			else
				htobe32buf (payload + DATABASE_STORE_REPLY_TOKEN_OFFSET, 0);
		}
		memcpy (payload + size, leaseSet->GetBuffer (), leaseSet->GetBufferLen ());
		size += leaseSet->GetBufferLen ();
		m->len += size;
		m->FillI2NPMessageHeader (eI2NPDatabaseStore);
		return m;
	}

	bool IsRouterInfoMsg (std::shared_ptr<I2NPMessage> msg)
	{
		if (!msg || msg->GetTypeID () != eI2NPDatabaseStore) return false;
		return !msg->GetPayload ()[DATABASE_STORE_TYPE_OFFSET]; // 0- RouterInfo
	}

	static bool HandleBuildRequestRecords (std::string host, std::string port, int num, uint8_t * records, uint8_t * clearText)
	{
		// 处理隧道请求记录
		for (int i = 0; i < num; i++)
		{
			// 遍历所有请求记录
			uint8_t * record = records + i*TUNNEL_BUILD_RECORD_SIZE;
			// 请求是发给本路由器的
			if (!memcmp (record + BUILD_REQUEST_RECORD_TO_PEER_OFFSET, (const uint8_t *)i2p::context.GetRouterInfo ().GetIdentHash (), 16))
			{
				LogPrint (eLogDebug, "I2NP: Build request record ", i, " is ours");
				// 解密请求记录
				if (!i2p::context.DecryptTunnelBuildRecord (record + BUILD_REQUEST_RECORD_ENCRYPTED_OFFSET, clearText)) 
				{
					LogPrint (eLogWarning, "I2NP: Failed to decrypt tunnel build record");
					return false;
				}	
				// 验证记录合法性
				if (!memcmp ((const uint8_t *)i2p::context.GetIdentHash (), clearText + ECIES_BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET, 32) && // if next ident is now ours
				    !(clearText[ECIES_BUILD_REQUEST_RECORD_FLAG_OFFSET] & TUNNEL_BUILD_RECORD_ENDPOINT_FLAG)) // and not endpoint
				{
					LogPrint (eLogWarning, "I2NP: Next ident is ours in tunnel build record");
					return false;
				}	

				// 处理隧道构建请求				
				uint8_t retCode = 0;
				// replace record to reply
				if (i2p::context.AcceptsTunnels () && i2p::context.GetCongestionLevel (false) < CONGESTION_LEVEL_FULL)
				{
					// 接受隧道并未达到拥塞水平，尝试建立中继隧道
					auto transitTunnel = i2p::tunnel::CreateTransitTunnel (
							host, port,
							bufbe32toh (clearText + ECIES_BUILD_REQUEST_RECORD_RECEIVE_TUNNEL_OFFSET),
							clearText + ECIES_BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET,
							bufbe32toh (clearText + ECIES_BUILD_REQUEST_RECORD_NEXT_TUNNEL_OFFSET),
							clearText + ECIES_BUILD_REQUEST_RECORD_LAYER_KEY_OFFSET,
							clearText + ECIES_BUILD_REQUEST_RECORD_IV_KEY_OFFSET,
							clearText[ECIES_BUILD_REQUEST_RECORD_FLAG_OFFSET] & TUNNEL_BUILD_RECORD_GATEWAY_FLAG,
							clearText[ECIES_BUILD_REQUEST_RECORD_FLAG_OFFSET] & TUNNEL_BUILD_RECORD_ENDPOINT_FLAG);
					// 创建失败
					if (!i2p::tunnel::tunnels.AddTransitTunnel (transitTunnel))
						retCode = 30;
				}
				else
					retCode = 30; // always reject with bandwidth reason (30)

				memset (record + ECIES_BUILD_RESPONSE_RECORD_OPTIONS_OFFSET, 0, 2); // no options
				record[ECIES_BUILD_RESPONSE_RECORD_RET_OFFSET] = retCode;
				// encrypt reply
				i2p::crypto::CBCEncryption encryption;
				for (int j = 0; j < num; j++)
				{
					uint8_t * reply = records + j*TUNNEL_BUILD_RECORD_SIZE;
					if (j == i)
					{
						uint8_t nonce[12];
						memset (nonce, 0, 12);
						auto& noiseState = i2p::context.GetCurrentNoiseState ();
						if (!i2p::crypto::AEADChaCha20Poly1305 (reply, TUNNEL_BUILD_RECORD_SIZE - 16,
							noiseState.m_H, 32, noiseState.m_CK, nonce, reply, TUNNEL_BUILD_RECORD_SIZE, true)) // encrypt
						{
							LogPrint (eLogWarning, "I2NP: Reply AEAD encryption failed");
							return false;
						}
					}
					else
					{
						encryption.SetKey (clearText + ECIES_BUILD_REQUEST_RECORD_REPLY_KEY_OFFSET);
						encryption.SetIV (clearText + ECIES_BUILD_REQUEST_RECORD_REPLY_IV_OFFSET);
						encryption.Encrypt(reply, TUNNEL_BUILD_RECORD_SIZE, reply);
					}
				}
				return true;
			}
		}
		return false;
	}

	static void HandleVariableTunnelBuildMsg (std::string host, std::string port, uint32_t replyMsgID, uint8_t * buf, size_t len)
	{
		int num = buf[0];
		LogPrint (eLogDebug, "I2NP: VariableTunnelBuild ", num, " records");
		if (num > i2p::tunnel::MAX_NUM_RECORDS)
		{
			LogPrint (eLogError, "I2NP: Too many records in VaribleTunnelBuild message ", num);
			return;
		}
		if (len < num*TUNNEL_BUILD_RECORD_SIZE + 1)
		{
			LogPrint (eLogError, "I2NP: VaribleTunnelBuild message of ", num, " records is too short ", len);
			return;
		}

		auto tunnel = i2p::tunnel::tunnels.GetPendingInboundTunnel (replyMsgID);		// 从待建隧道中，通过MsgID把这个隧道揪出来

		if (tunnel)
		{
			// LogToFile("在VariableTunnelBuild，隧道id：" + std::to_string(tunnel->GetTunnelID()));
			// LogToFile("在VariableTunnelBuild，下一跳的隧道id：" + std::to_string(tunnel->GetNextTunnelID()));
			// LogToFile("在VariableTunnelBuild，隧道的跳数：" + std::to_string(tunnel->GetNumHops()));
			// LogToFile("在VariableTunnelBuild，下一跳的hash：" + tunnel->GetNextIdentHash().ToBase64());
			// endpoint of inbound tunnel
			LogPrint (eLogDebug, "I2NP: VariableTunnelBuild reply for tunnel ", tunnel->GetTunnelID ());
			if (tunnel->HandleTunnelBuildResponse (buf, len, "in"))		// 构建成隧道
			{
				LogPrint (eLogInfo, "I2NP: Inbound tunnel ", tunnel->GetTunnelID (), " has been created");
				tunnel->SetState (i2p::tunnel::eTunnelStateEstablished);
				i2p::tunnel::tunnels.AddInboundTunnel (tunnel);		// 在所有的隧道里面插入一个InboundTunnel
			}
			else
			{
				LogPrint (eLogInfo, "I2NP: Inbound tunnel ", tunnel->GetTunnelID (), " has been declined");
				tunnel->SetState (i2p::tunnel::eTunnelStateBuildFailed);
			}
		}
		else
		{
			// 如果这个msg之前没有在我的池里面出现过，说明就是别人给我发的，我要成为中继节点
			uint8_t clearText[ECIES_BUILD_REQUEST_RECORD_CLEAR_TEXT_SIZE];
			if (HandleBuildRequestRecords (host, port, num, buf + 1, clearText))
			{
				if (clearText[ECIES_BUILD_REQUEST_RECORD_FLAG_OFFSET] & TUNNEL_BUILD_RECORD_ENDPOINT_FLAG) // we are endpoint of outboud tunnel
				{
					// so we send it to reply tunnel
					transports.SendMessage (clearText + ECIES_BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET,
						CreateTunnelGatewayMsg (bufbe32toh (clearText + ECIES_BUILD_REQUEST_RECORD_NEXT_TUNNEL_OFFSET),
							eI2NPVariableTunnelBuildReply, buf, len,
							bufbe32toh (clearText + ECIES_BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET)));
				}
				else
					transports.SendMessage (clearText + ECIES_BUILD_REQUEST_RECORD_NEXT_IDENT_OFFSET,
						CreateI2NPMessage (eI2NPVariableTunnelBuild, buf, len,
							bufbe32toh (clearText + ECIES_BUILD_REQUEST_RECORD_SEND_MSG_ID_OFFSET)));
			}
		}
	}

	static void HandleTunnelBuildMsg (uint8_t * buf, size_t len)
	{
		LogPrint (eLogWarning, "I2NP: TunnelBuild is too old for ECIES router");
	}

	static void HandleTunnelBuildReplyMsg (uint32_t replyMsgID, uint8_t * buf, size_t len, bool isShort)
	{
		int num = buf[0];
		LogPrint (eLogDebug, "I2NP: TunnelBuildReplyMsg of ", num, " records replyMsgID=", replyMsgID);
		if (num > i2p::tunnel::MAX_NUM_RECORDS)
		{
			LogPrint (eLogError, "I2NP: Too many records in TunnelBuildReply message ", num);
			return;
		}
		size_t recordSize = isShort ? SHORT_TUNNEL_BUILD_RECORD_SIZE : TUNNEL_BUILD_RECORD_SIZE;
		if (len < num*recordSize + 1)
		{
			LogPrint (eLogError, "I2NP: TunnelBuildReply message of ", num, " records is too short ", len);
			return;
		}

		auto tunnel = i2p::tunnel::tunnels.GetPendingOutboundTunnel (replyMsgID);
		if (tunnel)
		{
			// LogToFile("在TunnelBuildReply，隧道id：" + std::to_string(tunnel->GetTunnelID()));
			// LogToFile("在TunnelBuildReply，下一跳的隧道id：" + std::to_string(tunnel->GetNextTunnelID()));
			// LogToFile("在TunnelBuildReply，隧道的跳数：" + std::to_string(tunnel->GetNumHops()));
			// LogToFile("在TunnelBuildReply，下一跳的hash：" + tunnel->GetNextIdentHash().ToBase64());
			// reply for outbound tunnel
			if (tunnel->HandleTunnelBuildResponse (buf, len, "out"))
			{
				LogPrint (eLogInfo, "I2NP: Outbound tunnel ", tunnel->GetTunnelID (), " has been created");
				tunnel->SetState (i2p::tunnel::eTunnelStateEstablished);
				i2p::tunnel::tunnels.AddOutboundTunnel (tunnel);
			}
			else
			{
				LogPrint (eLogInfo, "I2NP: Outbound tunnel ", tunnel->GetTunnelID (), " has been declined");
				tunnel->SetState (i2p::tunnel::eTunnelStateBuildFailed);
			}
		}
		else
			LogPrint (eLogWarning, "I2NP: Pending tunnel for message ", replyMsgID, " not found");
	}

	static void HandleShortTunnelBuildMsg (std::string host, std::string port, uint32_t replyMsgID, uint8_t * buf, size_t len)
	{
		int num = buf[0];		// 表明这个shortTunnelbuild有num个tunnel

		LogPrint (eLogDebug, "I2NP: ShortTunnelBuild ", num, " records");
		// 检查记录数量是否超过允许的最大数量，超出则输出错误并返回
		if (num > i2p::tunnel::MAX_NUM_RECORDS)
		{
			LogPrint (eLogError, "I2NP: Too many records in ShortTunnelBuild message ", num);
			return;
		}

		// 检查消息长度是否足够容纳所有记录，如果消息过短，输出错误并返回
		if (len < num*SHORT_TUNNEL_BUILD_RECORD_SIZE + 1)
		{
			LogPrint (eLogError, "I2NP: ShortTunnelBuild message of ", num, " records is too short ", len);
			return;
		}

		// 尝试根据 replyMsgID 查找一个等待的入站隧道，如果找到，继续处理
		// 找到说明这个隧道是我自己创立的
		auto tunnel = i2p::tunnel::tunnels.GetPendingInboundTunnel (replyMsgID);
		if (tunnel)
		{
			// 我自己创立的隧道，我作为endpoint或者gateway
			// endpoint of inbound tunnel
			LogPrint (eLogDebug, "I2NP: ShortTunnelBuild reply for tunnel ", tunnel->GetTunnelID ());
			if (tunnel->HandleTunnelBuildResponse (buf, len, "in"))
			{
				LogPrint (eLogInfo, "I2NP: Inbound tunnel ", tunnel->GetTunnelID (), " has been created");
				tunnel->SetState (i2p::tunnel::eTunnelStateEstablished);
				i2p::tunnel::tunnels.AddInboundTunnel (tunnel);
			}
			else
			{
				LogPrint (eLogInfo, "I2NP: Inbound tunnel ", tunnel->GetTunnelID (), " has been declined");
				tunnel->SetState (i2p::tunnel::eTunnelStateBuildFailed);
			}
			return;
		}

		// 这个隧道不是我创立的，开始逐步处理每个隧道记录
		const uint8_t * record = buf + 1;
		for (int i = 0; i < num; i++)
		{
			// 检查记录中的身份散列（IdentHash）是否匹配本地路由器，如果匹配则是自己的记录，说明创建者就是来找我创建隧道的，如果不是就处理下一个记录
			// （这些不同的记录有什么关系呢） 
			if (!memcmp (record, (const uint8_t *)i2p::context.GetRouterInfo ().GetIdentHash (), 16))
			{
				LogPrint (eLogDebug, "I2NP: Short request record ", i, " is ours");
				uint8_t clearText[SHORT_REQUEST_RECORD_CLEAR_TEXT_SIZE];
				// 解密记录中的请求，如果解密失败就返回
				if (!i2p::context.DecryptTunnelShortRequestRecord (record + SHORT_REQUEST_RECORD_ENCRYPTED_OFFSET, clearText))
				{
					LogPrint (eLogWarning, "I2NP: Can't decrypt short request record ", i);
					return;
				}

				// 检查加密层的类型，如果不是 AES，输出警告并返回
				if (clearText[SHORT_REQUEST_RECORD_LAYER_ENCRYPTION_TYPE]) // not AES
				{
					LogPrint (eLogWarning, "I2NP: Unknown layer encryption type ", clearText[SHORT_REQUEST_RECORD_LAYER_ENCRYPTION_TYPE], " in short request record");
					return;
				}

				// 获取当前的 Noise 状态，用于后续的密钥生成
				auto& noiseState = i2p::context.GetCurrentNoiseState ();

				// 生成回复密钥 (AEAD/Chacha20/Poly1305) 和层密钥 (AES)
				uint8_t replyKey[32]; // AEAD/Chacha20/Poly1305
				i2p::crypto::AESKey layerKey, ivKey; // AES
				i2p::crypto::HKDF (noiseState.m_CK, nullptr, 0, "SMTunnelReplyKey", noiseState.m_CK);
				memcpy (replyKey, noiseState.m_CK + 32, 32);
				i2p::crypto::HKDF (noiseState.m_CK, nullptr, 0, "SMTunnelLayerKey", noiseState.m_CK);
				memcpy (layerKey, noiseState.m_CK + 32, 32);

				// 检查该记录是否是终端节点
				bool isEndpoint = clearText[SHORT_REQUEST_RECORD_FLAG_OFFSET] & TUNNEL_BUILD_RECORD_ENDPOINT_FLAG;	// TUNNEL_BUILD_RECORD_ENDPOINT_FLAG = 64U
				if (isEndpoint)
				{
					// 如果是终端节点，生成初始化向量密钥（IV Key）
					i2p::crypto::HKDF (noiseState.m_CK, nullptr, 0, "TunnelLayerIVKey", noiseState.m_CK);
					memcpy (ivKey, noiseState.m_CK + 32, 32);
				}
				else
				{	
					// 如果不是终端节点，检查下一跳的身份是否与当前节点匹配，如果匹配，输出警告并返回（不能自己发给自己）
					if (!memcmp ((const uint8_t *)i2p::context.GetIdentHash (), clearText + SHORT_REQUEST_RECORD_NEXT_IDENT_OFFSET, 32)) // if next ident is now ours
					{
						LogPrint (eLogWarning, "I2NP: Next ident is ours in short request record");
						return;
					}	
					memcpy (ivKey, noiseState.m_CK , 32);
				}	

				// check if we accept this tunnel
				std::shared_ptr<i2p::tunnel::TransitTunnel> transitTunnel;
				uint8_t retCode = 0;
				if (!i2p::context.AcceptsTunnels () || i2p::context.GetCongestionLevel (false) >= CONGESTION_LEVEL_FULL)
					retCode = 30;	// 拒绝隧道
				if (!retCode)
				{
					// create new transit tunnel
					// 主要是走这边
					transitTunnel = i2p::tunnel::CreateTransitTunnel (
						host, port,
						bufbe32toh (clearText + SHORT_REQUEST_RECORD_RECEIVE_TUNNEL_OFFSET),
						clearText + SHORT_REQUEST_RECORD_NEXT_IDENT_OFFSET,
						bufbe32toh (clearText + SHORT_REQUEST_RECORD_NEXT_TUNNEL_OFFSET),
						layerKey, ivKey,
						clearText[SHORT_REQUEST_RECORD_FLAG_OFFSET] & TUNNEL_BUILD_RECORD_GATEWAY_FLAG,
						clearText[SHORT_REQUEST_RECORD_FLAG_OFFSET] & TUNNEL_BUILD_RECORD_ENDPOINT_FLAG);
					if (!i2p::tunnel::tunnels.AddTransitTunnel (transitTunnel))
						retCode = 30;
				}

				// 加密回复消息
				uint8_t nonce[12];		// 用于 AEAD 加密的 nonce
				memset (nonce, 0, 12);
				uint8_t * reply = buf + 1;
				for (int j = 0; j < num; j++)
				{
					nonce[4] = j; // nonce 的第 4 字节是记录的索引
					if (j == i)
					{
						// 对自己的记录进行加密并返回结果
						memset (reply + SHORT_RESPONSE_RECORD_OPTIONS_OFFSET, 0, 2); // no options
						reply[SHORT_RESPONSE_RECORD_RET_OFFSET] = retCode;
						if (!i2p::crypto::AEADChaCha20Poly1305 (reply, SHORT_TUNNEL_BUILD_RECORD_SIZE - 16,
							noiseState.m_H, 32, replyKey, nonce, reply, SHORT_TUNNEL_BUILD_RECORD_SIZE, true)) // encrypt
						{
							LogPrint (eLogWarning, "I2NP: Short reply AEAD encryption failed");
							return;
						}
					}
					else
						// 如果不是当前记录，对其进行 ChaCha20 加密
						i2p::crypto::ChaCha20 (reply, SHORT_TUNNEL_BUILD_RECORD_SIZE, replyKey, nonce, reply);
					reply += SHORT_TUNNEL_BUILD_RECORD_SIZE;		// 处理下一个记录
				}

				// 定义当消息被丢弃时的处理函数
				// send reply
				auto onDrop = [transitTunnel]()
					{
						if (transitTunnel)
						{
							// 如果隧道超时，将其标记为过期
							auto t = transitTunnel->GetCreationTime ();
							if (t > i2p::tunnel::TUNNEL_EXPIRATION_TIMEOUT)
								// make transit tunnel expired 
								transitTunnel->SetCreationTime (t - i2p::tunnel::TUNNEL_EXPIRATION_TIMEOUT);
						}	
					};

				// 如果当前是终端节点，那么回复消息，否则将消息转发给下一个结点
				if (isEndpoint)
				{
					// 创建一个新的I2NP短消息
					auto replyMsg = NewI2NPShortMessage ();

					// 将接收到的数据添加到消息中
					replyMsg->Concat (buf, len);

					// 填充I2NP消息头，设置消息类型为短隧道构建回复，并将消息ID设置为从`clearText`解析出来的值
					replyMsg->FillI2NPMessageHeader (eI2NPShortTunnelBuildReply, bufbe32toh (clearText + SHORT_REQUEST_RECORD_SEND_MSG_ID_OFFSET));
					if (transitTunnel) replyMsg->onDrop = onDrop;		// 我们同意这个隧道

					// 检查收到的下一跳的身份哈希是否与本地节点的身份哈希匹配，即回复的入站网关是否是本地节点
					// 这时候应该把信息发送给创建者的一个入站隧道的网关
					if (memcmp ((const uint8_t *)i2p::context.GetIdentHash (),
						clearText + SHORT_REQUEST_RECORD_NEXT_IDENT_OFFSET, 32)) // reply IBGW is not local?
					{
						// 入站隧道网关不是我们
						i2p::crypto::HKDF (noiseState.m_CK, nullptr, 0, "RGarlicKeyAndTag", noiseState.m_CK);
						uint64_t tag;
						memcpy (&tag, noiseState.m_CK, 8);
						// we send it to reply tunnel

						// 将回复消息发送到下一个隧道，通过封装后的ECIES加密发送
						transports.SendMessage (clearText + SHORT_REQUEST_RECORD_NEXT_IDENT_OFFSET,
						CreateTunnelGatewayMsg (bufbe32toh (clearText + SHORT_REQUEST_RECORD_NEXT_TUNNEL_OFFSET),
							i2p::garlic::WrapECIESX25519Message (replyMsg, noiseState.m_CK + 32, tag)));
					}
					else
					{
						 // 如果回复的入站网关是本地节点
						// IBGW is local
						uint32_t tunnelID = bufbe32toh (clearText + SHORT_REQUEST_RECORD_NEXT_TUNNEL_OFFSET);

						// 从隧道管理器中查找对应的隧道
						auto tunnel = i2p::tunnel::tunnels.GetTunnel (tunnelID);
						if (tunnel)
						{	
							// 发送回复消息到隧道
							tunnel->SendTunnelDataMsg (replyMsg);

							// 刷新隧道数据消息队列
							tunnel->FlushTunnelDataMsgs ();
						}	
						else
							LogPrint (eLogWarning, "I2NP: Tunnel ", tunnelID, " not found for short tunnel build reply");
					}
				}
				else
				{
					auto msg = CreateI2NPMessage (eI2NPShortTunnelBuild, buf, len,
							bufbe32toh (clearText + SHORT_REQUEST_RECORD_SEND_MSG_ID_OFFSET));
					if (transitTunnel) msg->onDrop = onDrop;
					transports.SendMessage (clearText + SHORT_REQUEST_RECORD_NEXT_IDENT_OFFSET, msg);
				}	
				return;		// 处理完自己的记录后退出循环，也就是不管其他记录了
			}

			// 处理下一个记录
			record += SHORT_TUNNEL_BUILD_RECORD_SIZE;
		}
	}

	std::shared_ptr<I2NPMessage> CreateTunnelDataMsg (const uint8_t * buf)
	{
		auto msg = NewI2NPTunnelMessage (false);
		msg->Concat (buf, i2p::tunnel::TUNNEL_DATA_MSG_SIZE);
		msg->FillI2NPMessageHeader (eI2NPTunnelData);
		return msg;
	}

	std::shared_ptr<I2NPMessage> CreateTunnelDataMsg (uint32_t tunnelID, const uint8_t * payload)
	{
		auto msg = NewI2NPTunnelMessage (false);
		htobe32buf (msg->GetPayload (), tunnelID);
		msg->len += 4; // tunnelID
		msg->Concat (payload, i2p::tunnel::TUNNEL_DATA_MSG_SIZE - 4);
		msg->FillI2NPMessageHeader (eI2NPTunnelData);
		return msg;
	}

	std::shared_ptr<I2NPMessage> CreateEmptyTunnelDataMsg (bool endpoint)
	{
		auto msg = NewI2NPTunnelMessage (endpoint);
		msg->len += i2p::tunnel::TUNNEL_DATA_MSG_SIZE;
		return msg;
	}

	std::shared_ptr<I2NPMessage> CreateTunnelGatewayMsg (uint32_t tunnelID, const uint8_t * buf, size_t len)
	{
		auto msg = NewI2NPMessage (len);
		uint8_t * payload = msg->GetPayload ();
		htobe32buf (payload + TUNNEL_GATEWAY_HEADER_TUNNELID_OFFSET, tunnelID);
		htobe16buf (payload + TUNNEL_GATEWAY_HEADER_LENGTH_OFFSET, len);
		msg->len += TUNNEL_GATEWAY_HEADER_SIZE;
		if (msg->Concat (buf, len) < len)
			LogPrint (eLogError, "I2NP: Tunnel gateway buffer overflow ", msg->maxLen);
		msg->FillI2NPMessageHeader (eI2NPTunnelGateway);
		return msg;
	}

	std::shared_ptr<I2NPMessage> CreateTunnelGatewayMsg (uint32_t tunnelID, std::shared_ptr<I2NPMessage> msg)
	{
		if (msg->offset >= I2NP_HEADER_SIZE + TUNNEL_GATEWAY_HEADER_SIZE)
		{
			// message is capable to be used without copying
			uint8_t * payload = msg->GetBuffer () - TUNNEL_GATEWAY_HEADER_SIZE;
			htobe32buf (payload + TUNNEL_GATEWAY_HEADER_TUNNELID_OFFSET, tunnelID);
			int len = msg->GetLength ();
			htobe16buf (payload + TUNNEL_GATEWAY_HEADER_LENGTH_OFFSET, len);
			msg->offset -= (I2NP_HEADER_SIZE + TUNNEL_GATEWAY_HEADER_SIZE);
			msg->len = msg->offset + I2NP_HEADER_SIZE + TUNNEL_GATEWAY_HEADER_SIZE +len;
			msg->FillI2NPMessageHeader (eI2NPTunnelGateway);
			return msg;
		}
		else
		{	
			auto newMsg = CreateTunnelGatewayMsg (tunnelID, msg->GetBuffer (), msg->GetLength ());
			if (msg->onDrop) newMsg->onDrop = msg->onDrop; 
			return newMsg;
		}	
	}

	std::shared_ptr<I2NPMessage> CreateTunnelGatewayMsg (uint32_t tunnelID, I2NPMessageType msgType,
		const uint8_t * buf, size_t len, uint32_t replyMsgID)
	{
		auto msg = NewI2NPMessage (len);
		size_t gatewayMsgOffset = I2NP_HEADER_SIZE + TUNNEL_GATEWAY_HEADER_SIZE;
		msg->offset += gatewayMsgOffset;
		msg->len += gatewayMsgOffset;
		if (msg->Concat (buf, len) < len)
			LogPrint (eLogError, "I2NP: Tunnel gateway buffer overflow ", msg->maxLen);
		msg->FillI2NPMessageHeader (msgType, replyMsgID); // create content message
		len = msg->GetLength ();
		msg->offset -= gatewayMsgOffset;
		uint8_t * payload = msg->GetPayload ();
		htobe32buf (payload + TUNNEL_GATEWAY_HEADER_TUNNELID_OFFSET, tunnelID);
		htobe16buf (payload + TUNNEL_GATEWAY_HEADER_LENGTH_OFFSET, len);
		msg->FillI2NPMessageHeader (eI2NPTunnelGateway); // gateway message
		return msg;
	}

	size_t GetI2NPMessageLength (const uint8_t * msg, size_t len)
	{
		if (len < I2NP_HEADER_SIZE_OFFSET + 2)
		{
			LogPrint (eLogError, "I2NP: Message length ", len, " is smaller than header");
			return len;
		}
		auto l = bufbe16toh (msg + I2NP_HEADER_SIZE_OFFSET) + I2NP_HEADER_SIZE;
		if (l > len)
		{
			LogPrint (eLogError, "I2NP: Message length ", l, " exceeds buffer length ", len);
			l = len;
		}
		return l;
	}

	void HandleTunnelBuildI2NPMessage (std::shared_ptr<I2NPMessage> msg)
	{
		if (msg)
		{
			std::string host = msg->GetIP();
			std::string port = msg->GetPort();
			uint8_t typeID = msg->GetTypeID();
			uint32_t msgID = msg->GetMsgID();
			LogPrint (eLogDebug, "I2NP: Handling tunnel build message with len=", msg->GetLength(),", type=", (int)typeID, ", msgID=", (unsigned int)msgID);
			uint8_t * payload = msg->GetPayload();
			auto size = msg->GetPayloadLength();
			switch (typeID)
			{
				case eI2NPVariableTunnelBuild:
					// LogToFile("收到VariableTunnelBuild消息");		// 入站隧道，有可能中继路由
					HandleVariableTunnelBuildMsg (host, port, msgID, payload, size);
					break;
				case eI2NPShortTunnelBuild:
					// LogToFile("收到ShortTunnelBuild消息");		// 入站隧道，有可能中继路由
					// 这个消息可能创建自己的隧道，也可能创建传输隧道
					HandleShortTunnelBuildMsg (host, port, msgID, payload, size);
					break;
				case eI2NPVariableTunnelBuildReply:
					// LogToFile("收到VariableTunnelBuildReply消息");		// 出站隧道
					HandleTunnelBuildReplyMsg (msgID, payload, size, false);
					break;
				case eI2NPShortTunnelBuildReply:
					// LogToFile("收到ShortTunnelBuildReply消息");		// 出站隧道
					HandleTunnelBuildReplyMsg (msgID, payload, size, true);
					break;
				case eI2NPTunnelBuild:
					// LogToFile("收到I2NPTunnelBuild消息");
					HandleTunnelBuildMsg (payload, size);
					break;
				case eI2NPTunnelBuildReply:
					// LogToFile("收到I2NPTunnelBuildReply消息");
					// TODO:
					break;
				default:
					LogPrint (eLogError, "I2NP: Unexpected message with type", (int)typeID, " during handling TBM; skipping");
			}
		}
	}

	void HandleI2NPMessage (std::shared_ptr<I2NPMessage> msg)
	{
		if (msg)
		{
			uint8_t typeID = msg->GetTypeID ();
			LogPrint (eLogDebug, "I2NP: Handling message with type ", (int)typeID);
			switch (typeID)
			{
				case eI2NPTunnelData:
					if (!msg->from)
						i2p::tunnel::tunnels.PostTunnelData (msg);
				break;
				case eI2NPTunnelGateway:
					if (!msg->from)
						i2p::tunnel::tunnels.PostTunnelData (msg);
				break;
				case eI2NPGarlic:
				{
					if (msg->from && msg->from->GetTunnelPool ())
						msg->from->GetTunnelPool ()->ProcessGarlicMessage (msg);
					else
						i2p::context.ProcessGarlicMessage (msg);
					break;
				}
				case eI2NPDatabaseStore:
				case eI2NPDatabaseSearchReply:	
					// forward to netDb if came directly or through exploratory tunnel as response to our request
					if (!msg->from || !msg->from->GetTunnelPool () || msg->from->GetTunnelPool ()->IsExploratory ())
						i2p::data::netdb.PostI2NPMsg (msg);
				break;
				
				case eI2NPDatabaseLookup:
					// forward to netDb if floodfill and came directly
					if (!msg->from && i2p::context.IsFloodfill ())
						i2p::data::netdb.PostI2NPMsg (msg);
				break;
				case eI2NPDeliveryStatus:
				{
					if (msg->from && msg->from->GetTunnelPool ())
						msg->from->GetTunnelPool ()->ProcessDeliveryStatus (msg);
					else
						i2p::context.ProcessDeliveryStatusMessage (msg);
					break;
				}
				case eI2NPTunnelTest:
					if (msg->from && msg->from->GetTunnelPool ())
						msg->from->GetTunnelPool ()->ProcessTunnelTest (msg);
				break;
				case eI2NPVariableTunnelBuild:
				case eI2NPTunnelBuild:
				case eI2NPShortTunnelBuild:
					// forward to tunnel thread
					if (!msg->from)
						i2p::tunnel::tunnels.PostTunnelData (msg);
				break;
				case eI2NPVariableTunnelBuildReply:
				case eI2NPTunnelBuildReply:
				case eI2NPShortTunnelBuildReply:
					// forward to tunnel thread
					i2p::tunnel::tunnels.PostTunnelData (msg);
				break;
				default:
					LogPrint(eLogError, "I2NP: Unexpected I2NP message with type ", int(typeID), " during handling; skipping");
			}
		}
	}

	I2NPMessagesHandler::~I2NPMessagesHandler ()
	{
		Flush ();
	}

	void I2NPMessagesHandler::PutNextMessage (std::shared_ptr<I2NPMessage>&& msg)
	{
		if (msg)
		{
			switch (msg->GetTypeID ())
			{
				case eI2NPTunnelData:
					m_TunnelMsgs.push_back (msg);
				break;
				case eI2NPTunnelGateway:
					m_TunnelGatewayMsgs.push_back (msg);
				break;
				default:
					HandleI2NPMessage (msg);
			}
		}
	}

	void I2NPMessagesHandler::Flush ()
	{
		if (!m_TunnelMsgs.empty ())
		{
			i2p::tunnel::tunnels.PostTunnelData (m_TunnelMsgs);
			m_TunnelMsgs.clear ();
		}
		if (!m_TunnelGatewayMsgs.empty ())
		{
			i2p::tunnel::tunnels.PostTunnelData (m_TunnelGatewayMsgs);
			m_TunnelGatewayMsgs.clear ();
		}
	}
}
