/*
* Copyright (c) 2013-2024, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <algorithm>
#include "I2PEndian.h"
#include "Crypto.h"
#include "Tunnel.h"
#include "NetDb.hpp"
#include "Timestamp.h"
#include "Garlic.h"
#include "ECIESX25519AEADRatchetSession.h"
#include "Transports.h"
#include "Log.h"
#include "Tunnel.h"
#include "TunnelPool.h"
#include "Destination.h"
#include "Logger.h"

namespace i2p
{
namespace tunnel
{
	void Path::Add (std::shared_ptr<const i2p::data::RouterInfo> r)
	{
		if (r)
		{
			peers.push_back (r->GetRouterIdentity ());
			if (r->GetVersion () < i2p::data::NETDB_MIN_SHORT_TUNNEL_BUILD_VERSION ||
				r->GetRouterIdentity ()->GetCryptoKeyType () != i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD)
				isShort = false;
		}
	}

	void Path::Reverse ()
	{
		std::reverse (peers.begin (), peers.end ());
	}

	TunnelPool::TunnelPool (int numInboundHops, int numOutboundHops, int numInboundTunnels,
		int numOutboundTunnels, int inboundVariance, int outboundVariance):
		m_NumInboundHops (numInboundHops), m_NumOutboundHops (numOutboundHops),
		m_NumInboundTunnels (numInboundTunnels), m_NumOutboundTunnels (numOutboundTunnels),
		m_InboundVariance (inboundVariance), m_OutboundVariance (outboundVariance),
		m_IsActive (true), m_CustomPeerSelector(nullptr), m_Rng(m_Rd())
	{
		if (m_NumInboundTunnels > TUNNEL_POOL_MAX_INBOUND_TUNNELS_QUANTITY)
			m_NumInboundTunnels = TUNNEL_POOL_MAX_INBOUND_TUNNELS_QUANTITY;
		if (m_NumOutboundTunnels > TUNNEL_POOL_MAX_OUTBOUND_TUNNELS_QUANTITY)
			m_NumOutboundTunnels = TUNNEL_POOL_MAX_OUTBOUND_TUNNELS_QUANTITY;
		if (m_InboundVariance < 0 && m_NumInboundHops + m_InboundVariance <= 0)
			m_InboundVariance = m_NumInboundHops ? -m_NumInboundHops + 1 : 0;
		if (m_OutboundVariance < 0 && m_NumOutboundHops + m_OutboundVariance <= 0)
			m_OutboundVariance = m_NumOutboundHops ? -m_NumOutboundHops + 1 : 0;
		if (m_InboundVariance > 0 && m_NumInboundHops + m_InboundVariance > STANDARD_NUM_RECORDS)
			m_InboundVariance = (m_NumInboundHops < STANDARD_NUM_RECORDS) ? STANDARD_NUM_RECORDS - m_NumInboundHops : 0;
		if (m_OutboundVariance > 0 && m_NumOutboundHops + m_OutboundVariance > STANDARD_NUM_RECORDS)
			m_OutboundVariance = (m_NumOutboundHops < STANDARD_NUM_RECORDS) ? STANDARD_NUM_RECORDS - m_NumOutboundHops : 0;
		m_NextManageTime = i2p::util::GetSecondsSinceEpoch () + rand () % TUNNEL_POOL_MANAGE_INTERVAL;
	}

	TunnelPool::~TunnelPool ()
	{
		DetachTunnels ();
	}

	// 设置隧道池的明确指定的对等体（peers）
	void TunnelPool::SetExplicitPeers(std::shared_ptr<std::vector<i2p::data::IdentHash>> explicitPeers)
	{
		// 将传入的明确指定的对等体列表赋值给成员变量m_ExplicitPeers
		m_ExplicitPeers = explicitPeers;

		// 如果提供了明确指定的对等体列表
		if (m_ExplicitPeers)
		{
			// 获取列表的大小
			int size = m_ExplicitPeers->size();

			// 如果入站隧道的跳点数量大于列表的大小，调整入站隧道的跳点数量
			if (m_NumInboundHops > size)
			{
				m_NumInboundHops = size;
				// 打印信息日志，说明入站隧道长度已根据明确指定的对等体列表的大小进行了调整
				LogPrint(eLogInfo, "Tunnels: Inbound tunnel length has been adjusted to ", size, " for explicit peers");
			}
			// 如果出站隧道的跳点数量大于列表的大小，调整出站隧道的跳点数量
			if (m_NumOutboundHops > size)
			{
				m_NumOutboundHops = size;
				// 打印信息日志，说明出站隧道长度已根据明确指定的对等体列表的大小进行了调整
				LogPrint(eLogInfo, "Tunnels: Outbound tunnel length has been adjusted to ", size, " for explicit peers");
			}

			// 设置入站和出站隧道的数量为1，因为明确指定的对等体列表限制了隧道的构建
			m_NumInboundTunnels = 1;
			m_NumOutboundTunnels = 1;
		}
	}

	void TunnelPool::DetachTunnels ()
	{
		{
			std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
			for (auto& it: m_InboundTunnels)
				it->SetTunnelPool (nullptr);
			m_InboundTunnels.clear ();
		}
		{
			std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
			for (auto& it: m_OutboundTunnels)
				it->SetTunnelPool (nullptr);
			m_OutboundTunnels.clear ();
		}
		{
			std::unique_lock<std::mutex> l(m_TestsMutex);
			m_Tests.clear ();
		}	
	}

	bool TunnelPool::Reconfigure(int inHops, int outHops, int inQuant, int outQuant)
	{
		if( inHops >= 0 && outHops >= 0 && inQuant > 0 && outQuant > 0)
		{
			m_NumInboundHops = inHops;
			m_NumOutboundHops = outHops;
			m_NumInboundTunnels = inQuant;
			m_NumOutboundTunnels = outQuant;
			return true;
		}
		return false;
	}

	void TunnelPool::TunnelCreated (std::shared_ptr<InboundTunnel> createdTunnel)
	{
		if (!m_IsActive) return;
		{
			std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
			if (createdTunnel->IsRecreated ())
			{
				// find and mark old tunnel as expired
				createdTunnel->SetRecreated (false);
				for (auto& it: m_InboundTunnels)
					if (it->IsRecreated () && it->GetNextIdentHash () == createdTunnel->GetNextIdentHash ())
					{
						it->SetState (eTunnelStateExpiring);
						break;
					}
			}
			m_InboundTunnels.insert (createdTunnel);
		}
		if (m_LocalDestination)
			m_LocalDestination->SetLeaseSetUpdated ();
	}

	void TunnelPool::TunnelExpired (std::shared_ptr<InboundTunnel> expiredTunnel)
	{
		if (expiredTunnel)
		{
			expiredTunnel->SetTunnelPool (nullptr);
			{
				std::unique_lock<std::mutex> l(m_TestsMutex);
				for (auto& it: m_Tests)
					if (it.second.second == expiredTunnel) it.second.second = nullptr;
			}	

			std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
			m_InboundTunnels.erase (expiredTunnel);
		}
	}

	void TunnelPool::TunnelCreated (std::shared_ptr<OutboundTunnel> createdTunnel)
	{
		if (!m_IsActive) return;
		{
			std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
			m_OutboundTunnels.insert (createdTunnel);
		}
	}

	void TunnelPool::TunnelExpired (std::shared_ptr<OutboundTunnel> expiredTunnel)
	{
		if (expiredTunnel)
		{
			expiredTunnel->SetTunnelPool (nullptr);
			{
				std::unique_lock<std::mutex> l(m_TestsMutex);
				for (auto& it: m_Tests)
					if (it.second.first == expiredTunnel) it.second.first = nullptr;
			}	

			std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
			m_OutboundTunnels.erase (expiredTunnel);
		}
	}

	std::vector<std::shared_ptr<InboundTunnel> > TunnelPool::GetInboundTunnels (int num) const
	{
		std::vector<std::shared_ptr<InboundTunnel> > v;
		int i = 0;
		std::shared_ptr<InboundTunnel> slowTunnel;
		std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
		for (const auto& it : m_InboundTunnels)
		{
			if (i >= num) break;
			if (it->IsEstablished ())
			{
				if (it->IsSlow () && !slowTunnel)
					slowTunnel = it;
				else
				{
					v.push_back (it);
					i++;
				}
			}
		}
		if (slowTunnel && (int)v.size () < (num/2+1))
			v.push_back (slowTunnel);
		return v;
	}

	std::shared_ptr<OutboundTunnel> TunnelPool::GetNextOutboundTunnel (std::shared_ptr<OutboundTunnel> excluded,
		i2p::data::RouterInfo::CompatibleTransports compatible) const
	{
		std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
		return GetNextTunnel (m_OutboundTunnels, excluded, compatible);
	}

	std::shared_ptr<InboundTunnel> TunnelPool::GetNextInboundTunnel (std::shared_ptr<InboundTunnel> excluded,
		i2p::data::RouterInfo::CompatibleTransports compatible) const
	{
		std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
		return GetNextTunnel (m_InboundTunnels, excluded, compatible);
	}

	template<class TTunnels>
	typename TTunnels::value_type TunnelPool::GetNextTunnel (TTunnels& tunnels,
		typename TTunnels::value_type excluded, i2p::data::RouterInfo::CompatibleTransports compatible) const
	{
		if (tunnels.empty ()) return nullptr;
		uint32_t ind = rand () % (tunnels.size ()/2 + 1), i = 0;
		bool skipped = false;
		typename TTunnels::value_type tunnel = nullptr;
		for (const auto& it: tunnels)
		{
			if (it->IsEstablished () && it != excluded && (compatible & it->GetFarEndTransports ()))
			{
				if (it->IsSlow () || (HasLatencyRequirement() && it->LatencyIsKnown() &&
					!it->LatencyFitsRange(m_MinLatency, m_MaxLatency)))
				{
					i++; skipped = true;
					continue;
				}
				tunnel = it;
				i++;
			}
			if (i > ind && tunnel) break;
		}
		if (!tunnel && skipped)
		{
			ind = rand () % (tunnels.size ()/2 + 1), i = 0;
			for (const auto& it: tunnels)
			{
				if (it->IsEstablished () && it != excluded)
				{
					tunnel = it;
					i++;
				}
				if (i > ind && tunnel) break;
			}
		}
		if (!tunnel && excluded && excluded->IsEstablished ()) tunnel = excluded;
		return tunnel;
	}

	std::pair<std::shared_ptr<OutboundTunnel>, bool> TunnelPool::GetNewOutboundTunnel (std::shared_ptr<OutboundTunnel> old) const
	{
		if (old && old->IsEstablished ()) return std::make_pair(old, false);
		std::shared_ptr<OutboundTunnel> tunnel;
		bool freshTunnel = false;
		if (old)
		{
			std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
			for (const auto& it: m_OutboundTunnels)
				if (it->IsEstablished () && old->GetEndpointIdentHash () == it->GetEndpointIdentHash ())
				{
					tunnel = it;
					break;
				}
		}

		if (!tunnel)
		{	
			tunnel = GetNextOutboundTunnel ();
			freshTunnel = true;
		}	
		return std::make_pair(tunnel, freshTunnel);
	}

	void TunnelPool::CreateTunnels ()
	{
		int num = 0;
		{
			std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
			for (const auto& it : m_OutboundTunnels)
				if (it->IsEstablished ()) num++;
		}
		num = m_NumOutboundTunnels - num;
		if (num > 0)
		{
			if (num > TUNNEL_POOL_MAX_NUM_BUILD_REQUESTS) num = TUNNEL_POOL_MAX_NUM_BUILD_REQUESTS;
			for (int i = 0; i < num; i++)
				CreateOutboundTunnel ();
		}

		num = 0;
		{
			std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
			for (const auto& it : m_InboundTunnels)
				if (it->IsEstablished ()) num++;
		}
		if (!num && !m_OutboundTunnels.empty () && m_NumOutboundHops > 0 && 
		    m_NumInboundHops == m_NumOutboundHops)
		{
			for (auto it: m_OutboundTunnels)
			{
				// try to create inbound tunnel through the same path as successive outbound
				CreatePairedInboundTunnel (it);
				num++;
				if (num >= m_NumInboundTunnels) break;
			}
		}
		num = m_NumInboundTunnels - num;
		if (num > 0)
		{
			if (num > TUNNEL_POOL_MAX_NUM_BUILD_REQUESTS) num = TUNNEL_POOL_MAX_NUM_BUILD_REQUESTS;
			for (int i = 0; i < num; i++)
				CreateInboundTunnel ();
		}

		if (num < m_NumInboundTunnels && m_NumInboundHops <= 0 && m_LocalDestination) // zero hops IB
			m_LocalDestination->SetLeaseSetUpdated (); // update LeaseSet immediately
	}

	void TunnelPool::TestTunnels ()
	{
		decltype(m_Tests) tests;
		{
			std::unique_lock<std::mutex> l(m_TestsMutex);
			tests.swap(m_Tests);
		}

		for (auto& it: tests)
		{
			LogPrint (eLogWarning, "Tunnels: Test of tunnel ", it.first, " failed");
			// if test failed again with another tunnel we consider it failed
			if (it.second.first)
			{
				if (it.second.first->GetState () == eTunnelStateTestFailed)
				{
					it.second.first->SetState (eTunnelStateFailed);
					std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
					if (m_OutboundTunnels.size () > 1 || m_NumOutboundTunnels <= 1) // don't fail last tunnel
						m_OutboundTunnels.erase (it.second.first);
					else
						it.second.first->SetState (eTunnelStateTestFailed);
				}
				else if (it.second.first->GetState () != eTunnelStateExpiring)
					it.second.first->SetState (eTunnelStateTestFailed);
			}
			if (it.second.second)
			{
				if (it.second.second->GetState () == eTunnelStateTestFailed)
				{
					it.second.second->SetState (eTunnelStateFailed);
					{
						std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
						if (m_InboundTunnels.size () > 1 || m_NumInboundTunnels <= 1) // don't fail last tunnel
							m_InboundTunnels.erase (it.second.second);
						else
							it.second.second->SetState (eTunnelStateTestFailed);
					}
					if (m_LocalDestination)
						m_LocalDestination->SetLeaseSetUpdated ();
				}
				else if (it.second.second->GetState () != eTunnelStateExpiring)
					it.second.second->SetState (eTunnelStateTestFailed);
			}
		}

		// new tests
		if (!m_LocalDestination) return; 
		std::vector<std::pair<std::shared_ptr<OutboundTunnel>, std::shared_ptr<InboundTunnel> > > newTests;
		std::vector<std::shared_ptr<OutboundTunnel> > outboundTunnels;
		{
			std::unique_lock<std::mutex> l(m_OutboundTunnelsMutex);
			for (auto& it: m_OutboundTunnels)
				if (it->IsEstablished ())
					outboundTunnels.push_back (it);
		}
		std::shuffle (outboundTunnels.begin(), outboundTunnels.end(), m_Rng);
		std::vector<std::shared_ptr<InboundTunnel> > inboundTunnels;
		{
			std::unique_lock<std::mutex> l(m_InboundTunnelsMutex);
			for (auto& it: m_InboundTunnels)
				if (it->IsEstablished ())
					inboundTunnels.push_back (it);
		}
		std::shuffle (inboundTunnels.begin(), inboundTunnels.end(), m_Rng);
		auto it1 = outboundTunnels.begin ();
		auto it2 = inboundTunnels.begin ();
		while (it1 != outboundTunnels.end () && it2 != inboundTunnels.end ())
		{
			newTests.push_back(std::make_pair (*it1, *it2));
			++it1; ++it2;
		}
		bool isECIES = m_LocalDestination->SupportsEncryptionType (i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD);
		for (auto& it: newTests)
		{
			uint32_t msgID;
			RAND_bytes ((uint8_t *)&msgID, 4);
			{
				std::unique_lock<std::mutex> l(m_TestsMutex);
				m_Tests[msgID] = it;
			}
			auto msg = CreateTunnelTestMsg (msgID);
			auto outbound = it.first;
			auto s = shared_from_this ();
			msg->onDrop = [msgID, outbound, s]()
				{
					// if test msg dropped locally it's outbound tunnel to blame
					outbound->SetState (eTunnelStateFailed);
					{
						std::unique_lock<std::mutex> l(s->m_TestsMutex);
						s->m_Tests.erase (msgID);
					}
					{
						std::unique_lock<std::mutex> l(s->m_OutboundTunnelsMutex);
						s->m_OutboundTunnels.erase (outbound);
					}
				};
			// encrypt
			if (isECIES)
			{
				uint8_t key[32]; RAND_bytes (key, 32);
				uint64_t tag; RAND_bytes ((uint8_t *)&tag, 8); 
				m_LocalDestination->SubmitECIESx25519Key (key, tag);
				msg = i2p::garlic::WrapECIESX25519Message (msg, key, tag);
			}
			else
			{
				uint8_t key[32], tag[32];
				RAND_bytes (key, 32); RAND_bytes (tag, 32);
				m_LocalDestination->SubmitSessionKey (key, tag);
				i2p::garlic::ElGamalAESSession garlic (key, tag);
				msg = garlic.WrapSingleMessage (msg);
			}	
			outbound->SendTunnelDataMsgTo (it.second->GetNextIdentHash (), it.second->GetNextTunnelID (), msg);
		}	
	}

	void TunnelPool::ManageTunnels (uint64_t ts)
	{
		if (ts > m_NextManageTime || ts + 2*TUNNEL_POOL_MANAGE_INTERVAL < m_NextManageTime) // in case if clock was adjusted
		{
			CreateTunnels ();
			TestTunnels ();
			m_NextManageTime = ts + TUNNEL_POOL_MANAGE_INTERVAL + (rand () % TUNNEL_POOL_MANAGE_INTERVAL)/2;
		}
	}

	void TunnelPool::ProcessGarlicMessage (std::shared_ptr<I2NPMessage> msg)
	{
		if (m_LocalDestination)
			m_LocalDestination->ProcessGarlicMessage (msg);
		else
			LogPrint (eLogWarning, "Tunnels: Local destination doesn't exist, dropped");
	}

	void TunnelPool::ProcessDeliveryStatus (std::shared_ptr<I2NPMessage> msg)
	{
		if (m_LocalDestination)
			m_LocalDestination->ProcessDeliveryStatusMessage (msg);
		else
			LogPrint (eLogWarning, "Tunnels: Local destination doesn't exist, dropped");
	}

	void TunnelPool::ProcessTunnelTest (std::shared_ptr<I2NPMessage> msg)
	{
		const uint8_t * buf = msg->GetPayload ();
		uint32_t msgID = bufbe32toh (buf);
		buf += 4;
		uint64_t timestamp = bufbe64toh (buf);

		ProcessTunnelTest (msgID, timestamp);
	}

	bool TunnelPool::ProcessTunnelTest (uint32_t msgID, uint64_t timestamp)
	{
		decltype(m_Tests)::mapped_type test;
		bool found = false;
		{
			std::unique_lock<std::mutex> l(m_TestsMutex);
			auto it = m_Tests.find (msgID);
			if (it != m_Tests.end ())
			{
				found = true;
				test = it->second;
				m_Tests.erase (it);
			}
		}
		if (found)
		{
			int dlt = (uint64_t)i2p::util::GetMonotonicMicroseconds () - (int64_t)timestamp;
			LogPrint (eLogDebug, "Tunnels: Test of ", msgID, " successful. ", dlt, " microseconds");
			if (dlt < 0) dlt = 0; // should not happen
			int numHops = 0;
			if (test.first) numHops += test.first->GetNumHops ();
			if (test.second) numHops += test.second->GetNumHops ();
			// restore from test failed state if any
			if (test.first)
			{
				if (test.first->GetState () != eTunnelStateExpiring)
					test.first->SetState (eTunnelStateEstablished);
				// update latency
				int latency = 0;
				if (numHops) latency = dlt*test.first->GetNumHops ()/numHops;
				if (!latency) latency = dlt/2;
				test.first->AddLatencySample (latency);
			}
			if (test.second)
			{
				if (test.second->GetState () != eTunnelStateExpiring)
					test.second->SetState (eTunnelStateEstablished);
				// update latency
				int latency = 0;
				if (numHops) latency = dlt*test.second->GetNumHops ()/numHops;
				if (!latency) latency = dlt/2;
				test.second->AddLatencySample (latency);
			}
		}
		return found;
	}	
		
	bool TunnelPool::IsExploratory () const
	{
		return i2p::tunnel::tunnels.GetExploratoryPool () == shared_from_this ();
	}

	std::shared_ptr<const i2p::data::RouterInfo> TunnelPool::SelectNextHop (std::shared_ptr<const i2p::data::RouterInfo> prevHop, 
		bool reverse, bool endpoint) const
	{
		bool tryHighBandwidth = !IsExploratory ();
		std::shared_ptr<const i2p::data::RouterInfo> hop;
		for (int i = 0; i < TUNNEL_POOL_MAX_HOP_SELECTION_ATTEMPTS; i++)
		{
			hop = tryHighBandwidth ?
				i2p::data::netdb.GetHighBandwidthRandomRouter (prevHop, reverse, endpoint) :
				i2p::data::netdb.GetRandomRouter (prevHop, reverse, endpoint);
			if (hop)
			{
				if (!hop->GetProfile ()->IsBad ())
					break;
			}
			else if (tryHighBandwidth)
				tryHighBandwidth = false;
			else
				return nullptr;
		}
		return hop;
	}

	bool TunnelPool::StandardSelectPeers(Path & path, int numHops, bool inbound, SelectHopFunc nextHop)
	{
		int start = 0;
		std::shared_ptr<const i2p::data::RouterInfo> prevHop = i2p::context.GetSharedRouterInfo ();
		if(i2p::transport::transports.RoutesRestricted())
		{
			/** if routes are restricted prepend trusted first hop */
			auto hop = i2p::transport::transports.GetRestrictedPeer();
			if(!hop) return false;
			path.Add (hop);
			prevHop = hop;
			start++;
		}
		else if (i2p::transport::transports.GetNumPeers () > 100 ||
			(inbound && i2p::transport::transports.GetNumPeers () > 25))
		{
			auto r = i2p::transport::transports.GetRandomPeer (!IsExploratory ());
			if (r && r->IsECIES () && !r->GetProfile ()->IsBad () &&
				(numHops > 1 || (r->IsV4 () && (!inbound || r->IsPublished (true))))) // first inbound must be published ipv4
			{
				prevHop = r;
				path.Add (r);
				start++;
			}
		}

		for(int i = start; i < numHops; i++ )
		{
			auto hop = nextHop (prevHop, inbound, i == numHops - 1);
			if (!hop && !i) // if no suitable peer found for first hop, try already connected
			{
				LogPrint (eLogInfo, "Tunnels: Can't select first hop for a tunnel. Trying already connected");
				hop = i2p::transport::transports.GetRandomPeer (false);
				if (hop && !hop->IsECIES ()) hop = nullptr;
			}
			if (!hop)
			{
				LogPrint (eLogError, "Tunnels: Can't select next hop for ", prevHop->GetIdentHashBase64 ());
				return false;
			}
			prevHop = hop;
			path.Add (hop);
		}
		path.farEndTransports = prevHop->GetCompatibleTransports (inbound); // last hop
		return true;
	}

	// 挑选隧道的节点
	bool TunnelPool::SelectPeers (Path& path, bool isInbound)
	{
		////////////////选择入站隧道/////////////////////////
		// 创建一个智能指针，指向包含 IdentHash 对象的 vector
		if(isInbound){
			std::shared_ptr<std::vector<i2p::data::IdentHash>> explicitPeers =
				std::make_shared<std::vector<i2p::data::IdentHash>>();

			// 向 vector 中添加一些 IdentHash 对象
			size_t ret;
			i2p::data::IdentHash my_ident1;
			ret = my_ident1.FromBase64("4jV0bGLNa1DNg6e-vrw30KTKbES98NmVaPQlvsxfI0I=");
			explicitPeers->push_back(my_ident1);
			i2p::data::IdentHash my_ident2;
			ret = my_ident2.FromBase64("fwOptgWF3zskWoGfFxshL0FGcV6QBIKmg8QQKZDm5Ho=");
			explicitPeers->push_back(my_ident2);
			i2p::data::IdentHash my_ident3;
			ret = my_ident3.FromBase64("F4kKzMs3hbrclWqCbGv4i3mKIYrbDvKlzEoMi3yK8Fc=");
			explicitPeers->push_back(my_ident3);

			SetExplicitPeers(explicitPeers);
		}else{
			m_ExplicitPeers = nullptr;
		}

		///////////////////////////////////////////////////////////////
		// 如果使用了明确指定的对等体，调用SelectExplicitPeers函数选择对等体
		if (m_ExplicitPeers) {
			LogToFile("选择指定的入站隧道对等体，此时有 " + std::to_string(m_ExplicitPeers->size()) + " 个对等体");
			return SelectExplicitPeers (path, isInbound);
		}
		// 很少明确有定义对等体
		// calculate num hops
		int numHops;
		// 入站隧道配置跳数
		if (isInbound)
		{
			numHops = m_NumInboundHops;
			// 如果配置了入站跳点数量的随机偏差
			if (m_InboundVariance)
			{
				int offset = rand () % (std::abs (m_InboundVariance) + 1);
				if (m_InboundVariance < 0) offset = -offset;
				// 将偏移量应用到跳点数量上
				numHops += offset;
			}
		}

		// 出站隧道配置跳数
		else
		{
			numHops = m_NumOutboundHops;
			if (m_OutboundVariance)
			{
				int offset = rand () % (std::abs (m_OutboundVariance) + 1);
				if (m_OutboundVariance < 0) offset = -offset;
				numHops += offset;
			}
		}
		// peers is empty
		if (numHops <= 0) return true;
		// custom peer selector in use ?
		{
			std::lock_guard<std::mutex> lock(m_CustomPeerSelectorMutex);
			if (m_CustomPeerSelector){
				// 调用自定义选择器的SelectPeers函数选择对等体
				return m_CustomPeerSelector->SelectPeers(path, numHops, isInbound);
			}
		}
		// 使用标准的对等体选择算法，大家基本都是这样
		return StandardSelectPeers(path, numHops, isInbound, std::bind(&TunnelPool::SelectNextHop, this, 
			std::placeholders::_1, std::placeholders::_2, std::placeholders::_3));
	}

	// 从明确指定的对等体列表中选择隧道的对等体
	bool TunnelPool::SelectExplicitPeers (Path& path, bool isInbound)
	{
		// 如果明确指定的对等体列表为空，返回false
		if (!m_ExplicitPeers->size ()) return false;

		// 根据是否是入站隧道，确定跳点数量
		int numHops = isInbound ? m_NumInboundHops : m_NumOutboundHops;

		// 如果需要的跳点数量超过了明确指定的对等体列表的大小，使用列表的大小作为跳点数量
		if (numHops > (int)m_ExplicitPeers->size ()) numHops = m_ExplicitPeers->size ();

		// 遍历跳点数量指定的次数
		for (int i = 0; i < numHops; i++)
		{
			// 获取当前索引下的对等体标识
			auto& ident = (*m_ExplicitPeers)[i];

			// 在网络数据库中查找对应的路由器
			auto r = i2p::data::netdb.FindRouter (ident);

			// 如果找到了路由器
			if (r)
			{
				LogToFile("找到了" + ident.ToBase32());
				// 如果路由器支持ECIES加密
				if (r->IsECIES ())
				{
					// 将路由器添加到路径的对等体列表中
					path.Add (r);

					// 如果是最后一个跳点，设置远端的兼容传输类型
					if (i == numHops - 1)
						path.farEndTransports = r->GetCompatibleTransports (isInbound);
				}
				else
				{
					// 如果路由器不支持ECIES加密，记录错误日志并返回false
					LogPrint (eLogError, "Tunnels: ElGamal router ", ident.ToBase64 (), " is not supported");
					return false;
				}
			}
			else
			{
				// 如果没有找到任意一个路由器，之后也不会再找其他的
				LogToFile("没有找到" + ident.ToBase32());
				LogPrint (eLogInfo, "Tunnels: Can't find router for ", ident.ToBase64 ());

				// 请求网络数据库获取对应的目的地
				i2p::data::netdb.RequestDestination (ident);
				return false;
			}
		}
		return true;
	}

	// 创建入站隧道
	void TunnelPool::CreateInboundTunnel ()
	{	
		// 正在创建目的地入站隧道
		LogToFile("开始创建入站隧道");
		LogPrint (eLogDebug, "Tunnels: Creating destination inbound tunnel...");

		// 创建一个路径对象，用于存储隧道的跳点信息
		Path path;

		// 调用SelectPeers函数选择隧道的对等体（peers）
		// 第二个参数true表示这是一个入站隧道
		if (SelectPeers (path, true))
		{
			// 获取下一个可用的出站隧道，考虑远端支持的传输类型
			auto outboundTunnel = GetNextOutboundTunnel (nullptr, path.farEndTransports);

			// 如果没有可用的出站隧道，尝试获取任意可用的出站隧道
			if (!outboundTunnel)
				outboundTunnel = tunnels.GetNextOutboundTunnel ();

			// 创建隧道配置对象
			std::shared_ptr<TunnelConfig> config;

			// 如果入站跳点数量大于0，说明需要创建一个有跳点的隧道
			if (m_NumInboundHops > 0)
			{
				// 将路径中的跳点反转，因为入站隧道的路径需要反向
				path.Reverse ();
				// 创建隧道配置对象，包含跳点信息、是否为短隧道和远端传输类型
				config = std::make_shared<TunnelConfig> (path.peers, path.isShort, path.farEndTransports);
			}

			// 使用隧道配置创建一个新的入站隧道
			// shared_from_this()返回当前TunnelPool对象的shared_ptr
			// outboundTunnel是与入站隧道配对的出站隧道
			auto tunnel = tunnels.CreateInboundTunnel (config, shared_from_this (), outboundTunnel);

			// 如果隧道已经建立（零跳点隧道），则调用TunnelCreated函数处理
			if (tunnel->IsEstablished ()) // zero hops
				TunnelCreated (tunnel);
		}
		else
			LogPrint (eLogError, "Tunnels: Can't create inbound tunnel, no peers available");
	}

	void TunnelPool::RecreateInboundTunnel (std::shared_ptr<InboundTunnel> tunnel)
	{
		LogToFile("重新创建一个隧道");
		if (IsExploratory () || tunnel->IsSlow ()) // always create new exploratory tunnel or if slow
		{
			CreateInboundTunnel ();
			return;
		}
		auto outboundTunnel = GetNextOutboundTunnel (nullptr, tunnel->GetFarEndTransports ());
		if (!outboundTunnel)
			outboundTunnel = tunnels.GetNextOutboundTunnel ();
		LogPrint (eLogDebug, "Tunnels: Re-creating destination inbound tunnel...");
		std::shared_ptr<TunnelConfig> config;
		if (m_NumInboundHops > 0)
		{
			auto peers = tunnel->GetPeers();
			if (peers.size ()&& ValidatePeers (peers))
				config = std::make_shared<TunnelConfig>(tunnel->GetPeers (), 
					tunnel->IsShortBuildMessage (), tunnel->GetFarEndTransports ());
		}	
		if (!m_NumInboundHops || config)
		{
			auto newTunnel = tunnels.CreateInboundTunnel (config, shared_from_this(), outboundTunnel);
			if (newTunnel->IsEstablished ()) // zero hops
				TunnelCreated (newTunnel);
			else
				newTunnel->SetRecreated (true);
		}
	}

	void TunnelPool::CreateOutboundTunnel ()
	{
		LogPrint (eLogDebug, "Tunnels: Creating destination outbound tunnel...");
		Path path;
		if (SelectPeers (path, false))
		{
			auto inboundTunnel = GetNextInboundTunnel (nullptr, path.farEndTransports);
			if (!inboundTunnel)
				inboundTunnel = tunnels.GetNextInboundTunnel ();
			if (!inboundTunnel)
			{
				LogPrint (eLogError, "Tunnels: Can't create outbound tunnel, no inbound tunnels found");
				return;
			}

			if (m_LocalDestination && !m_LocalDestination->SupportsEncryptionType (i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD))
				path.isShort = false; // because can't handle ECIES encrypted reply

			std::shared_ptr<TunnelConfig> config;
			if (m_NumOutboundHops > 0)
				config = std::make_shared<TunnelConfig>(path.peers, inboundTunnel->GetNextTunnelID (),
					inboundTunnel->GetNextIdentHash (), path.isShort, path.farEndTransports);

			std::shared_ptr<OutboundTunnel> tunnel;
			if (path.isShort)
			{
				// TODO: implement it better
				tunnel = tunnels.CreateOutboundTunnel (config, inboundTunnel->GetTunnelPool ());
				tunnel->SetTunnelPool (shared_from_this ());
			}
			else
				tunnel = tunnels.CreateOutboundTunnel (config, shared_from_this ());
			if (tunnel && tunnel->IsEstablished ()) // zero hops
				TunnelCreated (tunnel);
		}
		else
			LogPrint (eLogError, "Tunnels: Can't create outbound tunnel, no peers available");
	}

	void TunnelPool::RecreateOutboundTunnel (std::shared_ptr<OutboundTunnel> tunnel)
	{
		if (IsExploratory () || tunnel->IsSlow ()) // always create new exploratory tunnel or if slow
		{
			CreateOutboundTunnel ();
			return;
		}
		auto inboundTunnel = GetNextInboundTunnel (nullptr, tunnel->GetFarEndTransports ());
		if (!inboundTunnel)
			inboundTunnel = tunnels.GetNextInboundTunnel ();
		if (inboundTunnel)
		{
			LogPrint (eLogDebug, "Tunnels: Re-creating destination outbound tunnel...");
			std::shared_ptr<TunnelConfig> config;
			if (m_NumOutboundHops > 0)
			{
				auto peers = tunnel->GetPeers();
				if (peers.size () && ValidatePeers (peers))
					config = std::make_shared<TunnelConfig>(peers, inboundTunnel->GetNextTunnelID (),
						inboundTunnel->GetNextIdentHash (), inboundTunnel->IsShortBuildMessage (), tunnel->GetFarEndTransports ());
			}
			if (!m_NumOutboundHops || config)
			{
				auto newTunnel = tunnels.CreateOutboundTunnel (config, shared_from_this ());
				if (newTunnel->IsEstablished ()) // zero hops
					TunnelCreated (newTunnel);
			}
		}
		else
			LogPrint (eLogDebug, "Tunnels: Can't re-create outbound tunnel, no inbound tunnels found");
	}

	void TunnelPool::CreatePairedInboundTunnel (std::shared_ptr<OutboundTunnel> outboundTunnel)
	{
		LogPrint (eLogDebug, "Tunnels: Creating paired inbound tunnel...");
		auto tunnel = tunnels.CreateInboundTunnel (
			m_NumOutboundHops > 0 ? std::make_shared<TunnelConfig>(outboundTunnel->GetInvertedPeers (),
				outboundTunnel->IsShortBuildMessage ()) : nullptr,
				shared_from_this (), outboundTunnel);
		if (tunnel->IsEstablished ()) // zero hops
			TunnelCreated (tunnel);
	}

	void TunnelPool::SetCustomPeerSelector(ITunnelPeerSelector * selector)
	{
		std::lock_guard<std::mutex> lock(m_CustomPeerSelectorMutex);
		m_CustomPeerSelector = selector;
	}

	void TunnelPool::UnsetCustomPeerSelector()
	{
		SetCustomPeerSelector(nullptr);
	}

	bool TunnelPool::HasCustomPeerSelector()
	{
		std::lock_guard<std::mutex> lock(m_CustomPeerSelectorMutex);
		return m_CustomPeerSelector != nullptr;
	}

	bool TunnelPool::ValidatePeers (std::vector<std::shared_ptr<const i2p::data::IdentityEx> >& peers) const
	{
		bool highBandwidth = !IsExploratory ();
		for (auto it: peers)
		{
			auto r = i2p::data::netdb.FindRouter (it->GetIdentHash ());
			if (r)
			{
				if (r->IsHighCongestion (highBandwidth)) return false;
				it = r->GetIdentity (); // use identity from updated RouterInfo
			}	
		}	
		return true;
	}	
		
	std::shared_ptr<InboundTunnel> TunnelPool::GetLowestLatencyInboundTunnel(std::shared_ptr<InboundTunnel> exclude) const
	{
		std::shared_ptr<InboundTunnel> tun = nullptr;
		std::unique_lock<std::mutex> lock(m_InboundTunnelsMutex);
		int min = 1000000;
		for (const auto & itr : m_InboundTunnels) {
			if(!itr->LatencyIsKnown()) continue;
			auto l = itr->GetMeanLatency();
			if (l >= min) continue;
			tun = itr;
			if(tun == exclude) continue;
			min = l;
		}
		return tun;
	}

	std::shared_ptr<OutboundTunnel> TunnelPool::GetLowestLatencyOutboundTunnel(std::shared_ptr<OutboundTunnel> exclude) const
	{
		std::shared_ptr<OutboundTunnel> tun = nullptr;
		std::unique_lock<std::mutex> lock(m_OutboundTunnelsMutex);
		int min = 1000000;
		for (const auto & itr : m_OutboundTunnels) {
			if(!itr->LatencyIsKnown()) continue;
			auto l = itr->GetMeanLatency();
			if (l >= min) continue;
			tun = itr;
			if(tun == exclude) continue;
			min = l;
		}
		return tun;
	}
}
}
