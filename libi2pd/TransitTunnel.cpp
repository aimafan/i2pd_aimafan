/*
* Copyright (c) 2013-2022, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include <string.h>
#include "I2PEndian.h"
#include "Log.h"
#include "RouterContext.h"
#include "I2NPProtocol.h"
#include "Tunnel.h"
#include "Transports.h"
#include "TransitTunnel.h"
#include "NetDb.hpp"

namespace i2p
{
namespace tunnel
{
	TransitTunnel::TransitTunnel (uint32_t receiveTunnelID,
		const i2p::data::IdentHash& nextIdent, uint32_t nextTunnelID,
		const i2p::crypto::AESKey& layerKey, const i2p::crypto::AESKey& ivKey):
			TunnelBase (receiveTunnelID, nextTunnelID, nextIdent),
			m_LayerKey (layerKey), m_IVKey (ivKey)
	{
	}

	void TransitTunnel::EncryptTunnelMsg (std::shared_ptr<const I2NPMessage> in, std::shared_ptr<I2NPMessage> out)
	{
		if (!m_Encryption)
		{
			m_Encryption.reset (new i2p::crypto::TunnelEncryption);
			m_Encryption->SetKeys (m_LayerKey, m_IVKey);
		}
		m_Encryption->Encrypt (in->GetPayload () + 4, out->GetPayload () + 4);
		i2p::transport::transports.UpdateTotalTransitTransmittedBytes (TUNNEL_DATA_MSG_SIZE);
	}

	TransitTunnelParticipant::~TransitTunnelParticipant ()
	{
	}

	void TransitTunnelParticipant::HandleTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage>&& tunnelMsg)
	{
		EncryptTunnelMsg (tunnelMsg, tunnelMsg);

		m_NumTransmittedBytes += tunnelMsg->GetLength ();
		htobe32buf (tunnelMsg->GetPayload (), GetNextTunnelID ());
		tunnelMsg->FillI2NPMessageHeader (eI2NPTunnelData);
		m_TunnelDataMsgs.push_back (tunnelMsg);
	}

	void TransitTunnelParticipant::FlushTunnelDataMsgs ()
	{
		if (!m_TunnelDataMsgs.empty ())
		{
			auto num = m_TunnelDataMsgs.size ();
			if (num > 1)
				LogPrint (eLogDebug, "TransitTunnel: ", GetTunnelID (), "->", GetNextTunnelID (), " ", num);
			i2p::transport::transports.SendMessages (GetNextIdentHash (), m_TunnelDataMsgs);
			m_TunnelDataMsgs.clear ();
		}
	}

	void TransitTunnel::SendTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage> msg)
	{
		LogPrint (eLogError, "TransitTunnel: We are not a gateway for ", GetTunnelID ());
	}

	void TransitTunnel::HandleTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage>&& tunnelMsg)
	{
		LogPrint (eLogError, "TransitTunnel: Incoming tunnel message is not supported ", GetTunnelID ());
	}

	void TransitTunnelGateway::SendTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage> msg)
	{
		TunnelMessageBlock block;
		block.deliveryType = eDeliveryTypeLocal;
		block.data = msg;
		std::unique_lock<std::mutex> l(m_SendMutex);
		m_Gateway.PutTunnelDataMsg (block);
	}

	void TransitTunnelGateway::FlushTunnelDataMsgs ()
	{
		std::unique_lock<std::mutex> l(m_SendMutex);
		m_Gateway.SendBuffer ();
	}

	void TransitTunnelEndpoint::HandleTunnelDataMsg (std::shared_ptr<i2p::I2NPMessage>&& tunnelMsg)
	{
		auto newMsg = CreateEmptyTunnelDataMsg (true);
		EncryptTunnelMsg (tunnelMsg, newMsg);

		LogPrint (eLogDebug, "TransitTunnel: handle msg for endpoint ", GetTunnelID ());
		m_Endpoint.HandleDecryptedTunnelDataMsg (newMsg);
	}

	// 创建中继节点
	std::shared_ptr<TransitTunnel> CreateTransitTunnel (std::string host, std::string port, uint32_t receiveTunnelID,
		const i2p::data::IdentHash& nextIdent, uint32_t nextTunnelID,
		const i2p::crypto::AESKey& layerKey, const i2p::crypto::AESKey& ivKey,
		bool isGateway, bool isEndpoint)
	{
		std::string ntcp2_ipv4, ntcp2_port;
		auto routerinfo = i2p::data::netdb.FindRouter(nextIdent);
		std::string ident_hash = nextIdent.ToBase64();
		if(routerinfo){
			if(routerinfo->GetNTCP2V4Address() ){
				if( routerinfo->GetNTCP2V4Address()->host.to_string() != "0.0.0.0"){
					ntcp2_ipv4 = routerinfo->GetNTCP2V4Address()->host.to_string();
					ntcp2_port = std::to_string(routerinfo->GetNTCP2V4Address()->port);
				}else{
					ntcp2_ipv4 = " ";
					ntcp2_port = "0";
				}
			}
		}else{
			ntcp2_ipv4 = " ";
			ntcp2_port = "0";
		}
		// 日志结构：身份, 上一跳节点IP, 上一跳节点Port, 下一跳节点ident, 下一跳节点tunnel id, 下一跳节点ip, 下一跳节点port
		std::string weizhi;
		std::string p_ip;
		std::string p_port;
		std::string n_ip;
		std::string n_port;
		std::string n_ident;
		std::string n_tunnel_id;
		std::string p_ident;
		std::string	p_tunnel_id;
		if (isGateway){
			weizhi = "gateway";
			p_ident = " ";
			p_tunnel_id = " ";
			p_ip = host;
			p_port = port;
			n_ip = ntcp2_ipv4;
			n_port = ntcp2_port;
			n_ident = nextIdent.ToBase64();
			n_tunnel_id = std::to_string(nextTunnelID);
		}
		else if (isEndpoint){
			weizhi = "endpoint";
			p_ident = " ";
			p_tunnel_id = " ";
			p_ip = host;
			p_port = port;
			n_ip = " ";
			n_port = " ";
			n_ident = " ";
			n_tunnel_id = " ";
		}
		else {
			weizhi = "participant";
			p_ident = " ";
			p_tunnel_id = " ";
			p_ip = host;
			p_port = port;
			n_ip = ntcp2_ipv4;
			n_port = ntcp2_port;
			n_ident = nextIdent.ToBase64();
			n_tunnel_id = std::to_string(nextTunnelID);
		}

		// 如果是endpoint，那么nexttunnelid和nexttunnelhash应该都是创建者的某个入站隧道网关的信息


		if (isEndpoint)
		{
			LogPrint (eLogDebug, "TransitTunnel: endpoint ", receiveTunnelID, " created");
			return std::make_shared<TransitTunnelEndpoint> (receiveTunnelID, nextIdent, nextTunnelID, layerKey, ivKey);
		}
		else if (isGateway)
		{
			LogPrint (eLogInfo, "TransitTunnel: gateway ", receiveTunnelID, " created");
			return std::make_shared<TransitTunnelGateway> (receiveTunnelID, nextIdent, nextTunnelID, layerKey, ivKey);
		}
		else
		{
			LogPrint (eLogDebug, "TransitTunnel: ", receiveTunnelID, "->", nextTunnelID, " created");
			return std::make_shared<TransitTunnelParticipant> (receiveTunnelID, nextIdent, nextTunnelID, layerKey, ivKey);
		}
	}
}
}
