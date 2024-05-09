#ifndef KAFKAPRODUCER_H
#define KAFKAPRODUCER_H


#pragma once
#include <string>
#include <iostream>
#include <librdkafka/rdkafkacpp.h>
#include "Config.h"


class KafkaProducer
{
public:
	/**
	* @brief KafkaProducer
	* @param brokers 服务器地址
	* @param topic 
	* @param partition 要发送消息的分区
	*/
	KafkaProducer();
	void KafkaProducer_connect(const std::string& brokers, const std::string& topic, int partition);
	/**
	* @brief push Message to Kafka
	* @param str, message data
	*/
	void pushMessage(const std::string& str);
	~KafkaProducer();


private:
	std::string m_brokers;			// Broker列表，多个使用逗号分隔
	std::string m_topicStr;			// Topic名称
	int m_partition;				// 分区


	RdKafka::Conf* m_config;        // Kafka Conf对象
	RdKafka::Conf* m_topicConfig;   // Topic Conf对象
	RdKafka::Topic* m_topic;		// Topic对象
	RdKafka::Producer* m_producer;	// Producer对象


	/*只要看到Cb 结尾的类，要继承它然后实现对应的回调函数*/
	RdKafka::DeliveryReportCb* m_dr_cb;
	RdKafka::EventCb* m_event_cb;
	RdKafka::PartitionerCb* m_partitioner_cb;
};


#endif