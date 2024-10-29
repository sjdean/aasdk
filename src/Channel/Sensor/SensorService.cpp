/*
*  This file is part of aasdk library project.
*  Copyright (C) 2018 f1x.studio (Michal Szwaj)
*
*  aasdk is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 3 of the License, or
*  (at your option) any later version.

*  aasdk is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with aasdk. If not, see <http://www.gnu.org/licenses/>.
*/

#include <aap_protobuf/service/sensor/SensorChannelMessageId.pb.h>
#include <aasdk/Channel/Sensor/ISensorServiceEventHandler.hpp>
#include <aasdk/Channel/Sensor/SensorService.hpp>
#include "aasdk/Common/Log.hpp"


namespace aasdk::channel::sensor {

  SensorService::SensorService(boost::asio::io_service::strand &strand, messenger::IMessenger::Pointer messenger)
      : Channel(strand, std::move(messenger), messenger::ChannelId::SENSOR) {

  }

  void SensorService::receive(ISensorServiceEventHandler::Pointer eventHandler) {
    auto receivePromise = messenger::ReceivePromise::defer(strand_);
    receivePromise->then(
        std::bind(&SensorService::messageHandler, this->shared_from_this(), std::placeholders::_1, eventHandler),
        std::bind(&ISensorServiceEventHandler::onChannelError, eventHandler, std::placeholders::_1));

    messenger_->enqueueReceive(channelId_, std::move(receivePromise));
  }

  void SensorService::sendChannelOpenResponse(const aap_protobuf::channel::ChannelOpenResponse &response,
                                              SendPromise::Pointer promise) {
    auto message(std::make_shared<messenger::Message>(channelId_, messenger::EncryptionType::ENCRYPTED,
                                                      messenger::MessageType::CONTROL));
    message->insertPayload(
        messenger::MessageId(aap_protobuf::channel::control::ControlMessageType::MESSAGE_CHANNEL_OPEN_RESPONSE).getData());
    message->insertPayload(response);

    this->send(std::move(message), std::move(promise));
  }

  void
  SensorService::messageHandler(messenger::Message::Pointer message, ISensorServiceEventHandler::Pointer eventHandler) {
    messenger::MessageId messageId(message->getPayload());
    common::DataConstBuffer payload(message->getPayload(), messageId.getSizeOf());

    switch (messageId.getId()) {
      case aap_protobuf::service::sensor::SensorChannelMessageId::SENSOR_MESSAGE_REQUEST:
        this->handleSensorStartRequest(payload, std::move(eventHandler));
        break;
      case aap_protobuf::channel::control::ControlMessageType::MESSAGE_CHANNEL_OPEN_REQUEST:
        this->handleChannelOpenRequest(payload, std::move(eventHandler));
        break;
      default:
        AASDK_LOG(error) << "[SensorService] message not handled: " << messageId.getId();
        this->receive(std::move(eventHandler));
        break;
    }
  }

  void
  SensorService::sendSensorEventIndication(const aap_protobuf::service::sensor::message::SensorBatch &indication,
                                           SendPromise::Pointer promise) {
    auto message(std::make_shared<messenger::Message>(channelId_, messenger::EncryptionType::ENCRYPTED,
                                                      messenger::MessageType::SPECIFIC));
    message->insertPayload(
        messenger::MessageId(aap_protobuf::service::sensor::SensorChannelMessageId::SENSOR_MESSAGE_BATCH).getData());
    message->insertPayload(indication);

    this->send(std::move(message), std::move(promise));
  }

  void
  SensorService::sendSensorStartResponse(const aap_protobuf::service::sensor::message::SensorStartResponseMessage &response,
                                         SendPromise::Pointer promise) {
    auto message(std::make_shared<messenger::Message>(channelId_, messenger::EncryptionType::ENCRYPTED,
                                                      messenger::MessageType::SPECIFIC));
    message->insertPayload(
        messenger::MessageId(aap_protobuf::service::sensor::SensorChannelMessageId::SENSOR_MESSAGE_RESPONSE).getData());
    message->insertPayload(response);

    this->send(std::move(message), std::move(promise));
  }

  void SensorService::handleSensorStartRequest(const common::DataConstBuffer &payload,
                                               ISensorServiceEventHandler::Pointer eventHandler) {
    aap_protobuf::channel::sensor::event::SensorRequest request;
    if (request.ParseFromArray(payload.cdata, payload.size)) {
      eventHandler->onSensorStartRequest(request);
    } else {
      eventHandler->onChannelError(error::Error(error::ErrorCode::PARSE_PAYLOAD));
    }
  }

  void SensorService::handleChannelOpenRequest(const common::DataConstBuffer &payload,
                                               ISensorServiceEventHandler::Pointer eventHandler) {
    aap_protobuf::channel::ChannelOpenRequest request;
    if (request.ParseFromArray(payload.cdata, payload.size)) {
      eventHandler->onChannelOpenRequest(request);
    } else {
      eventHandler->onChannelError(error::Error(error::ErrorCode::PARSE_PAYLOAD));
    }
  }

}


