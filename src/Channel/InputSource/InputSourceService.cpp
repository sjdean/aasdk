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

#include <aap_proto/proto/service/input/message/InputChannelMessageId.pb.h>
#include "aasdk/Channel/InputSource/InputSourceService.hpp"
#include "aasdk/Channel/InputSource/IInputSourceServiceEventHandler.hpp"
#include "aasdk/Common/Log.hpp"


namespace aasdk::channel::inputsource {

  InputSourceService::InputSourceService(boost::asio::io_service::strand &strand,
                                         messenger::IMessenger::Pointer messenger)
      : Channel(strand, std::move(messenger), messenger::ChannelId::INPUT_SOURCE) {

  }

  void InputSourceService::receive(IInputSourceServiceEventHandler::Pointer eventHandler) {
    auto receivePromise = messenger::ReceivePromise::defer(strand_);
    receivePromise->then(
        std::bind(&InputSourceService::messageHandler, this->shared_from_this(), std::placeholders::_1, eventHandler),
        std::bind(&IInputSourceServiceEventHandler::onChannelError, eventHandler, std::placeholders::_1));

    messenger_->enqueueReceive(channelId_, std::move(receivePromise));
  }

  void
  InputSourceService::sendInputEventIndication(const proto::service::input::message::InputEventIndication &indication,
                                               SendPromise::Pointer promise) {
    auto message(std::make_shared<messenger::Message>(channelId_, messenger::EncryptionType::ENCRYPTED,
                                                      messenger::MessageType::SPECIFIC));
    message->insertPayload(messenger::MessageId(
        proto::service::input::message::InputChannelMessageId::INPUT_MESSAGE_INPUT_REPORT).getData());
    message->insertPayload(indication);

    this->send(std::move(message), std::move(promise));
  }

  void InputSourceService::sendBindingResponse(const proto::service::media::sink::message::BindingResponse &response,
                                               SendPromise::Pointer promise) {
    auto message(std::make_shared<messenger::Message>(channelId_, messenger::EncryptionType::ENCRYPTED,
                                                      messenger::MessageType::SPECIFIC));
    message->insertPayload(messenger::MessageId(
        proto::service::input::message::InputChannelMessageId::INPUT_MESSAGE_KEY_BINDING_RESPONSE).getData());
    message->insertPayload(response);

    this->send(std::move(message), std::move(promise));
  }

  void InputSourceService::sendChannelOpenResponse(const proto::channel::ChannelOpenResponse &response,
                                                   SendPromise::Pointer promise) {
    auto message(std::make_shared<messenger::Message>(channelId_, messenger::EncryptionType::ENCRYPTED,
                                                      messenger::MessageType::CONTROL));
    message->insertPayload(
        messenger::MessageId(proto::channel::control::ControlMessageType::MESSAGE_CHANNEL_OPEN_RESPONSE).getData());
    message->insertPayload(response);

    this->send(std::move(message), std::move(promise));
  }

  void InputSourceService::messageHandler(messenger::Message::Pointer message,
                                          IInputSourceServiceEventHandler::Pointer eventHandler) {
    messenger::MessageId messageId(message->getPayload());
    common::DataConstBuffer payload(message->getPayload(), messageId.getSizeOf());

    switch (messageId.getId()) {
      case proto::service::input::message::InputChannelMessageId::INPUT_MESSAGE_KEY_BINDING_REQUEST:
        this->handleBindingRequest(payload, std::move(eventHandler));
        break;
      case proto::channel::control::ControlMessageType::MESSAGE_CHANNEL_OPEN_REQUEST:
        this->handleChannelOpenRequest(payload, std::move(eventHandler));
        break;
      default:
        AASDK_LOG(error) << "[InputSourceService] message not handled: " << messageId.getId();
        this->receive(std::move(eventHandler));
        break;
    }
  }

  void InputSourceService::handleBindingRequest(const common::DataConstBuffer &payload,
                                                IInputSourceServiceEventHandler::Pointer eventHandler) {
    proto::channel::input::event::BindingRequest request;
    if (request.ParseFromArray(payload.cdata, payload.size)) {
      eventHandler->onBindingRequest(request);
    } else {
      eventHandler->onChannelError(error::Error(error::ErrorCode::PARSE_PAYLOAD));
    }
  }

  void InputSourceService::handleChannelOpenRequest(const common::DataConstBuffer &payload,
                                                    IInputSourceServiceEventHandler::Pointer eventHandler) {
    proto::channel::ChannelOpenRequest request;
    if (request.ParseFromArray(payload.cdata, payload.size)) {
      eventHandler->onChannelOpenRequest(request);
    } else {
      eventHandler->onChannelError(error::Error(error::ErrorCode::PARSE_PAYLOAD));
    }
  }

}


