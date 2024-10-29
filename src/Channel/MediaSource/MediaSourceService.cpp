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

#include <aap_protobuf/service/media/shared/message/MediaMessageId.pb.h>
#include "aasdk/Messenger/Timestamp.hpp"
#include "aasdk/Channel/MediaSource/IMediaSourceServiceEventHandler.hpp"
#include "aasdk/Channel/MediaSource/MediaSourceService.hpp"
#include "aasdk/Common/Log.hpp"


namespace aasdk::channel::mediasource {

  MediaSourceService::MediaSourceService(boost::asio::io_service::strand &strand,
                                         messenger::IMessenger::Pointer messenger,
                                         messenger::ChannelId channelId)
      : Channel(strand, std::move(messenger), messenger::ChannelId::MEDIA_SOURCE), channelId_(channelId) {

  }

  void MediaSourceService::receive(IMediaSourceServiceEventHandler::Pointer eventHandler) {
    auto receivePromise = messenger::ReceivePromise::defer(strand_);
    receivePromise->then(
        std::bind(&MediaSourceService::messageHandler, this->shared_from_this(), std::placeholders::_1, eventHandler),
        std::bind(&IMediaSourceServiceEventHandler::onChannelError, eventHandler, std::placeholders::_1));

    messenger_->enqueueReceive(channelId_, std::move(receivePromise));
  }

  void MediaSourceService::sendChannelOpenResponse(const aap_protobuf::channel::ChannelOpenResponse &response,
                                                   SendPromise::Pointer promise) {
    auto message(std::make_shared<messenger::Message>(channelId_, messenger::EncryptionType::ENCRYPTED,
                                                      messenger::MessageType::CONTROL));
    message->insertPayload(
        messenger::MessageId(aap_protobuf::channel::control::ControlMessageType::MESSAGE_CHANNEL_OPEN_RESPONSE).getData());
    message->insertPayload(response);

    this->send(std::move(message), std::move(promise));
  }

/*
  void MediaSourceService::sendChannelSetupResponse(
      const aap_protobuf::service::media::source::message::MediaSinkChannelSetupResponse &response,
      SendPromise::Pointer promise) {
    auto message(std::make_shared<messenger::Message>(channelId_, messenger::EncryptionType::ENCRYPTED,
                                                      messenger::MessageType::SPECIFIC));
    message->insertPayload(
        messenger::MessageId(aap_protobuf::service::media::shared::message::MediaMessageId::MEDIA_MESSAGE_SETUP).getData());
    message->insertPayload(response);

    this->send(std::move(message), std::move(promise));
  }*/

  void MediaSourceService::messageHandler(messenger::Message::Pointer message,
                                          IMediaSourceServiceEventHandler::Pointer eventHandler) {
    messenger::MessageId messageId(message->getPayload());
    common::DataConstBuffer payload(message->getPayload(), messageId.getSizeOf());

    switch (messageId.getId()) {
      case aap_protobuf::channel::control::ControlMessageType::MESSAGE_CHANNEL_OPEN_REQUEST:
        this->handleChannelOpenRequest(payload, std::move(eventHandler));
        break;
      case aap_protobuf::service::media::shared::message::MediaMessageId::MEDIA_MESSAGE_SETUP:
        this->handleAVChannelSetupRequest(payload, std::move(eventHandler));
        break;
      case aap_protobuf::service::media::shared::message::MediaMessageId::MEDIA_MESSAGE_MICROPHONE_REQUEST:
        this->handleAVInputOpenRequest(payload, std::move(eventHandler));
        break;
      case aap_protobuf::service::media::shared::message::MediaMessageId::MEDIA_MESSAGE_ACK:
        this->handleAVMediaAckIndication(payload, std::move(eventHandler));
        break;
      default:
        AASDK_LOG(error) << "[AVInputSourceService] message not handled: " << messageId.getId();
        this->receive(std::move(eventHandler));
        break;
    }
  }

  void MediaSourceService::sendAVInputOpenResponse(
      const aap_protobuf::service::media::source::message::MicrophoneResponse &response, SendPromise::Pointer promise) {
    auto message(std::make_shared<messenger::Message>(channelId_, messenger::EncryptionType::ENCRYPTED,
                                                      messenger::MessageType::SPECIFIC));

    message->insertPayload(messenger::MessageId(
        aap_protobuf::service::media::shared::message::MediaMessageId::MEDIA_MESSAGE_MICROPHONE_REQUEST).getData());
    message->insertPayload(response);

    this->send(std::move(message), std::move(promise));
  }

  void MediaSourceService::sendAVMediaWithTimestampIndication(messenger::Timestamp::ValueType timestamp,
                                                              const common::Data &data, SendPromise::Pointer promise) {
    auto message(std::make_shared<messenger::Message>(channelId_, messenger::EncryptionType::ENCRYPTED,
                                                      messenger::MessageType::SPECIFIC));
    message->insertPayload(messenger::MessageId(
        aap_protobuf::service::media::shared::message::MediaMessageId::MEDIA_MESSAGE_CODEC_CONFIG).getData());

    auto timestampData = messenger::Timestamp(timestamp).getData();
    message->insertPayload(std::move(timestampData));
    message->insertPayload(data);

    this->send(std::move(message), std::move(promise));
  }

  void MediaSourceService::handleAVChannelSetupRequest(const common::DataConstBuffer &payload,
                                                       IMediaSourceServiceEventHandler::Pointer eventHandler) {
    aap_protobuf::channel::media::event::Setup request;
    if (request.ParseFromArray(payload.cdata, payload.size)) {
      eventHandler->onAVChannelSetupRequest(request);
    } else {
      eventHandler->onChannelError(error::Error(error::ErrorCode::PARSE_PAYLOAD));
    }
  }

  void MediaSourceService::handleAVInputOpenRequest(const common::DataConstBuffer &payload,
                                                    IMediaSourceServiceEventHandler::Pointer eventHandler) {
    aap_protobuf::service::media::source::message::MicrophoneRequest request;
    if (request.ParseFromArray(payload.cdata, payload.size)) {
      eventHandler->onAVInputOpenRequest(request);
    } else {
      eventHandler->onChannelError(error::Error(error::ErrorCode::PARSE_PAYLOAD));
    }
  }

  void MediaSourceService::handleAVMediaAckIndication(const common::DataConstBuffer &payload,
                                                      IMediaSourceServiceEventHandler::Pointer eventHandler) {
    aap_protobuf::service::media::source::message::MediaSourceMediaAckIndication indication;
    if (indication.ParseFromArray(payload.cdata, payload.size)) {
      eventHandler->onAVMediaAckIndication(indication);
    } else {
      eventHandler->onChannelError(error::Error(error::ErrorCode::PARSE_PAYLOAD));
    }
  }

  void MediaSourceService::handleChannelOpenRequest(const common::DataConstBuffer &payload,
                                                    IMediaSourceServiceEventHandler::Pointer eventHandler) {
    aap_protobuf::channel::ChannelOpenRequest request;
    if (request.ParseFromArray(payload.cdata, payload.size)) {
      eventHandler->onChannelOpenRequest(request);
    } else {
      eventHandler->onChannelError(error::Error(error::ErrorCode::PARSE_PAYLOAD));
    }
  }

}


