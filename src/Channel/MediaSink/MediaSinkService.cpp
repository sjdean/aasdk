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

#include "proto/service/media/shared/enum/MediaMessageId.pb.h"
#include <aasdk/channel/mediasink/IMediaSinkServiceEventHandler.hpp>
#include <aasdk/channel/mediasink/MediaSinkService.hpp>
#include "aasdk/Common/Log.hpp"


namespace aasdk::channel::mediasink {

  MediaSinkService::MediaSinkService(boost::asio::io_service::strand &strand,
                                     messenger::IMessenger::Pointer messenger,
                                     messenger::ChannelId channelId)
      : Channel(strand, std::move(messenger), messenger::ChannelId::MEDIA_SINK) {

  }

  void MediaSinkService::receive(IMediaSinkServiceEventHandler::Pointer eventHandler) {
    auto receivePromise = messenger::ReceivePromise::defer(strand_);
    receivePromise->then(
        std::bind(&MediaSinkService::messageHandler, this->shared_from_this(), std::placeholders::_1, eventHandler),
        std::bind(&IMediaSinkServiceEventHandler::onChannelError, eventHandler, std::placeholders::_1));

    messenger_->enqueueReceive(channelId_, std::move(receivePromise));
  }

  void MediaSinkService::sendChannelOpenResponse(const proto::channel::ChannelOpenResponse &response,
                                                 SendPromise::Pointer promise) {
    auto message(std::make_shared<messenger::Message>(channelId_, messenger::EncryptionType::ENCRYPTED,
                                                      messenger::MessageType::CONTROL));
    message->insertPayload(messenger::MessageId(proto::channel::control::MESSAGE_CHANNEL_OPEN_RESPONSE).getData());
    message->insertPayload(response);

    this->send(std::move(message), std::move(promise));
  }

  void MediaSinkService::sendChannelSetupResponse(
      const proto::service::media::sink::message::MediaSinkChannelSetupResponse &response,
      SendPromise::Pointer promise) {
    auto message(std::make_shared<messenger::Message>(channelId_, messenger::EncryptionType::ENCRYPTED,
                                                      messenger::MessageType::SPECIFIC));
    message->insertPayload(
        messenger::MessageId(proto::service::media::shared::enum_::MediaSinkMessage::MEDIA_MESSAGE_CONFIG).getData());
    message->insertPayload(response);

    this->send(std::move(message), std::move(promise));
  }

  void MediaSinkService::sendMediaAckIndication(
      const proto::service::media::source::message::MediaSourceMediaAckIndication &indication,
      SendPromise::Pointer promise) {
    auto message(std::make_shared<messenger::Message>(channelId_, messenger::EncryptionType::ENCRYPTED,
                                                      messenger::MessageType::SPECIFIC));
    message->insertPayload(
        messenger::MessageId(proto::service::media::shared::enum_::MediaSinkMessage::MEDIA_MESSAGE_ACK).getData());
    message->insertPayload(indication);

    this->send(std::move(message), std::move(promise));
  }

  void MediaSinkService::messageHandler(messenger::Message::Pointer message,
                                        IMediaSinkServiceEventHandler::Pointer eventHandler) {
    messenger::MessageId messageId(message->getPayload());
    common::DataConstBuffer payload(message->getPayload(), messageId.getSizeOf());

    switch (messageId.getId()) {
      case proto::service::media::shared::message::MediaMessageId::MEDIA_MESSAGE_SETUP:
        this->handleChannelSetupRequest(payload, std::move(eventHandler));
        break;
      case proto::service::media::shared::message::MediaMessageId::MEDIA_MESSAGE_START:
        this->handleStartIndication(payload, std::move(eventHandler));
        break;
      case proto::service::media::shared::message::MediaMessageId::MEDIA_MESSAGE_STOP:
        this->handleStopIndication(payload, std::move(eventHandler));
        break;
      case proto::service::media::shared::message::MediaMessageId::MEDIA_MESSAGE_DATA:
        this->handleMediaWithTimestampIndication(payload, std::move(eventHandler));
        break;
      case proto::service::media::shared::message::MediaMessageId::MEDIA_MESSAGE_CODEC_CONFIG:
        eventHandler->onMediaIndication(payload);
        break;
      case proto::channel::control::MESSAGE_CHANNEL_OPEN_REQUEST:
        this->handleChannelOpenRequest(payload, std::move(eventHandler));
        break;
      default:
        AASDK_LOG(error) << "[MediaSinkService] message not handled: " << messageId.getId();
        this->receive(std::move(eventHandler));
        break;
    }
  }

  void MediaSinkService::handleChannelSetupRequest(const common::DataConstBuffer &payload,
                                                   IMediaSinkServiceEventHandler::Pointer eventHandler) {
    proto::channel::media::event::Setup request;
    if (request.ParseFromArray(payload.cdata, payload.size)) {
      eventHandler->onSetup(request);
    } else {
      eventHandler->onChannelError(error::Error(error::ErrorCode::PARSE_PAYLOAD));
    }
  }

  void MediaSinkService::handleStartIndication(const common::DataConstBuffer &payload,
                                               IMediaSinkServiceEventHandler::Pointer eventHandler) {
    proto::channel::media::event::Start indication;
    if (indication.ParseFromArray(payload.cdata, payload.size)) {
      eventHandler->onStart(indication);
    } else {
      eventHandler->onChannelError(error::Error(error::ErrorCode::PARSE_PAYLOAD));
    }
  }

  void MediaSinkService::handleStopIndication(const common::DataConstBuffer &payload,
                                              IMediaSinkServiceEventHandler::Pointer eventHandler) {
    proto::channel::media::event::Stop indication;
    if (indication.ParseFromArray(payload.cdata, payload.size)) {
      eventHandler->onStop(indication);
    } else {
      eventHandler->onChannelError(error::Error(error::ErrorCode::PARSE_PAYLOAD));
    }
  }

  void MediaSinkService::handleChannelOpenRequest(const common::DataConstBuffer &payload,
                                                  IMediaSinkServiceEventHandler::Pointer eventHandler) {
    proto::channel::ChannelOpenRequest request;
    if (request.ParseFromArray(payload.cdata, payload.size)) {
      eventHandler->onChannelOpenRequest(request);
    } else {
      eventHandler->onChannelError(error::Error(error::ErrorCode::PARSE_PAYLOAD));
    }
  }

  void MediaSinkService::handleMediaWithTimestampIndication(const common::DataConstBuffer &payload,
                                                            IMediaSinkServiceEventHandler::Pointer eventHandler) {
    if (payload.size >= sizeof(messenger::Timestamp::ValueType)) {
      messenger::Timestamp timestamp(payload);
      eventHandler->onMediaWithTimestampIndication(timestamp.getValue(),
                                                     common::DataConstBuffer(payload.cdata, payload.size,
                                                                             sizeof(messenger::Timestamp::ValueType)));
    } else {
      eventHandler->onChannelError(error::Error(error::ErrorCode::PARSE_PAYLOAD));
    }
  }

}


