#include <aap_proto/proto/service/radio/RadioMessageId.pb.h>
#include <aasdk/Channel/Radio/IRadioServiceEventHandler.hpp>
#include <aasdk/Channel/Radio/RadioService.hpp>
#include "aasdk/Common/Log.hpp"

/*
 * This is a Radio channel that could be used for integration onto another Raspberry Pi/Other Device to integrate with third party systems or head units to help control the radio if necessary.
 */

namespace aasdk::channel::radio {

  RadioService::RadioService(boost::asio::io_service::strand &strand,
                             messenger::IMessenger::Pointer messenger)
      : Channel(strand, std::move(messenger), messenger::ChannelId::RADIO) {

  }

  void RadioService::receive(IRadioServiceEventHandler::Pointer eventHandler) {

    AASDK_LOG(debug) << "[RadioService] Receive";
    auto receivePromise = messenger::ReceivePromise::defer(strand_);
    receivePromise->then(
        std::bind(&RadioService::messageHandler, this->shared_from_this(), std::placeholders::_1,
                  eventHandler),
        std::bind(&IRadioServiceEventHandler::onChannelError, eventHandler, std::placeholders::_1));

    messenger_->enqueueReceive(channelId_, std::move(receivePromise));
  }

  void RadioService::sendChannelOpenResponse(const proto::channel::ChannelOpenResponse &response,
                                             SendPromise::Pointer promise) {
    auto message(std::make_shared<messenger::Message>(channelId_, messenger::EncryptionType::ENCRYPTED,
                                                      messenger::MessageType::CONTROL));
    message->insertPayload(
        messenger::MessageId(proto::channel::control::ControlMessageType::MESSAGE_CHANNEL_OPEN_RESPONSE).getData());
    message->insertPayload(response);

    this->send(std::move(message), std::move(promise));
  }

  void RadioService::messageHandler(messenger::Message::Pointer message,
                                    IRadioServiceEventHandler::Pointer eventHandler) {
    messenger::MessageId messageId(message->getPayload());
    common::DataConstBuffer payload(message->getPayload(), messageId.getSizeOf());

    AASDK_LOG(debug) << "[RadioService] Processing Message";

    switch (messageId.getId()) {
      case proto::channel::control::ControlMessageType::MESSAGE_CHANNEL_OPEN_REQUEST:
        this->handleChannelOpenRequest(payload, std::move(eventHandler));
        break;
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_ACTIVE_RADIO_NOTIFICATION:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_SELECT_ACTIVE_RADIO_REQUEST:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_STEP_CHANNEL_REQUEST:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_STEP_CHANNEL_RESPONSE:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_SEEK_STATION_REQUEST:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_SEEK_STATION_RESPONSE:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_SCAN_STATIONS_REQUEST:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_SCAN_STATIONS_RESPONSE:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_TUNE_TO_STATION_REQUEST:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_TUNE_TO_STATION_RESPONSE:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_GET_PROGRAM_LIST_REQUEST:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_GET_PROGRAM_LIST_RESPONSE:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_STATION_PRESETS_NOTIFICATION:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_CANCEL_OPERATIONS_REQUEST:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_CANCEL_OPERATIONS_RESPONSE:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_CONFIGURE_CHANNEL_SPACING_REQUEST:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_CONFIGURE_CHANNEL_SPACING_RESPONSE:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_RADIO_STATION_INFO_NOTIFICATION:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_MUTE_RADIO_REQUEST:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_MUTE_RADIO_RESPONSE:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_GET_TRAFFIC_UPDATE_REQUEST:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_GET_TRAFFIC_UPDATE_RESPONSE:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_RADIO_SOURCE_REQUEST:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_RADIO_SOURCE_RESPONSE:
      case proto::service::radio::_::RadioMessageId::RADIO_MESSAGE_STATE_NOTIFICATION:
      default:
        AASDK_LOG(error) << "[RadioService] message not handled: " << messageId.getId();
        this->receive(std::move(eventHandler));
        break;
    }
  }

  void RadioService::handleChannelOpenRequest(const common::DataConstBuffer &payload,
                                              IRadioServiceEventHandler::Pointer eventHandler) {
    AASDK_LOG(debug) << "[RadioService] Handling Channel Open";
    proto::channel::ChannelOpenRequest request;
    if (request.ParseFromArray(payload.cdata, payload.size)) {
      eventHandler->onChannelOpenRequest(request);
    } else {
      eventHandler->onChannelError(error::Error(error::ErrorCode::PARSE_PAYLOAD));
    }
  }
}


