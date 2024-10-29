
#include <aap_protobuf/service/phonestatus/PhoneStatusMessageId.pb.h>
#include <aasdk/Channel/PhoneStatus/IPhoneStatusServiceEventHandler.hpp>
#include <aasdk/Channel/PhoneStatus/PhoneStatusService.hpp>
#include "aasdk/Common/Log.hpp"

/*
 * This is a Phone Status channel that could be used for integration onto another Raspberry Pi/Other Device to add an additional screen for notification and control purposes.
 */

namespace aasdk::channel::phonestatus {

  PhoneStatusService::PhoneStatusService(boost::asio::io_service::strand &strand,
                                         messenger::IMessenger::Pointer messenger)
      : Channel(strand, std::move(messenger), messenger::ChannelId::PHONE_STATUS) {

  }

  void PhoneStatusService::receive(IPhoneStatusServiceEventHandler::Pointer eventHandler) {

    AASDK_LOG(debug) << "[PhoneStatusService] Receive";
    auto receivePromise = messenger::ReceivePromise::defer(strand_);
    receivePromise->then(
        std::bind(&PhoneStatusService::messageHandler, this->shared_from_this(), std::placeholders::_1,
                  eventHandler),
        std::bind(&IPhoneStatusServiceEventHandler::onChannelError, eventHandler, std::placeholders::_1));

    messenger_->enqueueReceive(channelId_, std::move(receivePromise));
  }

  void PhoneStatusService::sendChannelOpenResponse(const aap_protobuf::channel::ChannelOpenResponse &response,
                                                   SendPromise::Pointer promise) {
    auto message(std::make_shared<messenger::Message>(channelId_, messenger::EncryptionType::ENCRYPTED,
                                                      messenger::MessageType::CONTROL));
    message->insertPayload(
        messenger::MessageId(aap_protobuf::channel::control::ControlMessageType::MESSAGE_CHANNEL_OPEN_RESPONSE).getData());
    message->insertPayload(response);

    this->send(std::move(message), std::move(promise));
  }

  void PhoneStatusService::messageHandler(messenger::Message::Pointer message,
                                          IPhoneStatusServiceEventHandler::Pointer eventHandler) {
    messenger::MessageId messageId(message->getPayload());
    common::DataConstBuffer payload(message->getPayload(), messageId.getSizeOf());

    AASDK_LOG(debug) << "[PhoneStatusService] Processing Message";

    switch (messageId.getId()) {
      case aap_protobuf::channel::control::ControlMessageType::MESSAGE_CHANNEL_OPEN_REQUEST:
        this->handleChannelOpenRequest(payload, std::move(eventHandler));
        break;
      case aap_protobuf::service::phonestatus::PhoneStatusMessageId::PHONE_STATUS:
      case aap_protobuf::service::phonestatus::PhoneStatusMessageId::PHONE_STATUS_INPUT:
      default:
        AASDK_LOG(error) << "[PhoneStatusService] message not handled: " << messageId.getId();
        this->receive(std::move(eventHandler));
        break;
    }
  }

  void PhoneStatusService::handleChannelOpenRequest(const common::DataConstBuffer &payload,
                                                    IPhoneStatusServiceEventHandler::Pointer eventHandler) {
    AASDK_LOG(debug) << "[PhoneStatusService] Handling Channel Open";
    aap_protobuf::channel::ChannelOpenRequest request;
    if (request.ParseFromArray(payload.cdata, payload.size)) {
      eventHandler->onChannelOpenRequest(request);
    } else {
      eventHandler->onChannelError(error::Error(error::ErrorCode::PARSE_PAYLOAD));
    }
  }
}


