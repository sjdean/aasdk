
#include <aap_proto/proto/service/phonestatus/PhoneStatusMessageId.pb.h>
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

  void PhoneStatusService::sendChannelOpenResponse(const proto::channel::ChannelOpenResponse &response,
                                                   SendPromise::Pointer promise) {
    auto message(std::make_shared<messenger::Message>(channelId_, messenger::EncryptionType::ENCRYPTED,
                                                      messenger::MessageType::CONTROL));
    message->insertPayload(
        messenger::MessageId(proto::channel::control::ControlMessageType::MESSAGE_CHANNEL_OPEN_RESPONSE).getData());
    message->insertPayload(response);

    this->send(std::move(message), std::move(promise));
  }

  void PhoneStatusService::messageHandler(messenger::Message::Pointer message,
                                          IPhoneStatusServiceEventHandler::Pointer eventHandler) {
    messenger::MessageId messageId(message->getPayload());
    common::DataConstBuffer payload(message->getPayload(), messageId.getSizeOf());

    AASDK_LOG(debug) << "[PhoneStatusService] Processing Message";

    switch (messageId.getId()) {
      case proto::channel::control::ControlMessageType::MESSAGE_CHANNEL_OPEN_REQUEST:
        this->handleChannelOpenRequest(payload, std::move(eventHandler));
        break;
      case proto::service::phonestatus::PhoneStatusMessageId::PHONE_STATUS:
      case proto::service::phonestatus::PhoneStatusMessageId::PHONE_STATUS_INPUT:
      default:
        AASDK_LOG(error) << "[PhoneStatusService] message not handled: " << messageId.getId();
        this->receive(std::move(eventHandler));
        break;
    }
  }

  void PhoneStatusService::handleChannelOpenRequest(const common::DataConstBuffer &payload,
                                                    IPhoneStatusServiceEventHandler::Pointer eventHandler) {
    AASDK_LOG(debug) << "[PhoneStatusService] Handling Channel Open";
    proto::channel::ChannelOpenRequest request;
    if (request.ParseFromArray(payload.cdata, payload.size)) {
      eventHandler->onChannelOpenRequest(request);
    } else {
      eventHandler->onChannelError(error::Error(error::ErrorCode::PARSE_PAYLOAD));
    }
  }
}


