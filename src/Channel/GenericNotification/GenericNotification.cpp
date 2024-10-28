

#include <aasdk/Channel/GenericNotification/IGenericNotificationServiceEventHandler.hpp>
#include <aasdk/Channel/GenericNotification/GenericNotificationService.hpp>
#include "aasdk/Common/Log.hpp"

/*
 * This is a Generic Notification channel - not much is known at this point.
 */


namespace aasdk::channel::genericnotification {

  GenericNotificationService::GenericNotificationService(boost::asio::io_service::strand &strand,
                                                         messenger::IMessenger::Pointer messenger)
      : Channel(strand, std::move(messenger), messenger::ChannelId::GENERIC_NOTIFICATION) {

  }

  void GenericNotificationService::receive(IGenericNotificationServiceEventHandler::Pointer eventHandler) {

    AASDK_LOG(debug) << "[GenericNotificationService] Receive";
    auto receivePromise = messenger::ReceivePromise::defer(strand_);
    receivePromise->then(
        std::bind(&GenericNotificationService::messageHandler, this->shared_from_this(), std::placeholders::_1,
                  eventHandler),
        std::bind(&IGenericNotificationServiceEventHandler::onChannelError, eventHandler, std::placeholders::_1));

    messenger_->enqueueReceive(channelId_, std::move(receivePromise));
  }

  void GenericNotificationService::sendChannelOpenResponse(const proto::channel::ChannelOpenResponse &response,
                                                           SendPromise::Pointer promise) {
    auto message(std::make_shared<messenger::Message>(channelId_, messenger::EncryptionType::ENCRYPTED,
                                                      messenger::MessageType::CONTROL));
    message->insertPayload(
        messenger::MessageId(proto::channel::control::ControlMessageType::MESSAGE_CHANNEL_OPEN_RESPONSE).getData());
    message->insertPayload(response);

    this->send(std::move(message), std::move(promise));
  }

  void GenericNotificationService::messageHandler(messenger::Message::Pointer message,
                                                  IGenericNotificationServiceEventHandler::Pointer eventHandler) {
    messenger::MessageId messageId(message->getPayload());
    common::DataConstBuffer payload(message->getPayload(), messageId.getSizeOf());

    AASDK_LOG(debug) << "[GenericNotificationService] Processing Message";

    switch (messageId.getId()) {
      case proto::channel::control::ControlMessageType::MESSAGE_CHANNEL_OPEN_REQUEST:
        this->handleChannelOpenRequest(payload, std::move(eventHandler));
        break;
      default:
        AASDK_LOG(error) << "[GenericNotificationService] message not handled: " << messageId.getId();
        this->receive(std::move(eventHandler));
        break;
    }
  }

  void GenericNotificationService::handleChannelOpenRequest(const common::DataConstBuffer &payload,
                                                            IGenericNotificationServiceEventHandler::Pointer eventHandler) {
    AASDK_LOG(debug) << "[GenericNotificationService] Handling Channel Open";
    proto::channel::ChannelOpenRequest request;
    if (request.ParseFromArray(payload.cdata, payload.size)) {
      eventHandler->onChannelOpenRequest(request);
    } else {
      eventHandler->onChannelError(error::Error(error::ErrorCode::PARSE_PAYLOAD));
    }
  }
}


