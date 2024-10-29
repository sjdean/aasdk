#include <aasdk/Channel/VendorExtension/IVendorExtensionServiceEventHandler.hpp>
#include <aasdk/Channel/VendorExtension/VendorExtensionService.hpp>
#include "aasdk/Common/Log.hpp"

/*
 * This is a Vendor Extension channel to link to a known Vendor App on the Mobile Phone.
 */

namespace aasdk::channel::vendorextension {

  VendorExtensionService::VendorExtensionService(boost::asio::io_service::strand &strand,
                                                 messenger::IMessenger::Pointer messenger)
      : Channel(strand, std::move(messenger), messenger::ChannelId::VENDOR_EXTENSION) {

  }

  void VendorExtensionService::receive(IVendorExtensionServiceEventHandler::Pointer eventHandler) {

    AASDK_LOG(debug) << "[VendorExtensionService] Receive";
    auto receivePromise = messenger::ReceivePromise::defer(strand_);
    receivePromise->then(
        std::bind(&VendorExtensionService::messageHandler, this->shared_from_this(), std::placeholders::_1,
                  eventHandler),
        std::bind(&IVendorExtensionServiceEventHandler::onChannelError, eventHandler, std::placeholders::_1));

    messenger_->enqueueReceive(channelId_, std::move(receivePromise));
  }

  void VendorExtensionService::sendChannelOpenResponse(const aap_protobuf::channel::ChannelOpenResponse &response,
                                                       SendPromise::Pointer promise) {
    auto message(std::make_shared<messenger::Message>(channelId_, messenger::EncryptionType::ENCRYPTED,
                                                      messenger::MessageType::CONTROL));
    message->insertPayload(
        messenger::MessageId(aap_protobuf::channel::control::ControlMessageType::MESSAGE_CHANNEL_OPEN_RESPONSE).getData());
    message->insertPayload(response);

    this->send(std::move(message), std::move(promise));
  }

  void VendorExtensionService::messageHandler(messenger::Message::Pointer message,
                                              IVendorExtensionServiceEventHandler::Pointer eventHandler) {
    messenger::MessageId messageId(message->getPayload());
    common::DataConstBuffer payload(message->getPayload(), messageId.getSizeOf());

    AASDK_LOG(debug) << "[VendorExtensionService] Processing Message";

    switch (messageId.getId()) {
      case aap_protobuf::channel::control::ControlMessageType::MESSAGE_CHANNEL_OPEN_REQUEST:
        this->handleChannelOpenRequest(payload, std::move(eventHandler));
        break;
      default:
        AASDK_LOG(error) << "[VendorExtensionService] message not handled: " << messageId.getId();
        this->receive(std::move(eventHandler));
        break;
    }
  }

  void VendorExtensionService::handleChannelOpenRequest(const common::DataConstBuffer &payload,
                                                        IVendorExtensionServiceEventHandler::Pointer eventHandler) {
    AASDK_LOG(debug) << "[VendorExtensionService] Handling Channel Open";
    aap_protobuf::channel::ChannelOpenRequest request;
    if (request.ParseFromArray(payload.cdata, payload.size)) {
      eventHandler->onChannelOpenRequest(request);
    } else {
      eventHandler->onChannelError(error::Error(error::ErrorCode::PARSE_PAYLOAD));
    }
  }
}


