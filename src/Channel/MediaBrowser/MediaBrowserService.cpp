
#include <aap_protobuf/service/mediabrowser/MediaBrowserMessageId.pb.h>
#include <aasdk/Channel/MediaBrowser/IMediaBrowserServiceEventHandler.hpp>
#include <aasdk/Channel/MediaBrowser/MediaBrowserService.hpp>
#include "aasdk/Common/Log.hpp"

/*
 * This is a Media Browser channel that could be used for integration onto another Raspberry Pi/Other Device to add an additional screen for notification and control purposes - such as updating the LCD screen on older Vauxhall/Opel/GM Cars
 */

namespace aasdk::channel::mediabrowser {

  MediaBrowserService::MediaBrowserService(boost::asio::io_service::strand &strand,
                                           messenger::IMessenger::Pointer messenger)
      : Channel(strand, std::move(messenger), messenger::ChannelId::MEDIA_BROWSER) {

  }

  void MediaBrowserService::receive(IMediaBrowserServiceEventHandler::Pointer eventHandler) {

    AASDK_LOG(debug) << "[MediaBrowserService] Receive";
    auto receivePromise = messenger::ReceivePromise::defer(strand_);
    receivePromise->then(
        std::bind(&MediaBrowserService::messageHandler, this->shared_from_this(), std::placeholders::_1,
                  eventHandler),
        std::bind(&IMediaBrowserServiceEventHandler::onChannelError, eventHandler, std::placeholders::_1));

    messenger_->enqueueReceive(channelId_, std::move(receivePromise));
  }

  void MediaBrowserService::sendChannelOpenResponse(const aap_protobuf::channel::ChannelOpenResponse &response,
                                                    SendPromise::Pointer promise) {
    auto message(std::make_shared<messenger::Message>(channelId_, messenger::EncryptionType::ENCRYPTED,
                                                      messenger::MessageType::CONTROL));
    message->insertPayload(
        messenger::MessageId(aap_protobuf::channel::control::ControlMessageType::MESSAGE_CHANNEL_OPEN_RESPONSE).getData());
    message->insertPayload(response);

    this->send(std::move(message), std::move(promise));
  }

  void MediaBrowserService::messageHandler(messenger::Message::Pointer message,
                                           IMediaBrowserServiceEventHandler::Pointer eventHandler) {
    messenger::MessageId messageId(message->getPayload());
    common::DataConstBuffer payload(message->getPayload(), messageId.getSizeOf());

    AASDK_LOG(debug) << "[MediaBrowserService] Processing Message";

    switch (messageId.getId()) {
      case aap_protobuf::channel::control::ControlMessageType::MESSAGE_CHANNEL_OPEN_REQUEST:
        this->handleChannelOpenRequest(payload, std::move(eventHandler));
      case aap_protobuf::service::mediabrowser::MEDIA_ROOT_NODE:
      case aap_protobuf::service::mediabrowser::MEDIA_SOURCE_NODE:
      case aap_protobuf::service::mediabrowser::MEDIA_LIST_NODE:
      case aap_protobuf::service::mediabrowser::MEDIA_SONG_NODE:
      case aap_protobuf::service::mediabrowser::MEDIA_GET_NODE:
      case aap_protobuf::service::mediabrowser::MEDIA_BROWSE_INPUT:
      default:
        AASDK_LOG(error) << "[MediaBrowserService] message not handled: " << messageId.getId();
        this->receive(std::move(eventHandler));
        break;
    }
  }

  void MediaBrowserService::handleChannelOpenRequest(const common::DataConstBuffer &payload,
                                                     IMediaBrowserServiceEventHandler::Pointer eventHandler) {
    AASDK_LOG(debug) << "[MediaBrowserService] Handling Channel Open";
    aap_protobuf::channel::ChannelOpenRequest request;
    if (request.ParseFromArray(payload.cdata, payload.size)) {
      eventHandler->onChannelOpenRequest(request);
    } else {
      eventHandler->onChannelError(error::Error(error::ErrorCode::PARSE_PAYLOAD));
    }
  }
}


