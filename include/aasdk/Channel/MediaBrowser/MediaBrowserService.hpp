#pragma once

#include "aasdk/Channel/Channel.hpp"
#include "IMediaBrowserService.hpp"


namespace aasdk::channel::mediabrowser {


  class MediaBrowserService
      : public IMediaBrowserService, public Channel, public std::enable_shared_from_this<MediaBrowserService> {
  public:
    MediaBrowserService(boost::asio::io_service::strand &strand, messenger::IMessenger::Pointer messenger);

    // Senders and Receivers

    void receive(IMediaBrowserServiceEventHandler::Pointer eventHandler) override;

    void
    sendChannelOpenResponse(const aap_protobuf::channel::ChannelOpenResponse &response, SendPromise::Pointer promise) override;


  private:
    using std::enable_shared_from_this<MediaBrowserService>::shared_from_this;

    // Internal Message Handlers

    void messageHandler(messenger::Message::Pointer message, IMediaBrowserServiceEventHandler::Pointer eventHandler);

    void handleChannelOpenRequest(const common::DataConstBuffer &payload,
                                  IMediaBrowserServiceEventHandler::Pointer eventHandler);

  };

}
