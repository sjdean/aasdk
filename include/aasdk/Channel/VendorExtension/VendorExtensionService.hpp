#pragma once

#include "aasdk/Channel/Channel.hpp"
#include "IVendorExtensionService.hpp"


namespace aasdk::channel::vendorextension {


  class VendorExtensionService
      : public IVendorExtensionService, public Channel, public std::enable_shared_from_this<VendorExtensionService> {
  public:
    VendorExtensionService(boost::asio::io_service::strand &strand, messenger::IMessenger::Pointer messenger);

    // Senders and Receivers

    void receive(IVendorExtensionServiceEventHandler::Pointer eventHandler) override;

    void
    sendChannelOpenResponse(const proto::channel::ChannelOpenResponse &response, SendPromise::Pointer promise) override;


  private:
    using std::enable_shared_from_this<VendorExtensionService>::shared_from_this;

    // Internal Message Handlers

    void messageHandler(messenger::Message::Pointer message, IVendorExtensionServiceEventHandler::Pointer eventHandler);

    void handleChannelOpenRequest(const common::DataConstBuffer &payload,
                                  IVendorExtensionServiceEventHandler::Pointer eventHandler);

  };

}
