#pragma once

#include "aasdk/Channel/Channel.hpp"
#include "IPhoneStatusService.hpp"


namespace aasdk::channel::phonestatus {


  class PhoneStatusService
      : public IPhoneStatusService, public Channel, public std::enable_shared_from_this<PhoneStatusService> {
  public:
    PhoneStatusService(boost::asio::io_service::strand &strand, messenger::IMessenger::Pointer messenger);

    // Senders and Receivers

    void receive(IPhoneStatusServiceEventHandler::Pointer eventHandler) override;

    void
    sendChannelOpenResponse(const aap_protobuf::channel::ChannelOpenResponse &response, SendPromise::Pointer promise) override;


  private:
    using std::enable_shared_from_this<PhoneStatusService>::shared_from_this;

    // Internal Message Handlers

    void messageHandler(messenger::Message::Pointer message, IPhoneStatusServiceEventHandler::Pointer eventHandler);

    void handleChannelOpenRequest(const common::DataConstBuffer &payload,
                                  IPhoneStatusServiceEventHandler::Pointer eventHandler);

  };

}
