#pragma once

#include "aasdk/Channel/Channel.hpp"
#include "IRadioService.hpp"


namespace aasdk::channel::radio {


  class RadioService
      : public IRadioService, public Channel, public std::enable_shared_from_this<RadioService> {
  public:
    RadioService(boost::asio::io_service::strand &strand, messenger::IMessenger::Pointer messenger);

    // Senders and Receivers

    void receive(IRadioServiceEventHandler::Pointer eventHandler) override;

    void
    sendChannelOpenResponse(const proto::channel::ChannelOpenResponse &response, SendPromise::Pointer promise) override;


  private:
    using std::enable_shared_from_this<RadioService>::shared_from_this;

    void messageHandler(messenger::Message::Pointer message, IRadioServiceEventHandler::Pointer eventHandler);

    void handleChannelOpenRequest(const common::DataConstBuffer &payload,
                                  IRadioServiceEventHandler::Pointer eventHandler);

  };

}
