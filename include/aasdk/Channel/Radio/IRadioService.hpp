#pragma once

#include <memory>
#include "aasdk/Messenger/ServiceId.hpp"
#include "aasdk/Channel/Promise.hpp"
#include <proto/channel/ChannelOpenResponse.pb.h>
#include "IRadioServiceEventHandler.hpp"

namespace aasdk::channel::radio {

  class IRadioService {
  public:
    typedef std::shared_ptr<IRadioService> Pointer;

    IRadioService() = default;

    virtual ~IRadioService() = default;

    virtual void receive(IRadioServiceEventHandler::Pointer eventHandler) = 0;

    virtual void
    sendChannelOpenResponse(const proto::channel::ChannelOpenResponse &response, SendPromise::Pointer promise) = 0;

  };
}
