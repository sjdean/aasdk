#pragma once

#include <memory>
#include "aasdk/Channel/Promise.hpp"
#include "aasdk/Channel/IChannel.hpp"
#include "aasdk/Messenger/ChannelId.hpp"
#include <aap_protobuf/channel/ChannelOpenResponse.pb.h>
#include "IRadioServiceEventHandler.hpp"

namespace aasdk::channel::radio {

  class IRadioService : public virtual IChannel {
  public:
    typedef std::shared_ptr<IRadioService> Pointer;

    IRadioService() = default;

    virtual ~IRadioService() = default;

    virtual void receive(IRadioServiceEventHandler::Pointer eventHandler) = 0;

    virtual void
    sendChannelOpenResponse(const aap_protobuf::channel::ChannelOpenResponse &response, SendPromise::Pointer promise) = 0;

  };
}
