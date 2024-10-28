#pragma once

#include <memory>
#include "aasdk/Messenger/ServiceId.hpp"
#include "aasdk/Channel/Promise.hpp"
#include <proto/channel/ChannelOpenResponse.pb.h>
#include <proto/service/wifiprojection/message/WifiCredentialsResponse.pb.h>
#include "IPhoneStatusServiceEventHandler.hpp"

namespace aasdk::channel::phonestatus {

  class IPhoneStatusService {
  public:
    typedef std::shared_ptr<IPhoneStatusService> Pointer;

    IPhoneStatusService() = default;

    virtual ~IPhoneStatusService() = default;

    virtual void receive(IPhoneStatusServiceEventHandler::Pointer eventHandler) = 0;

    virtual void
    sendChannelOpenResponse(const proto::channel::ChannelOpenResponse &response, SendPromise::Pointer promise) = 0;

  };
}
