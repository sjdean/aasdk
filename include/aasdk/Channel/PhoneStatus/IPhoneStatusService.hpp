#pragma once

#include <memory>
#include "aasdk/Messenger/ChannelId.hpp"
#include "aasdk/Channel/Promise.hpp"
#include <aap_protobuf/channel/ChannelOpenResponse.pb.h>
#include <aap_protobuf/service/wifiprojection/message/WifiCredentialsResponse.pb.h>
#include "IPhoneStatusServiceEventHandler.hpp"

namespace aasdk::channel::phonestatus {

  class IPhoneStatusService {
  public:
    typedef std::shared_ptr<IPhoneStatusService> Pointer;

    IPhoneStatusService() = default;

    virtual ~IPhoneStatusService() = default;

    virtual void receive(IPhoneStatusServiceEventHandler::Pointer eventHandler) = 0;

    virtual void
    sendChannelOpenResponse(const aap_protobuf::channel::ChannelOpenResponse &response, SendPromise::Pointer promise) = 0;

  };
}
