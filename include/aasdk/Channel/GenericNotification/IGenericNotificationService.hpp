#pragma once

#include <memory>
#include <proto/channel/ChannelOpenResponse.pb.h>
#include <proto/service/wifiprojection/message/WifiCredentialsResponse.pb.h>
#include "aasdk/Messenger/ServiceId.hpp"
#include "aasdk/Channel/Promise.hpp"
#include "IGenericNotificationServiceEventHandler.hpp"

namespace aasdk::channel::genericnotification {

  class IGenericNotificationService {
  public:
    typedef std::shared_ptr<IGenericNotificationService> Pointer;

    IGenericNotificationService() = default;

    virtual ~IGenericNotificationService() = default;

    virtual void receive(IGenericNotificationServiceEventHandler::Pointer eventHandler) = 0;

    virtual void
    sendChannelOpenResponse(const proto::channel::ChannelOpenResponse &response, SendPromise::Pointer promise) = 0;

  };
}
