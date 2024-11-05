#pragma once

#include <memory>
#include "aasdk/Channel/Promise.hpp"
#include "aasdk/Channel/IChannel.hpp"
#include "aasdk/Messenger/ChannelId.hpp"
#include <aap_protobuf/channel/ChannelOpenResponse.pb.h>
#include <aap_protobuf/service/wifiprojection/message/WifiCredentialsResponse.pb.h>
#include "IGenericNotificationServiceEventHandler.hpp"

namespace aasdk::channel::genericnotification {

  class IGenericNotificationService : public virtual IChannel {
  public:
    typedef std::shared_ptr<IGenericNotificationService> Pointer;

    IGenericNotificationService() = default;

    virtual ~IGenericNotificationService() = default;

    virtual void receive(IGenericNotificationServiceEventHandler::Pointer eventHandler) = 0;

    virtual void
    sendChannelOpenResponse(const aap_protobuf::channel::ChannelOpenResponse &response, SendPromise::Pointer promise) = 0;

  };
}
