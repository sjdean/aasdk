#pragma once


#include <proto/channel/ChannelOpenRequest.pb.h>
#include "aasdk/Error/Error.hpp"

namespace aasdk::channel::genericnotification {


  class IGenericNotificationServiceEventHandler {
  public:
    typedef std::shared_ptr<IGenericNotificationServiceEventHandler> Pointer;

    IGenericNotificationServiceEventHandler() = default;

    virtual ~IGenericNotificationServiceEventHandler() = default;

    virtual void onChannelOpenRequest(const proto::channel::ChannelOpenRequest &request) = 0;

    virtual void onChannelError(const error::Error &e) = 0;
  };

}
