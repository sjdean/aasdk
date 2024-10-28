#pragma once

#include <proto/channel/ChannelOpenRequest.pb.h>
#include "aasdk/Error/Error.hpp"

namespace aasdk::channel::radio {


  class IRadioServiceEventHandler {
  public:
    typedef std::shared_ptr<IRadioServiceEventHandler> Pointer;

    IRadioServiceEventHandler() = default;

    virtual ~IRadioServiceEventHandler() = default;

    virtual void onChannelOpenRequest(const proto::channel::ChannelOpenRequest &request) = 0;

    virtual void onChannelError(const error::Error &e) = 0;
  };

}
