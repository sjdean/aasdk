#pragma once

#include <memory>
#include "aasdk/Messenger/ServiceId.hpp"
#include "aasdk/Channel/Promise.hpp"
#include <proto/channel/ChannelOpenResponse.pb.h>
#include "IMediaBrowserServiceEventHandler.hpp"

namespace aasdk::channel::mediabrowser {

  class IMediaBrowserService {
  public:
    typedef std::shared_ptr<IMediaBrowserService> Pointer;

    IMediaBrowserService() = default;

    virtual ~IMediaBrowserService() = default;

    virtual void receive(IMediaBrowserServiceEventHandler::Pointer eventHandler) = 0;

    virtual void
    sendChannelOpenResponse(const proto::channel::ChannelOpenResponse &response, SendPromise::Pointer promise) = 0;

  };
}
