#pragma once


#include <aap_protobuf/channel/ChannelOpenRequest.pb.h>
#include "aasdk/Error/Error.hpp"

namespace aasdk::channel::mediabrowser {


  class IMediaBrowserServiceEventHandler {
  public:
    typedef std::shared_ptr<IMediaBrowserServiceEventHandler> Pointer;

    IMediaBrowserServiceEventHandler() = default;

    virtual ~IMediaBrowserServiceEventHandler() = default;

    virtual void onChannelOpenRequest(const aap_protobuf::channel::ChannelOpenRequest &request) = 0;

    virtual void onChannelError(const error::Error &e) = 0;
  };

}
