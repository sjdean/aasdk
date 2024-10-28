
#pragma once

#include <proto/channel/ChannelOpenRequest.pb.h>
#include "aasdk/Error/Error.hpp"

namespace aasdk::channel::vendorextension {


  class IVendorExtensionServiceEventHandler {
  public:
    typedef std::shared_ptr<IVendorExtensionServiceEventHandler> Pointer;

    IVendorExtensionServiceEventHandler() = default;

    virtual ~IVendorExtensionServiceEventHandler() = default;

    virtual void onChannelOpenRequest(const proto::channel::ChannelOpenRequest &request) = 0;

    virtual void onChannelError(const error::Error &e) = 0;
  };

}
