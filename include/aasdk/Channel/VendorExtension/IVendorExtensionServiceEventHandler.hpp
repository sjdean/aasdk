
#pragma once

#include <aap_protobuf/channel/ChannelOpenRequest.pb.h>
#include "aasdk/Error/Error.hpp"

namespace aasdk::channel::vendorextension {


  class IVendorExtensionServiceEventHandler {
  public:
    typedef std::shared_ptr<IVendorExtensionServiceEventHandler> Pointer;

    IVendorExtensionServiceEventHandler() = default;

    virtual ~IVendorExtensionServiceEventHandler() = default;

    virtual void onChannelOpenRequest(const aap_protobuf::channel::ChannelOpenRequest &request) = 0;

    virtual void onChannelError(const error::Error &e) = 0;
  };

}
