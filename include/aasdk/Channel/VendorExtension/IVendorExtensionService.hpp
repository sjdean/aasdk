#pragma once

#include <memory>
#include "aasdk/Messenger/ServiceId.hpp"
#include "aasdk/Channel/Promise.hpp"
#include <proto/channel/ChannelOpenResponse.pb.h>
#include <proto/service/wifiprojection/message/WifiCredentialsResponse.pb.h>
#include "IVendorExtensionServiceEventHandler.hpp"

namespace aasdk::channel::vendorextension {

  class IVendorExtensionService {
  public:
    typedef std::shared_ptr<IVendorExtensionService> Pointer;

    IVendorExtensionService() = default;

    virtual ~IVendorExtensionService() = default;

    virtual void receive(IVendorExtensionServiceEventHandler::Pointer eventHandler) = 0;

    virtual void
    sendChannelOpenResponse(const proto::channel::ChannelOpenResponse &response, SendPromise::Pointer promise) = 0;

  };
}
