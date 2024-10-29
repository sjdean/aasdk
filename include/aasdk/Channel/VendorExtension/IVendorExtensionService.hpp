#pragma once

#include <memory>
#include "aasdk/Messenger/ChannelId.hpp"
#include "aasdk/Channel/Promise.hpp"
#include <aap_protobuf/channel/ChannelOpenResponse.pb.h>
#include <aap_protobuf/service/wifiprojection/message/WifiCredentialsResponse.pb.h>
#include "IVendorExtensionServiceEventHandler.hpp"

namespace aasdk::channel::vendorextension {

  class IVendorExtensionService {
  public:
    typedef std::shared_ptr<IVendorExtensionService> Pointer;

    IVendorExtensionService() = default;

    virtual ~IVendorExtensionService() = default;

    virtual void receive(IVendorExtensionServiceEventHandler::Pointer eventHandler) = 0;

    virtual void
    sendChannelOpenResponse(const aap_protobuf::channel::ChannelOpenResponse &response, SendPromise::Pointer promise) = 0;

  };
}
