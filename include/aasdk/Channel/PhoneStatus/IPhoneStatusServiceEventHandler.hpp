#pragma once


#include <aap_protobuf/channel/ChannelOpenRequest.pb.h>
#include "aasdk/Error/Error.hpp"

namespace aasdk::channel::phonestatus {


  class IPhoneStatusServiceEventHandler {
  public:
    typedef std::shared_ptr<IPhoneStatusServiceEventHandler> Pointer;

    IPhoneStatusServiceEventHandler() = default;

    virtual ~IPhoneStatusServiceEventHandler() = default;

    virtual void onChannelOpenRequest(const aap_protobuf::channel::ChannelOpenRequest &request) = 0;

    virtual void onChannelError(const error::Error &e) = 0;
  };

}
