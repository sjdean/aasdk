#pragma once

#include <stdint.h>

#include <aap_protobuf/channel/media/event/Setup.pb.h>
#include <aap_protobuf/channel/media/event/Start.pb.h>
#include <aap_protobuf/channel/media/event/Stop.pb.h>
#include <aap_protobuf/channel/ChannelOpenRequest.pb.h>
#include "aasdk/Messenger/Timestamp.hpp"
#include "aasdk/Common/Data.hpp"
#include "aasdk/Error/Error.hpp"
#include "aasdk/Channel/MediaSink/IMediaSinkServiceEventHandler.hpp"
#include <aap_protobuf/channel/control/focus/video/event/VideoFocusRequestNotification.pb.h>


namespace aasdk::channel::mediasink::video {

  class IVideoMediaSinkServiceEventHandler : public IMediaSinkServiceEventHandler {
  public:
    typedef std::shared_ptr<IVideoMediaSinkServiceEventHandler> Pointer;

    IVideoMediaSinkServiceEventHandler() = default;

    virtual ~IVideoMediaSinkServiceEventHandler() = default;

    virtual void onVideoFocusRequest(const aap_protobuf::channel::control::focus::video::event::VideoFocusRequestNotification &request) = 0;
  };

}


