#pragma once

#include <stdint.h>

#include "proto/channel/media/event/Setup.pb.h"
#include "proto/channel/media/event/Start.pb.h"
#include "proto/channel/media/event/Stop.pb.h"
#include "proto/channel/ChannelOpenRequest.pb.h"
#include "aasdk/Messenger/Timestamp.hpp"
#include "aasdk/Common/Data.hpp"
#include "aasdk/Error/Error.hpp"
#include "aasdk/Channel/MediaSink/IMediaSinkServiceEventHandler.hpp"
#include "proto/channel/control/focus/video/event/VideoFocusRequestNotification.pb.h"


namespace aasdk::channel::mediasink::video {

  class IVideoMediaSinkServiceEventHandler : public IMediaSinkServiceEventHandler {
  public:
    typedef std::shared_ptr<IVideoMediaSinkServiceEventHandler> Pointer;

    IVideoMediaSinkServiceEventHandler() = default;

    virtual ~IVideoMediaSinkServiceEventHandler() = default;

    virtual void onVideoFocusRequest(const proto::channel::control::focus::video::event::VideoFocusRequestNotification &request) = 0;
  };

}


