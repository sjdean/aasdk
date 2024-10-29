
#pragma once

#include <memory>
#include <aap_protobuf/service/media/sink/message/MediaSinkChannelSetupResponse.pb.h>
#include <aap_protobuf/service/media/source/message/MediaSourceMediaAckIndication.pb.h>
#include <aap_protobuf/channel/ChannelOpenResponse.pb.h>
#include "aasdk/Messenger/ChannelId.hpp"
#include "aasdk/Channel/Promise.hpp"
#include "IVideoMediaSinkServiceEventHandler.hpp"
#include "aasdk/Channel/MediaSink/IMediaSinkService.hpp"
#include <aap_protobuf/channel/control/focus/video/notification/VideoFocusNotification.pb.h>


namespace aasdk::channel::mediasink::video {

  class IVideoMediaSinkService : public IMediaSinkService {
  public:
    typedef std::shared_ptr<IVideoMediaSinkService> Pointer;

    IVideoMediaSinkService() = default;

    virtual ~IVideoMediaSinkService() = default;

    virtual void receive(IVideoMediaSinkService::Pointer eventHandler) = 0;

    virtual void
    sendVideoFocusIndication(const aap_protobuf::channel::control::focus::video::notification::VideoFocusNotification &indication, SendPromise::Pointer promise) = 0;
  };

}


