
#pragma once

#include <memory>
#include "IAudioMediaSinkServiceEventHandler.hpp"
#include "aasdk/Channel/Promise.hpp"
#include "aasdk/Channel/IChannel.hpp"
#include "aasdk/Messenger/ChannelId.hpp"
#include <aap_protobuf/service/media/sink/message/MediaSinkChannelSetupResponse.pb.h>
#include <aap_protobuf/service/media/source/message/MediaSourceMediaAckIndication.pb.h>
#include <aap_protobuf/channel/control/focus/video/notification/VideoFocusNotification.pb.h>
#include <aap_protobuf/channel/control/focus/video/event/VideoFocusRequestNotification.pb.h>
#include <aap_protobuf/channel/ChannelOpenResponse.pb.h>

namespace aasdk::channel::mediasink::audio {

  class IAudioMediaSinkService : public virtual IChannel {
  public:
    typedef std::shared_ptr<IAudioMediaSinkService> Pointer;

    IAudioMediaSinkService() = default;

    virtual ~IAudioMediaSinkService() = default;

    virtual void receive(IAudioMediaSinkServiceEventHandler::Pointer eventHandler) = 0;

    virtual void
    sendChannelOpenResponse(const aap_protobuf::channel::ChannelOpenResponse &response, SendPromise::Pointer promise) = 0;

    virtual void
    sendChannelSetupResponse(const aap_protobuf::service::media::sink::message::MediaSinkChannelSetupResponse &response,
                             SendPromise::Pointer promise) = 0;

    virtual void
    sendMediaAckIndication(const aap_protobuf::service::media::source::message::MediaSourceMediaAckIndication &indication,
                           SendPromise::Pointer promise) = 0;

  };

}


