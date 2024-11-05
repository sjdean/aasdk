#pragma once

#include <stdint.h>
#include <aap_protobuf/channel/media/event/Setup.pb.h>
#include <aap_protobuf/channel/media/event/Start.pb.h>
#include <aap_protobuf/channel/media/event/Stop.pb.h>
#include <aap_protobuf/channel/ChannelOpenRequest.pb.h>
#include "aasdk/Messenger/Timestamp.hpp"
#include "aasdk/Common/Data.hpp"
#include "aasdk/Error/Error.hpp"
#include <aap_protobuf/channel/control/focus/video/event/VideoFocusRequestNotification.pb.h>

namespace aasdk::channel::mediasink::audio {

  class IAudioMediaSinkServiceEventHandler {
  public:
    typedef std::shared_ptr<IAudioMediaSinkServiceEventHandler> Pointer;

    IAudioMediaSinkServiceEventHandler() = default;

    virtual ~IAudioMediaSinkServiceEventHandler() = default;

    virtual void onChannelOpenRequest(const aap_protobuf::channel::ChannelOpenRequest &request) = 0;

    virtual void onMediaChannelSetupRequest(const aap_protobuf::channel::media::event::Setup &request) = 0;

    virtual void onMediaChannelStartIndication(const aap_protobuf::channel::media::event::Start &indication) = 0;

    virtual void onMediaChannelStopIndication(const aap_protobuf::channel::media::event::Stop &indication) = 0;

    virtual void
    onMediaWithTimestampIndication(messenger::Timestamp::ValueType, const common::DataConstBuffer &buffer) = 0;

    virtual void onMediaIndication(const common::DataConstBuffer &buffer) = 0;

    virtual void onChannelError(const error::Error &e) = 0;

    };

}


