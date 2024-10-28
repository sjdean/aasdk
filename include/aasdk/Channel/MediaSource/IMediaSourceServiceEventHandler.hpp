/*
*  This file is part of aasdk library project.
*  Copyright (C) 2018 f1x.studio (Michal Szwaj)
*
*  aasdk is free software: you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 3 of the License, or
*  (at your option) any later version.

*  aasdk is distributed in the hope that it will be useful,
*  but WITHOUT ANY WARRANTY; without even the implied warranty of
*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*  GNU General Public License for more details.
*
*  You should have received a copy of the GNU General Public License
*  along with aasdk. If not, see <http://www.gnu.org/licenses/>.
*/

#pragma once

#include <proto/channel/media/event/Setup.pb.h>
#include <proto/service/media/source/message/MediaSourceMediaAckIndication.pb.h>
#include <proto/service/media/source/message/MicrophoneRequest.pb.h>
#include <proto/channel/ChannelOpenRequest.pb.h>
#include "aasdk/Error/Error.hpp"


namespace aasdk::channel::mediasource {

  class IMediaSourceServiceEventHandler {
  public:
    typedef std::shared_ptr<IMediaSourceServiceEventHandler> Pointer;

    IMediaSourceServiceEventHandler() = default;

    virtual ~IMediaSourceServiceEventHandler() = default;

    virtual void onChannelOpenRequest(const proto::channel::ChannelOpenRequest &request) = 0;

    virtual void onAVChannelSetupRequest(const proto::channel::media::event::Setup &request) = 0;

    virtual void
    onAVInputOpenRequest(const proto::service::media::source::message::MicrophoneRequest &request) = 0;

    virtual void
    onAVMediaAckIndication(const proto::service::media::source::message::MediaSourceMediaAckIndication &indication) = 0;

    virtual void onChannelError(const error::Error &e) = 0;
  };

}


