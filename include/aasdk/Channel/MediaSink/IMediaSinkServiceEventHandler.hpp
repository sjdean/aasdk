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

#include <stdint.h>

#include "proto/channel/media/event/Setup.pb.h"
#include "proto/channel/media/event/Start.pb.h"
#include "proto/channel/media/event/Stop.pb.h"
#include "proto/channel/ChannelOpenRequest.pb.h"
#include "aasdk/Messenger/Timestamp.hpp"
#include "aasdk/Common/Data.hpp"
#include "aasdk/Error/Error.hpp"


namespace aasdk::channel::mediasink {

  class IMediaSinkServiceEventHandler {
  public:
    typedef std::shared_ptr<IMediaSinkServiceEventHandler> Pointer;

    IMediaSinkServiceEventHandler() = default;

    virtual ~IMediaSinkServiceEventHandler() = default;

    virtual void onChannelOpenRequest(const proto::channel::ChannelOpenRequest &request) = 0;

    virtual void onSetup(const proto::channel::media::event::Setup &request) = 0;

    virtual void onStart(const proto::channel::media::event::Start &indication) = 0;

    virtual void onStop(const proto::channel::media::event::Stop &indication) = 0;

    virtual void
    onMediaWithTimestampIndication(messenger::Timestamp::ValueType, const common::DataConstBuffer &buffer) = 0;

    virtual void onMediaIndication(const common::DataConstBuffer &buffer) = 0;

    virtual void onChannelError(const error::Error &e) = 0;
  };

}


