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

#include <memory>
#include <aap_protobuf/service/media/sink/message/MediaSinkChannelSetupResponse.pb.h>
#include <aap_protobuf/service/media/source/message/MediaSourceMediaAckIndication.pb.h>
#include <aap_protobuf/channel/ChannelOpenResponse.pb.h>
#include "aasdk/Messenger/ChannelId.hpp"
#include "aasdk/Channel/Promise.hpp"
#include "IMediaSinkServiceEventHandler.hpp"


namespace aasdk::channel::mediasink {

  class IMediaSinkService {
  public:
    typedef std::shared_ptr<IMediaSinkService> Pointer;

    IMediaSinkService() = default;

    virtual ~IMediaSinkService() = default;

    virtual void receive(IMediaSinkServiceEventHandler::Pointer eventHandler) = 0;

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


