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

#include <aap_protobuf/shared/MessageStatus.pb.h>
#include <aap_protobuf/service/media/sink/message/BindingResponse.pb.h>
#include <aap_protobuf/service/input/message/InputEventIndication.pb.h>
#include <aap_protobuf/channel/ChannelOpenResponse.pb.h>
#include "aasdk/Messenger/ChannelId.hpp"
#include "aasdk/Channel/Promise.hpp"
#include "IInputSourceServiceEventHandler.hpp"


namespace aasdk::channel::inputsource {
  class IInputSourceService {
  public:
    typedef std::shared_ptr<IInputSourceService> Pointer;

    IInputSourceService() = default;

    virtual ~IInputSourceService() = default;

    virtual void receive(IInputSourceServiceEventHandler::Pointer eventHandler) = 0;

    virtual void
    sendChannelOpenResponse(const aap_protobuf::channel::ChannelOpenResponse &response, SendPromise::Pointer promise) = 0;

    virtual void sendInputEventIndication(const aap_protobuf::service::input::message::InputEventIndication &indication,
                                          SendPromise::Pointer promise) = 0;

    virtual void sendBindingResponse(const aap_protobuf::service::media::sink::message::BindingResponse &response,
                                     SendPromise::Pointer promise) = 0;
  };

}


