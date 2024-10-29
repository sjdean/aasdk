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

#include <aap_protobuf/channel/control/byebye/event/ByeByeRequest.pb.h>
#include <aap_protobuf/channel/control/byebye/notification/ByeByeResponse.pb.h>
#include <aap_protobuf/channel/control/auth/AuthResponse.pb.h>
#include <aap_protobuf/channel/control/servicediscovery/notification/ServiceDiscoveryResponse.pb.h>
#include <aap_protobuf/channel/control/focus/audio/notification/AudioFocusNotification.pb.h>
#include <aap_protobuf/channel/control/focus/navigation/notification/NavFocusNotification.pb.h>
#include <aap_protobuf/shared/MessageStatus.pb.h>
#include <aap_protobuf/channel/control/ping/PingRequest.pb.h>
#include <aap_protobuf/channel/control/ping/PingResponse.pb.h>
#include <aap_protobuf/channel/control/voice/VoiceSessionNotification.pb.h>
#include <aasdk/Common/Data.hpp>
#include <aasdk/Channel/Promise.hpp>
#include <aasdk/Channel/Control/IControlServiceChannelEventHandler.hpp>


namespace aasdk::channel::control {

  class IControlServiceChannel {
  public:
    typedef std::shared_ptr<IControlServiceChannel> Pointer;

    IControlServiceChannel() = default;

    virtual ~IControlServiceChannel() = default;

    virtual void receive(IControlServiceChannelEventHandler::Pointer eventHandler) = 0;

    virtual void sendVersionRequest(SendPromise::Pointer promise) = 0;

    virtual void sendHandshake(common::Data handshakeBuffer, SendPromise::Pointer promise) = 0;

    virtual void sendAuthComplete(const aap_protobuf::channel::control::auth::AuthResponse &response,
                                  SendPromise::Pointer promise) = 0;

    virtual void sendServiceDiscoveryResponse(
        const aap_protobuf::channel::control::servicediscovery::notification::ServiceDiscoveryResponse &response,
        SendPromise::Pointer promise) = 0;

    virtual void
    sendAudioFocusResponse(const aap_protobuf::channel::control::focus::audio::notification::AudioFocusNotification &response,
                           SendPromise::Pointer promise) = 0;

    virtual void
    sendShutdownRequest(const aap_protobuf::channel::control::byebye::event::ByeByeRequest &request,
                        SendPromise::Pointer promise) = 0;

    virtual void sendShutdownResponse(const aap_protobuf::channel::control::byebye::notification::ByeByeResponse &response,
                                      SendPromise::Pointer promise) = 0;

    virtual void
    sendNavigationFocusResponse(
        const aap_protobuf::channel::control::focus::navigation::notification::NavFocusNotification &response,
        SendPromise::Pointer promise) = 0;

    virtual void
    sendVoiceSessionFocusResponse(const aap_protobuf::channel::control::version::VoiceSessionNotification &response,
                                  SendPromise::Pointer promise) = 0;

    virtual void
    sendPingRequest(const aap_protobuf::channel::control::ping::PingRequest &request, SendPromise::Pointer promise) = 0;

    virtual void
    sendPingResponse(const aap_protobuf::channel::control::ping::PingResponse &response, SendPromise::Pointer promise) = 0;
  };
}


