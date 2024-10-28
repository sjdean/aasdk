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

#include <proto/channel/control/byebye/event/ByeByeRequest.pb.h>
#include <proto/channel/control/byebye/notification//ByeByeResponse.pb.h>
#include <proto/channel/control/auth/AuthResponse.pb.h>
#include <proto/channel/control/servicediscovery/notification/ServiceDiscoveryResponse.pb.h>
#include <proto/channel/control/focus/audio/notification/AudioFocusNotification.pb.h>
#include <proto/channel/control/focus/navigation/notification/NavigationFocusNotification.pb.h>
#include <proto/shared/MessageStatus.pb.h>
#include <proto/channel/control/ping/PingRequest.pb.h>
#include <proto/channel/control/ping/PingResponse.pb.h>
#include <proto/channel/control/voice/VoiceSessionNotification.pb.h>
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

    virtual void sendAuthComplete(const proto::channel::control::auth::AuthResponse &response,
                                  SendPromise::Pointer promise) = 0;

    virtual void sendServiceDiscoveryResponse(
        const proto::channel::control::servicediscovery::notification::ServiceDiscoveryResponse &response,
        SendPromise::Pointer promise) = 0;

    virtual void
    sendAudioFocusResponse(const proto::channel::control::focus::audio::notification::AudioFocusNotification &response,
                           SendPromise::Pointer promise) = 0;

    virtual void
    sendShutdownRequest(const proto::channel::control::byebye::event::ByeByeRequest &request,
                        SendPromise::Pointer promise) = 0;

    virtual void sendShutdownResponse(const proto::channel::control::byebye::notification::ByeByeResponse &response,
                                      SendPromise::Pointer promise) = 0;

    virtual void
    sendNavigationFocusResponse(
        const proto::channel::control::focus::navigation::notification::NavigationFocusNotification &response,
        SendPromise::Pointer promise) = 0;

    virtual void
    sendVoiceSessionFocusResponse(const proto::channel::control::version::VoiceSessionNotification &response,
                                  SendPromise::Pointer promise) = 0;

    virtual void
    sendPingRequest(const proto::channel::control::ping::PingRequest &request, SendPromise::Pointer promise) = 0;

    virtual void
    sendPingResponse(const proto::channel::control::ping::PingResponse &response, SendPromise::Pointer promise) = 0;
  };
}


