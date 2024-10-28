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

#include <boost/asio.hpp>
#include <aasdk/Messenger/IMessenger.hpp>
#include "aasdk/Channel/Channel.hpp"
#include <aasdk/Channel/Control/IControlServiceChannel.hpp>


namespace aasdk::channel::control {

  class ControlServiceChannel
      : public IControlServiceChannel, public Channel, public std::enable_shared_from_this<ControlServiceChannel> {
  public:
    ControlServiceChannel(boost::asio::io_service::strand &strand, messenger::IMessenger::Pointer messenger);

    // Senders and Receivers

    void receive(IControlServiceChannelEventHandler::Pointer eventHandler) override;

    void sendVersionRequest(SendPromise::Pointer promise) override;

    void sendHandshake(common::Data handshakeBuffer, SendPromise::Pointer promise) override;

    void sendAuthComplete(const proto::channel::control::auth::AuthResponse &response,
                          SendPromise::Pointer promise) override;

    void sendServiceDiscoveryResponse(
        const proto::channel::control::servicediscovery::notification::ServiceDiscoveryResponse &response,
        SendPromise::Pointer promise) override;

    void
    sendAudioFocusResponse(const proto::channel::control::focus::audio::notification::AudioFocusNotification &response,
                           SendPromise::Pointer promise) override;

    void sendShutdownRequest(const proto::channel::control::byebye::event::ByeByeRequest &request,
                             SendPromise::Pointer promise) override;

    void sendShutdownResponse(const proto::channel::control::byebye::notification::ByeByeResponse &response,
                              SendPromise::Pointer promise) override;

    void sendNavigationFocusResponse(
        const proto::channel::control::focus::navigation::notification::NavigationFocusNotification &response,
        SendPromise::Pointer promise) override;

    void
    sendPingRequest(const proto::channel::control::ping::PingRequest &request, SendPromise::Pointer promise) override;

    void
    sendPingResponse(const proto::channel::control::ping::PingResponse &response,
                     SendPromise::Pointer promise) override;

  private:
    using std::enable_shared_from_this<ControlServiceChannel>::shared_from_this;

    // Internal Message Handlers

    void
    messageHandler(messenger::Message::Pointer message, IControlServiceChannelEventHandler::Pointer eventHandler);

    void handleVersionResponse(const common::DataConstBuffer &payload,
                               IControlServiceChannelEventHandler::Pointer eventHandler);

    void handleServiceDiscoveryRequest(const common::DataConstBuffer &payload,
                                       IControlServiceChannelEventHandler::Pointer eventHandler);

    void handleAudioFocusRequest(const common::DataConstBuffer &payload,
                                 IControlServiceChannelEventHandler::Pointer eventHandler);

    void handleShutdownRequest(const common::DataConstBuffer &payload,
                               IControlServiceChannelEventHandler::Pointer eventHandler);

    void handleShutdownResponse(const common::DataConstBuffer &payload,
                                IControlServiceChannelEventHandler::Pointer eventHandler);

    void handleNavigationFocusRequest(const common::DataConstBuffer &payload,
                                      IControlServiceChannelEventHandler::Pointer eventHandler);

    void handlePingRequest(const common::DataConstBuffer &payload,
                           IControlServiceChannelEventHandler::Pointer eventHandler);

    void handlePingResponse(const common::DataConstBuffer &payload,
                            IControlServiceChannelEventHandler::Pointer eventHandler);

    void handleVoiceSessionRequest(const common::DataConstBuffer &payload,
                                   IControlServiceChannelEventHandler::Pointer eventHandler);
  };

}


