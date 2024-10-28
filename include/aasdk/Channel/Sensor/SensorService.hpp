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

#include "aasdk/Channel/Channel.hpp"
#include "ISensorService.hpp"

namespace aasdk::channel::sensor {

  class SensorService : public ISensorService, public Channel, public std::enable_shared_from_this<SensorService> {
  public:
    SensorService(boost::asio::io_service::strand &strand, messenger::IMessenger::Pointer messenger);

    // Senders and Receivers

    void receive(ISensorServiceEventHandler::Pointer eventHandler) override;

    void
    sendChannelOpenResponse(const proto::channel::ChannelOpenResponse &response, SendPromise::Pointer promise) override;

    void sendSensorEventIndication(const proto::service::sensor::message::SensorBatch &indication,
                                   SendPromise::Pointer promise) override;

    void sendSensorStartResponse(const proto::service::sensor::message::SensorStartResponseMessage &response,
                                 SendPromise::Pointer promise) override;

  private:
    using std::enable_shared_from_this<SensorService>::shared_from_this;

    // Internal Message Handlers

    void messageHandler(messenger::Message::Pointer message, ISensorServiceEventHandler::Pointer eventHandler);

    void
    handleSensorStartRequest(const common::DataConstBuffer &payload, ISensorServiceEventHandler::Pointer eventHandler);

    void
    handleChannelOpenRequest(const common::DataConstBuffer &payload, ISensorServiceEventHandler::Pointer eventHandler);
  };

}
