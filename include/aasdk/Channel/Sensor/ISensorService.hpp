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
#include "aasdk/Messenger/ServiceId.hpp"
#include "aasdk/Channel/Promise.hpp"
#include <proto/service/sensor/message/SensorStartResponseMessage.pb.h>
#include <proto/service/sensor/message/SensorBatch.pb.h>
#include <proto/channel/ChannelOpenResponse.pb.h>
#include "ISensorServiceEventHandler.hpp"

namespace aasdk::channel::sensor {

  class ISensorService {
  public:
    typedef std::shared_ptr<ISensorService> Pointer;

    ISensorService() = default;

    virtual ~ISensorService() = default;

    virtual void receive(ISensorServiceEventHandler::Pointer eventHandler) = 0;

    virtual void
    sendChannelOpenResponse(const proto::channel::ChannelOpenResponse &response, SendPromise::Pointer promise) = 0;

    virtual void sendSensorEventIndication(const proto::service::sensor::message::SensorBatch &indication,
                                           SendPromise::Pointer promise) = 0;

    virtual void sendSensorStartResponse(const proto::service::sensor::message::SensorStartResponseMessage &response,
                                         SendPromise::Pointer promise) = 0;
  };

}


