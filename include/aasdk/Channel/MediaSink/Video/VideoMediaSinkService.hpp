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

#include "aasdk/Messenger/MessageId.hpp"
#include "aasdk/Channel/Channel.hpp"
#include "aasdk/Channel/Channel.hpp"
#include "IVideoMediaSinkService.hpp"
#include "aasdk/Channel/MediaSink/MediaSinkService.hpp"
#include <aap_protobuf/channel/control/focus/video/notification/VideoFocusNotification.pb.h>

namespace aasdk::channel::mediasink::video {

  class VideoMediaSinkService
      : public MediaSinkService {
  public:
    VideoMediaSinkService(boost::asio::io_service::strand &strand, messenger::IMessenger::Pointer messenger,
                          messenger::ChannelId channelId);

  private:
    using std::enable_shared_from_this<MediaSinkService>::shared_from_this;

    void messageHandler(messenger::Message::Pointer message, IMediaSinkServiceEventHandler::Pointer eventHandler);

    void sendVideoFocusIndication(const aap_protobuf::channel::control::focus::video::notification::VideoFocusNotification &indication,
                                  SendPromise::Pointer promise);
  };

}


