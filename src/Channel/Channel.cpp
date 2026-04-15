// This file is part of aasdk library project.
// Copyright (C) 2018 f1x.studio (Michal Szwaj)
// Copyright (C) 2024 CubeOne (Simon Dean - simon.dean@cubeone.co.uk)
//
// aasdk is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 3 of the License, or
// (at your option) any later version.
//
// aasdk is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with aasdk. If not, see <http://www.gnu.org/licenses/>.

#include "aasdk/Channel/Channel.hpp"

namespace aasdk::channel {
  Channel::Channel(messenger::IMessenger::Pointer messenger,
                   messenger::ChannelId channelId)
      : messengerContext_(dynamic_cast<QObject*>(messenger.get())),
        messenger_(std::move(messenger)),
        channelId_(channelId) {

  }

  messenger::ChannelId Channel::getId() const {
    return channelId_;
  }

  void Channel::send(messenger::Message::Pointer message, SendPromise::Pointer promise) {
    auto sendPromise = messenger::SendPromise::defer(messengerContext_);
    sendPromise->then(
        [promise]() { if (promise) promise->resolve(); },
        [promise](const error::Error& e) { if (promise) promise->reject(e); }
    );
    messenger_->enqueueSend(std::move(message), std::move(sendPromise));
  }

}

