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

#include <boost/endian/conversion.hpp>
#include <f1x/aasdk/Error/Error.hpp>
#include <f1x/aasdk/Messenger/Messenger.hpp>
#include <f1x/aasdk/Common/Log.hpp>

namespace f1x
{
namespace aasdk
{
namespace messenger
{

Messenger::Messenger(boost::asio::io_service& ioService, IMessageInStream::Pointer messageInStream, IMessageOutStream::Pointer messageOutStream)
    : receiveStrand_(ioService)
    , sendStrand_(ioService)
    , messageInStream_(std::move(messageInStream))
    , messageOutStream_(std::move(messageOutStream))
{
    qId_ = 0;
    isM_ = 0;
}

void Messenger::enqueueReceive(ChannelId channelId, ReceivePromise::Pointer promise)
{
    qId_++;
    isM_ = 0;

    AASDK_LOG(error) << "[Messenger] enqueueReceive Id " << qId_;

    receiveStrand_.dispatch([this, self = this->shared_from_this(), channelId, promise = std::move(promise)]() mutable {
        if(!channelReceiveMessageQueue_.empty(channelId))
        {
            AASDK_LOG(error) << "[Messenger] Queue Not Empty. Popping. "
            promise->resolve(std::move(channelReceiveMessageQueue_.pop(channelId)));
        }
        else
        {
            AASDK_LOG(error) << "[Messenger] Queue Empty. Pushing. ";
            channelReceivePromiseQueue_.push(channelId, std::move(promise));

            if(channelReceivePromiseQueue_.size() == 1)
            {
                AASDK_LOG(error) << "[Messenger] Queue Size One. ";
                AASDK_LOG(error) << "[Messenger] Calling startReceive from enqueueReceive on channel " << (int) channelId;
                auto inStreamPromise = ReceivePromise::defer(receiveStrand_);
                inStreamPromise->then(std::bind(&Messenger::inStreamMessageHandler, this->shared_from_this(), std::placeholders::_1),
                                     std::bind(&Messenger::rejectReceivePromiseQueue, this->shared_from_this(), std::placeholders::_1));
                messageInStream_->startReceive(std::move(inStreamPromise), channelId, 1, qId_, isM_);
            }
        }
    });
}

void Messenger::enqueueSend(Message::Pointer message, SendPromise::Pointer promise)
{
    sendStrand_.dispatch([this, self = this->shared_from_this(), message = std::move(message), promise = std::move(promise)]() mutable {
        channelSendPromiseQueue_.emplace_back(std::make_pair(std::move(message), std::move(promise)));

        if(channelSendPromiseQueue_.size() == 1)
        {
            this->doSend();
        }
    });
}

void Messenger::inStreamMessageHandler(Message::Pointer message)
{
    auto channelId = message->getChannelId();

    isM_++;
    AASDK_LOG(error) << "[Messenger] inStreamMessageHandler. " << qId_;
    AASDK_LOG(error) << "[Messenger] inStreamMessageHandler. " << isM_;

    if(channelReceivePromiseQueue_.isPending(channelId))
    {
        AASDK_LOG(error) << "[Messenger] inStreamMessageHandler Popping ";
        channelReceivePromiseQueue_.pop(channelId)->resolve(std::move(message));
    }
    else
    {
        AASDK_LOG(error) << "[Messenger] inStreamMessageHandler Pushing ";
        channelReceiveMessageQueue_.push(std::move(message));
    }

    if(!channelReceivePromiseQueue_.empty())
    {
        AASDK_LOG(error) << "[Messenger] Calling startReceive from inStreamMessageHandler on channel " << (int) channelId;
        auto inStreamPromise = ReceivePromise::defer(receiveStrand_);
        inStreamPromise->then(std::bind(&Messenger::inStreamMessageHandler, this->shared_from_this(), std::placeholders::_1),
                             std::bind(&Messenger::rejectReceivePromiseQueue, this->shared_from_this(), std::placeholders::_1));
        messageInStream_->startReceive(std::move(inStreamPromise), channelId, 2, qId_, isM_);
    }
}

void Messenger::doSend()
{
    auto queueElementIter = channelSendPromiseQueue_.begin();
    auto outStreamPromise = SendPromise::defer(sendStrand_);
    outStreamPromise->then(std::bind(&Messenger::outStreamMessageHandler, this->shared_from_this(), queueElementIter),
                           std::bind(&Messenger::rejectSendPromiseQueue, this->shared_from_this(), std::placeholders::_1));

    messageOutStream_->stream(std::move(queueElementIter->first), std::move(outStreamPromise));
}

void Messenger::outStreamMessageHandler(ChannelSendQueue::iterator queueElement)
{
    queueElement->second->resolve();
    channelSendPromiseQueue_.erase(queueElement);

    if(!channelSendPromiseQueue_.empty())
    {
        this->doSend();
    }
}

void Messenger::rejectReceivePromiseQueue(const error::Error& e)
{
    AASDK_LOG(error) << "[Messenger] Rejecting Promise. " << qId_;
    AASDK_LOG(error) << "[Messenger] Rejecting Promise. " << isM_;
    while(!channelReceivePromiseQueue_.empty())
    {
        channelReceivePromiseQueue_.pop()->reject(e);
    }
}

void Messenger::rejectSendPromiseQueue(const error::Error& e)
{
    while(!channelSendPromiseQueue_.empty())
    {
        auto queueElement(std::move(channelSendPromiseQueue_.front()));
        channelSendPromiseQueue_.pop_front();
        queueElement.second->reject(e);
    }
}

void Messenger::stop()
{
    receiveStrand_.dispatch([this, self = this->shared_from_this()]() {
        channelReceiveMessageQueue_.clear();
    });
}

}
}
}
