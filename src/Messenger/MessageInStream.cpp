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

#include <f1x/aasdk/Messenger/MessageInStream.hpp>
#include <f1x/aasdk/Error/Error.hpp>
#include <f1x/aasdk/Common/Log.hpp>

namespace f1x
{
namespace aasdk
{
namespace messenger
{

MessageInStream::MessageInStream(boost::asio::io_service& ioService, transport::ITransport::Pointer transport, ICryptor::Pointer cryptor)
    : strand_(ioService)
    , transport_(std::move(transport))
    , cryptor_(std::move(cryptor))
{

}

void MessageInStream::startReceive(ReceivePromise::Pointer promise, ChannelId channelId, int calledFromFunction, int qid, int ism)
{
    AASDK_LOG(error) << "[MessageInStream] start receive called on queue " << qid;
    AASDK_LOG(error) << "[MessageInStream] start receive called on ism " << ism;

    qid_ = qid;
    ism_ = ism;
    calledFromFunction_ = calledFromFunction;
    channelId_ = channelId;
    strand_.dispatch([this, self = this->shared_from_this(), promise = std::move(promise)]() mutable {
        if(promise_ == nullptr)
        {
            promise_ = std::move(promise);

            auto transportPromise = transport::ITransport::ReceivePromise::defer(strand_);
            transportPromise->then(
                [this, self = this->shared_from_this()](common::Data data) mutable {
                    this->receiveFrameHeaderHandler(common::DataConstBuffer(data));
                },
                [this, self = this->shared_from_this()](const error::Error& e) mutable {
                    promise_->reject(e);
                    promise_.reset();
                });

            transport_->receive(FrameHeader::getSizeOf(), std::move(transportPromise));
        }
        else
        {
            promise->reject(error::Error(error::ErrorCode::OPERATION_IN_PROGRESS));
        }
    });
}

void MessageInStream::receiveFrameHeaderHandler(const common::DataConstBuffer& buffer)
{
    ignoreFrame = false;

    AASDK_LOG(error) << "[MessageInStream::receiveFrameHeaderHandler] Queue Id" << qid_;
    AASDK_LOG(error) << "[MessageInStream::receiveFrameHeaderHandler] inStreamMessage Id " << ism_;

    FrameHeader frameHeader(buffer);
    const size_t frameSize = FrameSize::getSizeOf(frameHeader.getType() == FrameType::FIRST ? FrameSizeType::EXTENDED : FrameSizeType::SHORT);

    AASDK_LOG(error) << "[MessageInStream::receiveFrameSizeHandler] Buffer Size" << buffer.size;
    AASDK_LOG(error) << "[MessageInStream::receiveFrameHeaderHandler] Frame Channel: " << (int) frameHeader.getChannelId();
    AASDK_LOG(error) << "[MessageInStream::receiveFrameHeaderHandler] Frame Header Type: " << (int) frameHeader.getType();
    AASDK_LOG(error) << "[MessageInStream::receiveFrameHeaderHandler] Frame Message Type: " << (int) frameHeader.getMessageType();

    AASDK_LOG(error) << "[MessageInStream::receiveFrameHeaderHandler] Buffer Contents " << common::dump(buffer);

    if(message_ == nullptr)
    {
        message_ = std::make_shared<Message>(frameHeader.getChannelId(), frameHeader.getEncryptionType(), frameHeader.getMessageType());
    }

    if(message_->getChannelId() != frameHeader.getChannelId())
    {
        AASDK_LOG(error) << "[MessageInStream::receiveFrameHeaderHandler] Last Frame Header Type: " << (int) recentFrameType_;
        AASDK_LOG(error) << "[MessageInStream::receiveFrameHeaderHandler] Last Frame Channel: " << (int) recentFrameChannelId_;

        message_.reset();
        promise_->reject(error::Error(error::ErrorCode::MESSENGER_INTERTWINED_CHANNELS));
        promise_.reset();
        return;
   }

    recentFrameType_ = frameHeader.getType();
    recentFrameMessageType_ = frameHeader.getMessageType();
    recentFrameChannelId_ = frameHeader.getChannelId();

    auto transportPromise = transport::ITransport::ReceivePromise::defer(strand_);
    transportPromise->then(
        [this, self = this->shared_from_this()](common::Data data) mutable {
            this->receiveFrameSizeHandler(common::DataConstBuffer(data));
        },
        [this, self = this->shared_from_this()](const error::Error& e) mutable {
            message_.reset();
            promise_->reject(e);
            promise_.reset();
        });

    transport_->receive(frameSize, std::move(transportPromise));
}

void MessageInStream::receiveFrameSizeHandler(const common::DataConstBuffer& buffer)
{
    FrameSize frameSize(buffer);
    AASDK_LOG(error) << "[MessageInStream::receiveFrameSizeHandler] Buffer Size" << buffer.size;
    AASDK_LOG(error) << "[MessageInStream::receiveFrameSizeHandler] Frame Size " << (int) frameSize.getSize();
    AASDK_LOG(error) << "[MessageInStream::receiveFrameSizeHandler] Total Frame Size " << (int) frameSize.getTotalSize();
    AASDK_LOG(error) << "[MessageInStream::receiveFrameSizeHandler] Buffer Contents" << common::dump(buffer);

    auto transportPromise = transport::ITransport::ReceivePromise::defer(strand_);
    transportPromise->then(
        [this, self = this->shared_from_this()](common::Data data) mutable {
            this->receiveFramePayloadHandler(common::DataConstBuffer(data));
        },
        [this, self = this->shared_from_this()](const error::Error& e) mutable {
            message_.reset();
            promise_->reject(e);
            promise_.reset();
        });

    transport_->receive(frameSize.getSize(), std::move(transportPromise));
}

void MessageInStream::receiveFramePayloadHandler(const common::DataConstBuffer& buffer)
{
    AASDK_LOG(error) << "[MessageInStream::receiveFramePayloadHandler] Buffer Size" << buffer.size;
    AASDK_LOG(error) << "[MessageInStream::receiveFramePayloadHandler] Buffer Contents" << common::dump(buffer);
    if(message_->getEncryptionType() == EncryptionType::ENCRYPTED)
    {
        try
        {
            cryptor_->decrypt(message_->getPayload(), buffer);
        }
        catch(const error::Error& e)
        {
            message_.reset();
            promise_->reject(e);
            promise_.reset();
            return;
        }
    }
    else
    {
        if (!ignoreFrame) {
            message_->insertPayload(buffer);
        }
    }

    // TODO: Do we need to check on anything else here?
    if(recentFrameType_ == FrameType::BULK || recentFrameType_ == FrameType::LAST)
    {
        AASDK_LOG(error) << "[MessageInStream] Resolving QueueId " << qid_;
        AASDK_LOG(error) << "[MessageInStream] Resolving ISM Id " << ism_;

        promise_->resolve(std::move(message_));
        message_.reset();
        promise_.reset();
    }
    else
    {
        auto transportPromise = transport::ITransport::ReceivePromise::defer(strand_);
        transportPromise->then(
            [this, self = this->shared_from_this()](common::Data data) mutable {
                this->receiveFrameHeaderHandler(common::DataConstBuffer(data));
            },
            [this, self = this->shared_from_this()](const error::Error& e) mutable {
                message_.reset();
                promise_->reject(e);
                promise_.reset();
            });

        transport_->receive(FrameHeader::getSizeOf(), std::move(transportPromise));
    }
}

}
}
}




