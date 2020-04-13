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

void MessageInStream::startReceive(ReceivePromise::Pointer promise)
{
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

void MessageInStream::registerRandomCollector(ReceivePromise::Pointer promise) {
    AASDK_LOG(error) << "[MessageInStream] Registering Promise";
    randomPromise_ = std::move(promise);
}

void MessageInStream::receiveFrameHeaderHandler(const common::DataConstBuffer& buffer)
{
    FrameHeader frameHeader(buffer);
    frameHeaderBuffer = buffer;
    const size_t frameSize = FrameSize::getSizeOf(frameHeader.getType() == FrameType::FIRST ? FrameSizeType::EXTENDED : FrameSizeType::SHORT);

    if(message_ == nullptr)
    {
        message_ = std::make_shared<Message>(frameHeader.getChannelId(), frameHeader.getEncryptionType(), frameHeader.getMessageType());
        originalFrameChannelId = frameHeader.getChannelId();
    }

    // If the frame channel does not match the message channel, then we will process the frame separately
    if(message_->getChannelId() != frameHeader.getChannelId()) {
        newChannelMessage_ = std::make_shared<Message>(frameHeader.getChannelId(), frameHeader.getEncryptionType(), frameHeader.getMessageType());
    }

    currentFrameChannelId = frameHeader.getChannelId();

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
    if(message_->getEncryptionType() == EncryptionType::ENCRYPTED)
    {
        AASDK_LOG(error) << "[MessageInStream] Message is Encrypted";
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
        if (originalFrameChannelId == currentFrameChannelId) {
            message_->insertPayload(buffer);
        } else {
            if (originalFrameChannelId != currentFrameChannelId) {
                bool bypass = false;
                AASDK_LOG(error) << "[MessageInStream] Original Frame does Not Match Current Frame";
                FrameHeader frameHeader(frameHeaderBuffer);

                // Store the Old Message
                unfinishedMessage_[(int) originalFrameChannelId] = std::move(message_);

                // Create a new Message...
                auto newChannelMessage = std::make_shared<Message>(frameHeader.getChannelId(),
                                                                   frameHeader.getEncryptionType(),
                                                                   frameHeader.getMessageType());;

                // Try and see if there is a message for the current channel...
                auto unfinishedMessage = unfinishedMessage_.find((int) currentFrameChannelId);

                // If there isn't...
                if (unfinishedMessage == unfinishedMessage_.end()) {
                    AASDK_LOG(error) << "[MessageInStream] No Prior Message...";
                    // Ignore if this is the last or a middle message.
                    if ((frameHeader.getType() == FrameType::MIDDLE) || (frameHeader.getType() == FrameType::LAST)) {
                        AASDK_LOG(error) << "[MessageInStream] But it is a Middle or Last?";
                        bypass = true;
                    } else {
                        AASDK_LOG(error) << "[MessageInStream] This is a First Message. We can process.";
                        newChannelMessage = unfinishedMessage->second;
                    }
                } else {
                    AASDK_LOG(error) << "[MessageInStream] There is a Prior Message";
                    // If there is a message... but this is a first frame (or bulk) then we'll discard what we've got and start again...
                    if ((frameHeader.getType() == FrameType::FIRST) || (frameHeader.getType() == FrameType::BULK)) {
                        AASDK_LOG(error) << "[MessageInStream] First or Bulk - Will Process";
                        newChannelMessage = std::make_shared<Message>(frameHeader.getChannelId(),
                                                                      frameHeader.getEncryptionType(),
                                                                      frameHeader.getMessageType());
                    } else {
                        AASDK_LOG(error) << "[MessageInStream] This is a Middle or Last, but we have no first. Ignore.";
                        bypass = true;
                    }
                }

                if (!bypass) {
                    // Copy Contents to our unfinishedMessage
                    AASDK_LOG(error) << "[MessageInStream] Copy in Message";
                    newChannelMessage->insertPayload(buffer);
                    if (recentFrameType_ == FrameType::BULK || recentFrameType_ == FrameType::LAST) {
                        // If we can send this back, then we'll do it here...
                        AASDK_LOG(error) << "[MessageInStream] Resolving Random Promise";
                        randomPromise_->resolve(std::move(newChannelMessage));
                    } else {
                        AASDK_LOG(error) << "[MessageInStream] Cannot Process yet. Store back for safe keeping.";
                        // Otherwise we'll put it back in its box.
                        unfinishedMessage_[(int) currentFrameChannelId] = std::move(newChannelMessage);
                    }
                }
            }
            auto transportPromise = transport::ITransport::ReceivePromise::defer(strand_);
            transportPromise->then(
                    [this, self = this->shared_from_this()](common::Data data) mutable {
                        this->receiveFrameHeaderHandler(common::DataConstBuffer(data));
                    },
                    [this, self = this->shared_from_this()](const error::Error &e) mutable {
                        message_.reset();
                        promise_->reject(e);
                        promise_.reset();
                    });

            transport_->receive(FrameHeader::getSizeOf(), std::move(transportPromise));
        }
    }

    if (originalFrameChannelId == currentFrameChannelId) {
        if (recentFrameType_ == FrameType::BULK || recentFrameType_ == FrameType::LAST) {
            promise_->resolve(std::move(message_));
            message_.reset();
            promise_.reset();
        } else {
            auto transportPromise = transport::ITransport::ReceivePromise::defer(strand_);
            transportPromise->then(
                    [this, self = this->shared_from_this()](common::Data data) mutable {
                        this->receiveFrameHeaderHandler(common::DataConstBuffer(data));
                    },
                    [this, self = this->shared_from_this()](const error::Error &e) mutable {
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
}




