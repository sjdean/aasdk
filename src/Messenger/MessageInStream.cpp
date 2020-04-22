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

            void MessageInStream::setRandomHandler(ReceivePromise::Pointer promise)
            {
                randomPromise_ = std::move(promise);
            }

            void MessageInStream::findExistingMessage(FrameHeader frameHeader) {
                // Store Old Message for Safe Keeping
                messageInProgress_[(int) originalChannelId_] = std::move(message_);

                if (frameHeader.getType() == FrameType::FIRST || frameHeader.getType() == FrameType::BULK) {
                    // Create a New Message. If we had pre-existing data on this channel then we will lose that, because this is a New Message.
                    message_ = std::make_shared<Message>(currentChannelId_, encryptionType_, messageType_);
                    hasInterleavedMessage_ = true;
                } else {
                    // This is a Middle or Last Message. We must find an existing message.
                    auto interleavedMessage = messageInProgress_.find((int) currentChannelId_);
                    if (interleavedMessage != messageInProgress_.end()) {
                        // If it's not first or bulk, then it's middle or last...
                        message_ = std::move(interleavedMessage->second);
                        hasInterleavedMessage_ = true;
                    }
                }

            }

            void MessageInStream::receiveFrameHeaderHandler(const common::DataConstBuffer& buffer)
            {
                FrameHeader frameHeader(buffer);
                currentChannelId_ = frameHeader.getChannelId();
                encryptionType_ = frameHeader.getEncryptionType();
                messageType_ = frameHeader.getMessageType();

                hasInterleavedMessage_ = false;

                if(message_ == nullptr)
                {
                    message_ = std::make_shared<Message>(frameHeader.getChannelId(), frameHeader.getEncryptionType(), frameHeader.getMessageType());
                    originalChannelId_ = frameHeader.getChannelId();
                }

                if (originalChannelId_ != frameHeader.getChannelId()) {
                    this->findExistingMessage(frameHeader);
                }

                recentFrameType_ = frameHeader.getType();
                const size_t frameSize = FrameSize::getSizeOf(frameHeader.getType() == FrameType::FIRST ? FrameSizeType::EXTENDED : FrameSizeType::SHORT);

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

                FrameSize frameSize(buffer);
                frameSize_ = (int) frameSize.getSize();
                transport_->receive(frameSize.getSize(), std::move(transportPromise));
            }

            void MessageInStream::receiveFramePayloadHandler(const common::DataConstBuffer& buffer)
            {
                bool promiseResolved = false;

                // Process the message as normal...
                if (message_ != nullptr) {
                    if (message_->getEncryptionType() == EncryptionType::ENCRYPTED) {
                        try {
                            cryptor_->decrypt(message_->getPayload(), buffer, frameSize_ - 29);
                        }
                        catch (const error::Error &e) {
                            message_.reset();
                            promise_->reject(e);
                            promise_.reset();
                            return;
                        }
                    } else {
                        message_->insertPayload(buffer);
                    }

                    // Resolve Promises As Necessary
                    if ((recentFrameType_ == FrameType::BULK || recentFrameType_ == FrameType::LAST)) {
                        if (originalChannelId_ == currentChannelId_) {
                            promiseResolved = true;
                            promise_->resolve(std::move(message_));
                            promise_.reset();
                        } else {
                            if (hasInterleavedMessage_) {
                                randomPromise_->resolve(std::move(message_));

                                // Reset Messages
                                message_.reset();
                                messageInProgress_[(int) currentChannelId_].reset();
                            }
                        }
                    } else {
                        // First or Middle... Store message in messages...
                        if (originalChannelId_ != currentChannelId_) {
                            messageInProgress_[(int) currentChannelId_] = std::move(message_);
                        }
                    }
                }

                // Reset message_
                if (originalChannelId_ != currentChannelId_) {
                    // Recover Existing Channel Message
                    auto originalMessage = messageInProgress_.find((int) originalChannelId_);
                    if (originalMessage != messageInProgress_.end()) {
                        message_ = std::move(originalMessage->second);
                    }
                }

                // Then receive next header...
                if (!promiseResolved) {
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
