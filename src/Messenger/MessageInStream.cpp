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

            void MessageInStream::receiveFrameHeaderHandler(const common::DataConstBuffer& buffer)
            {
                FrameHeader frameHeader(buffer);
                currentChannelId_ = frameHeader.getChannelId();
                encryptionType_ = frameHeader.getEncryptionType();
                messageType_ = frameHeader.getMessageType();

                if(message_ == nullptr)
                {
                    message_ = std::make_shared<Message>(frameHeader.getChannelId(), frameHeader.getEncryptionType(), frameHeader.getMessageType());
                    originalChannelId_ = frameHeader.getChannelId();
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
                bool hasInterleavedMessage = false;
                bool promiseResolved = false;

                if (originalChannelId_ != currentChannelId_) {
                    AASDK_LOG(error) << "[MessageInStream] Interleaved ";
                    AASDK_LOG(error) << "[MessageInStream] Channel Id: " << (int) currentChannelId_;
                    AASDK_LOG(error) << "[MessageInStream] Encryption Type: " << (int) encryptionType_;
                    AASDK_LOG(error) << "[MessageInStream] Frame Type: " << (int) recentFrameType_;
                    AASDK_LOG(error) << "[MessageInStream] Message Type: " << (int) messageType_;

                    AASDK_LOG(error) << "[MessageInStream] Storing original message. ";
                    // Store Old Message for Safe Keeping
                    messageInProgress_[(int) originalChannelId_] = std::move(message_);

                    if (recentFrameType_ == FrameType::FIRST || recentFrameType_ == FrameType::BULK) {
                        AASDK_LOG(error) << "[MessageInStream] First or Bulk. Creating New Message. ";
                        // Create a New Message. If we had data, then it will be lost, because that's how FIRST and BULK FRAMES work.
                        message_ = std::make_shared<Message>(currentChannelId_, encryptionType_, messageType_);
                        hasInterleavedMessage = true;
                    } else {
                        AASDK_LOG(error) << "[MessageInStream] Middle or Last. Finding Existing Message. ";
                        // If this however is a MIDDLE or LAST message, then try to find any existing messages.
                        auto interleavedMessage = messageInProgress_.find((int) currentChannelId_);
                        if (interleavedMessage != messageInProgress_.end()) {
                            AASDK_LOG(error) << "[MessageInStream] Found Message. ";
                            // If it's not first or bulk, then it's middle or last...
                            hasInterleavedMessage = true;
                            message_ = std::move(interleavedMessage->second);
                        }
                    }
                }

                // Process the message as normal...
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
                        if (hasInterleavedMessage) {
                            AASDK_LOG(error) << "[MessageInStream] Interleaved. Not doing anything (yet). ";
                            // TODO: Send Back Temporary Message
                        }
                    }
                }

                // Reset Message
                if (originalChannelId_ != currentChannelId_) {
                    // Reset Message
                    AASDK_LOG(error) << "[MessageInStream] Loading Message from Original Channel Id. ";
                    auto originalMessage = messageInProgress_.find((int) originalChannelId_);
                    if (originalMessage != messageInProgress_.end()) {
                        AASDK_LOG(error) << "[MessageInStream] Found original message. ";
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
