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

#include <aasdk/TCP/QtTCPEndpoint.hpp>
#include <aasdk/Error/Error.hpp>
#include <algorithm>

namespace aasdk {
namespace tcp {

QtTCPEndpoint::QtTCPEndpoint(std::shared_ptr<QTcpSocket> socket, QObject* parent)
    : QObject(parent), socket_(std::move(socket)) {
    pendingSend_.promise = nullptr;
    pendingSend_.bytesWrittenSoFar = 0;

    pendingReceive_.promise = nullptr;
    pendingReceive_.bytesReadSoFar = 0;

    connect(socket_.get(), &QTcpSocket::bytesWritten, this, &QtTCPEndpoint::onBytesWritten);
    connect(socket_.get(), &QTcpSocket::readyRead, this, &QtTCPEndpoint::onReadyRead);
#if QT_VERSION >= QT_VERSION_CHECK(5, 15, 0)
    connect(socket_.get(), &QAbstractSocket::errorOccurred, this, &QtTCPEndpoint::onErrorOccurred);
#else
    connect(socket_.get(), QOverload<QAbstractSocket::SocketError>::of(&QAbstractSocket::error), this, &QtTCPEndpoint::onErrorOccurred);
#endif
}

QtTCPEndpoint::~QtTCPEndpoint() {
    stop();
}

void QtTCPEndpoint::send(common::DataConstBuffer buffer, Promise::Pointer promise) {
    if (pendingSend_.promise) {
        promise->reject(error::Error(error::ErrorCode::OPERATION_IN_PROGRESS));
        return;
    }

    pendingSend_.buffer = buffer;
    pendingSend_.promise = std::move(promise);
    pendingSend_.bytesWrittenSoFar = 0;

    qint64 written = socket_->write(reinterpret_cast<const char*>(buffer.cdata), buffer.size);
    if (written < 0) {
        auto p = std::move(pendingSend_.promise);
        pendingSend_.promise = nullptr;
        p->reject(error::Error(error::ErrorCode::TCP_TRANSFER, static_cast<uint32_t>(socket_->error())));
    }
}

void QtTCPEndpoint::receive(common::DataBuffer buffer, Promise::Pointer promise) {
    if (pendingReceive_.promise) {
        promise->reject(error::Error(error::ErrorCode::OPERATION_IN_PROGRESS));
        return;
    }

    pendingReceive_.buffer = buffer;
    pendingReceive_.promise = std::move(promise);
    pendingReceive_.bytesReadSoFar = 0;

    if (socket_->bytesAvailable() > 0) {
        onReadyRead();
    }
}

void QtTCPEndpoint::stop() {
    socket_->disconnectFromHost();

    if (pendingSend_.promise) {
        auto promise = std::move(pendingSend_.promise);
        pendingSend_.promise = nullptr;
        promise->reject(error::Error(error::ErrorCode::OPERATION_ABORTED));
    }

    if (pendingReceive_.promise) {
        auto promise = std::move(pendingReceive_.promise);
        pendingReceive_.promise = nullptr;
        promise->reject(error::Error(error::ErrorCode::OPERATION_ABORTED));
    }
}

void QtTCPEndpoint::onBytesWritten(qint64 bytes) {
    if (!pendingSend_.promise) {
        return;
    }

    pendingSend_.bytesWrittenSoFar += bytes;
    if (pendingSend_.bytesWrittenSoFar >= pendingSend_.buffer.size) {
        auto promise = std::move(pendingSend_.promise);
        pendingSend_.promise = nullptr;
        promise->resolve(pendingSend_.bytesWrittenSoFar);
    }
}

void QtTCPEndpoint::onReadyRead() {
    if (!pendingReceive_.promise) {
        return;
    }

    size_t remaining = pendingReceive_.buffer.size - pendingReceive_.bytesReadSoFar;
    qint64 bytesToRead = std::min<qint64>(static_cast<qint64>(remaining), socket_->bytesAvailable());
    
    if (bytesToRead > 0) {
        qint64 read = socket_->read(reinterpret_cast<char*>(pendingReceive_.buffer.data) + pendingReceive_.bytesReadSoFar, bytesToRead);
        if (read > 0) {
            pendingReceive_.bytesReadSoFar += read;
        } else if (read < 0) {
            auto promise = std::move(pendingReceive_.promise);
            pendingReceive_.promise = nullptr;
            promise->reject(error::Error(error::ErrorCode::TCP_TRANSFER, static_cast<uint32_t>(socket_->error())));
            return;
        }
    }

    if (pendingReceive_.bytesReadSoFar >= pendingReceive_.buffer.size) {
        auto promise = std::move(pendingReceive_.promise);
        pendingReceive_.promise = nullptr;
        promise->resolve(pendingReceive_.bytesReadSoFar);
    }
}

void QtTCPEndpoint::onErrorOccurred(QAbstractSocket::SocketError socketError) {
    if (pendingSend_.promise) {
        auto promise = std::move(pendingSend_.promise);
        pendingSend_.promise = nullptr;
        promise->reject(error::Error(error::ErrorCode::TCP_TRANSFER, static_cast<uint32_t>(socketError)));
    }

    if (pendingReceive_.promise) {
        auto promise = std::move(pendingReceive_.promise);
        pendingReceive_.promise = nullptr;
        promise->reject(error::Error(error::ErrorCode::TCP_TRANSFER, static_cast<uint32_t>(socketError)));
    }
}

} // namespace tcp
} // namespace aasdk