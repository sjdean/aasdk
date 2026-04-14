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

#pragma once

#include <QObject>
#include <QTcpSocket>
#include <memory>
#include <aasdk/TCP/ITCPEndpoint.hpp>

namespace aasdk {
namespace tcp {

class QtTCPEndpoint : public QObject, public ITCPEndpoint, public std::enable_shared_from_this<QtTCPEndpoint> {
    Q_OBJECT

public:
    explicit QtTCPEndpoint(std::shared_ptr<QTcpSocket> socket, QObject* parent = nullptr);
    ~QtTCPEndpoint() override;

    void send(common::DataConstBuffer buffer, Promise::Pointer promise) override;
    void receive(common::DataBuffer buffer, Promise::Pointer promise) override;
    void stop() override;

private slots:
    void onBytesWritten(qint64 bytes);
    void onReadyRead();
    void onErrorOccurred(QAbstractSocket::SocketError socketError);

private:
    std::shared_ptr<QTcpSocket> socket_;

    struct PendingSend {
        common::DataConstBuffer buffer;
        Promise::Pointer promise;
        size_t bytesWrittenSoFar;
    };

    struct PendingReceive {
        common::DataBuffer buffer;
        Promise::Pointer promise;
        size_t bytesReadSoFar;
    };

    PendingSend pendingSend_;
    PendingReceive pendingReceive_;
};

} // namespace tcp
} // namespace aasdk
