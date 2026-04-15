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

#include <list>
#include <QObject>
#include <QThread>
#include <QtGlobal>
#include <aasdk/USB/IUSBHub.hpp>
#include <aasdk/USB/IAccessoryModeQueryChainFactory.hpp>


namespace aasdk::usb {

  class IUSBWrapper;

  class USBHub : public QObject, public IUSBHub, public std::enable_shared_from_this<USBHub> {
    Q_OBJECT
    Q_DISABLE_COPY(USBHub)
  public:
    USBHub(IUSBWrapper &usbWrapper, IAccessoryModeQueryChainFactory &queryChainFactory);
    ~USBHub() override;

    void start(Promise::Pointer promise) override;

    void cancel() override;

  private:
    typedef std::list<IAccessoryModeQueryChain::Pointer> QueryChainQueue;
    using std::enable_shared_from_this<USBHub>::shared_from_this;

    void handleDevice(libusb_device *device);

    bool isAOAPDevice(const libusb_device_descriptor &deviceDescriptor) const;

    static int hotplugEventsHandler(libusb_context *usbContext, libusb_device *device, libusb_hotplug_event event,
                                    void *userData);

    IUSBWrapper &usbWrapper_;
    IAccessoryModeQueryChainFactory &queryChainFactory_;
    Promise::Pointer hotplugPromise_;
    Pointer self_;
    HotplugCallbackHandle hotplugHandle_;
    QueryChainQueue queryChainQueue_;
    QThread workerThread_;

    static constexpr uint16_t cGoogleVendorId = 0x18D1;
    static constexpr uint16_t cAOAPId = 0x2D00;
    static constexpr uint16_t cAOAPWithAdbId = 0x2D01;
  };

}
