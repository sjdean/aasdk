# Promise Audit

## Overview
This document maps every `io::Promise<T, E>` specialisation in use across `aasdk` and `openauto`, along with the planned Qt replacements.

## Promise Specialisations

### aasdk

1. **`io::Promise<size_t>`**
   - **Locations:** `ITCPEndpoint`, `IUSBEndpoint`
   - **Usage:** Tracking bytes transferred in async read/write operations.
   - **Qt Equivalent:** `QFuture<size_t>`

2. **`io::Promise<bool>`**
   - **Locations:** `IConnectedAccessoriesEnumerator`
   - **Usage:** Tracking enumeration completion.
   - **Qt Equivalent:** `QFuture<bool>`

3. **`io::Promise<DeviceHandle>`**
   - **Locations:** `IUSBHub`, `IAccessoryModeQueryChain`
   - **Usage:** Returning a handle to an opened USB device.
   - **Qt Equivalent:** `QFuture<DeviceHandle>`

4. **`io::Promise<IUSBEndpoint::Pointer>`**
   - **Locations:** `IAccessoryModeQuery`
   - **Usage:** Returning the active endpoint.
   - **Qt Equivalent:** `QFuture<IUSBEndpoint::Pointer>`

5. **`io::Promise<void>`** (Defaults to `Error` for the rejection type)
   - **Locations:** `ITransport::SendPromise`, `IMessenger::SendPromise`, `Channel::SendPromise`, `IPinger`
   - **Usage:** Completion notification for send operations.
   - **Qt Equivalent:** `QFuture<void>`

6. **`io::Promise<common::Data>`**
   - **Locations:** `ITransport::ReceivePromise`
   - **Usage:** Returning received data chunks from the transport layer.
   - **Qt Equivalent:** `QFuture<common::Data>`

7. **`io::Promise<Message::Pointer>`**
   - **Locations:** `IMessenger::ReceivePromise`
   - **Usage:** Returning a fully demuxed and decoded message to a channel.
   - **Qt Equivalent:** `QFuture<Message::Pointer>`

### openauto

8. **`io::Promise<void, void>`**
   - **Locations:** `StartPromise` and `PairingPromise`
   - **Usage:** Signalling that an operation (like audio recording start or BT pairing) has completed.
   - **Qt Equivalent:** `QFuture<void>`

9. **`io::Promise<common::Data, void>`**
   - **Locations:** `ReadPromise`
   - **Usage:** Reading audio data in `IAudioInput`.
   - **Qt Equivalent:** `QFuture<common::Data>`

## Error Handling Map
`io::Promise` handles errors via the `reject()` method, passing an error type (usually `aasdk::error::Error`). 

In Qt 6, `QFuture` can propagate exceptions via `QPromise::setException`. However, since we avoid exceptions for standard control flow, non-void error scenarios will likely require a structural approach:
- We will construct a `QtPromise<T>` bridging class that emulates the `.then(resolveHandler, rejectHandler)` flow to simplify the migration without requiring C++23 `std::expected`.
- The custom `QtPromise` will wrap `QPromise<T>` but provide the familiar two-callback structure.
