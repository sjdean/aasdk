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

#include <QFuture>
#include <QPromise>
#include <QObject>
#include <memory>
#include <functional>
#include <exception>
#include <aasdk/Error/Error.hpp>

namespace aasdk {
namespace io {

template<typename ResolveArgumentType, typename ErrorArgumentType = error::Error>
class QtPromise {
public:
    using ValueType = ResolveArgumentType;
    using ErrorType = ErrorArgumentType;
    using ResolveHandler = std::function<void(ResolveArgumentType)>;
    using RejectHandler = std::function<void(ErrorArgumentType)>;
    using Pointer = std::shared_ptr<QtPromise>;

    static Pointer defer(QObject* context = nullptr) {
        return std::make_shared<QtPromise>(context);
    }

    explicit QtPromise(QObject* context) : context_(context) {
        promise_.start();
    }

    QFuture<ResolveArgumentType> future() const {
        return promise_.future();
    }

    void then(ResolveHandler resolveHandler, RejectHandler rejectHandler = RejectHandler()) {
        auto fut = future();
        if (context_) {
            auto fut2 = fut.then(context_, [resolveHandler](ResolveArgumentType val) {
                if (resolveHandler) resolveHandler(std::move(val));
            });
            if (rejectHandler) {
                fut2.onFailed(context_, [rejectHandler](const ErrorArgumentType& e) {
                    rejectHandler(e);
                });
            }
        } else {
            auto fut2 = fut.then([resolveHandler](ResolveArgumentType val) {
                if (resolveHandler) resolveHandler(std::move(val));
            });
            if (rejectHandler) {
                fut2.onFailed([rejectHandler](const ErrorArgumentType& e) {
                    rejectHandler(e);
                });
            }
        }
    }

    void resolve(ResolveArgumentType argument) {
        promise_.addResult(std::move(argument));
        promise_.finish();
    }

    void reject(ErrorArgumentType error) {
        promise_.setException(std::make_exception_ptr(error));
        promise_.finish();
    }

private:
    QPromise<ResolveArgumentType> promise_;
    QObject* context_;
};

// Void resolution specialisation
template<typename ErrorArgumentType>
class QtPromise<void, ErrorArgumentType> {
public:
    using ErrorType = ErrorArgumentType;
    using ResolveHandler = std::function<void()>;
    using RejectHandler = std::function<void(ErrorArgumentType)>;
    using Pointer = std::shared_ptr<QtPromise>;

    static Pointer defer(QObject* context = nullptr) {
        return std::make_shared<QtPromise>(context);
    }

    explicit QtPromise(QObject* context) : context_(context) {
        promise_.start();
    }

    QFuture<void> future() const {
        return promise_.future();
    }

    void then(ResolveHandler resolveHandler, RejectHandler rejectHandler = RejectHandler()) {
        auto fut = future();
        if (context_) {
            auto fut2 = fut.then(context_, [resolveHandler]() {
                if (resolveHandler) resolveHandler();
            });
            if (rejectHandler) {
                fut2.onFailed(context_, [rejectHandler](const ErrorArgumentType& e) {
                    rejectHandler(e);
                });
            }
        } else {
            auto fut2 = fut.then([resolveHandler]() {
                if (resolveHandler) resolveHandler();
            });
            if (rejectHandler) {
                fut2.onFailed([rejectHandler](const ErrorArgumentType& e) {
                    rejectHandler(e);
                });
            }
        }
    }

    void resolve() {
        promise_.finish();
    }

    void reject(ErrorArgumentType error) {
        promise_.setException(std::make_exception_ptr(error));
        promise_.finish();
    }

private:
    QPromise<void> promise_;
    QObject* context_;
};

// Void resolution, Void error specialisation
template<>
class QtPromise<void, void> {
public:
    using ResolveHandler = std::function<void()>;
    using RejectHandler = std::function<void()>;
    using Pointer = std::shared_ptr<QtPromise>;

    static Pointer defer(QObject* context = nullptr) {
        return std::make_shared<QtPromise>(context);
    }

    explicit QtPromise(QObject* context) : context_(context) {
        promise_.start();
    }

    QFuture<void> future() const {
        return promise_.future();
    }

    void then(ResolveHandler resolveHandler, RejectHandler rejectHandler = RejectHandler()) {
        auto fut = future();
        if (context_) {
            auto fut2 = fut.then(context_, [resolveHandler]() {
                if (resolveHandler) resolveHandler();
            });
            if (rejectHandler) {
                // Qt 6 QFuture can't catch "void" exceptions, we use a custom dummy exception
                fut2.onFailed(context_, [rejectHandler](const std::exception&) {
                    rejectHandler();
                });
            }
        } else {
            auto fut2 = fut.then([resolveHandler]() {
                if (resolveHandler) resolveHandler();
            });
            if (rejectHandler) {
                fut2.onFailed([rejectHandler](const std::exception&) {
                    rejectHandler();
                });
            }
        }
    }

    void resolve() {
        promise_.finish();
    }

    void reject() {
        promise_.setException(std::make_exception_ptr(std::runtime_error("Promise rejected")));
        promise_.finish();
    }

private:
    QPromise<void> promise_;
    QObject* context_;
};

// T resolution, Void error specialisation
template<typename ResolveArgumentType>
class QtPromise<ResolveArgumentType, void> {
public:
    using ValueType = ResolveArgumentType;
    using ResolveHandler = std::function<void(ResolveArgumentType)>;
    using RejectHandler = std::function<void()>;
    using Pointer = std::shared_ptr<QtPromise>;

    static Pointer defer(QObject* context = nullptr) {
        return std::make_shared<QtPromise>(context);
    }

    explicit QtPromise(QObject* context) : context_(context) {
        promise_.start();
    }

    QFuture<ResolveArgumentType> future() const {
        return promise_.future();
    }

    void then(ResolveHandler resolveHandler, RejectHandler rejectHandler = RejectHandler()) {
        auto fut = future();
        if (context_) {
            auto fut2 = fut.then(context_, [resolveHandler](ResolveArgumentType val) {
                if (resolveHandler) resolveHandler(std::move(val));
            });
            if (rejectHandler) {
                fut2.onFailed(context_, [rejectHandler](const std::exception&) {
                    rejectHandler();
                });
            }
        } else {
            auto fut2 = fut.then([resolveHandler](ResolveArgumentType val) {
                if (resolveHandler) resolveHandler(std::move(val));
            });
            if (rejectHandler) {
                fut2.onFailed([rejectHandler](const std::exception&) {
                    rejectHandler();
                });
            }
        }
    }

    void resolve(ResolveArgumentType argument) {
        promise_.addResult(std::move(argument));
        promise_.finish();
    }

    void reject() {
        promise_.setException(std::make_exception_ptr(std::runtime_error("Promise rejected")));
        promise_.finish();
    }

private:
    QPromise<ResolveArgumentType> promise_;
    QObject* context_;
};

} // namespace io
} // namespace aasdk
