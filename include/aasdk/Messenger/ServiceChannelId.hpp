#include <aasdk/messenger/ServiceId.hpp>
#include <aasdk/messenger/ChannelId.hpp>

namespace aasdk::messenger {
  struct ServiceChannelId {
    ServiceId serviceId;
    std::optional <ChannelId> channelId; // optional to indicate if it's just a service or a channel within a service

    bool operator==(const ServiceChannelId &other) const {
      return serviceId == other.serviceId && channelId == other.channelId;
    }
  };
}

namespace std {
  template<>
  struct hash<aasdk::messenger::ServiceChannelId> {
    std::size_t operator()(const aasdk::messenger::ServiceChannelId &id) const {
      std::size_t h1 = std::hash<aasdk::messenger::ServiceId>{}(id.serviceId);
      std::size_t h2 = id.channelId.has_value() ? std::hash<aasdk::messenger::ChannelId>{}(*id.channelId) : 0;
      return h1 ^ (h2 + 0x9e3779b9 + (h1 << 6) + (h1 >> 2));
    }
  };
}