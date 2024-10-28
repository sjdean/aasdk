#include <aasdk/Messenger/ServiceId.hpp>

namespace aasdk
{
  namespace messenger
  {
    std::string serviceIdToString(ServiceId serviceId)
    {
      switch(serviceId)
      {
        case ServiceId::CONTROL:
          return "CONTROL";
        case ServiceId::SENSOR:
          return "SENSOR";
        case ServiceId::MEDIA_SINK:
          return "MEDIA_SINK";
        case ServiceId::INPUT_SOURCE:
          return "INPUT_SOURCE";
        case ServiceId::MEDIA_SOURCE:
          return "MEDIA_SOURCE";
        case ServiceId::BLUETOOTH:
          return "BLUETOOTH";
        case ServiceId::RADIO:
          return "RADIO";
        case ServiceId::NAVIGATION_STATUS:
          return "NAVIGATION_STATUS";
        case ServiceId::MEDIA_PLAYBACK_STATUS:
          return "MEDIA_PLAYBACK_STATUS";
        case ServiceId::PHONE_STATUS:
          return "PHONE_STATUS";
        case ServiceId::MEDIA_BROWSER:
          return "MEDIA_BROWSER";
        case ServiceId::VENDOR_EXTENSION:
          return "VENDOR_EXTENSION";
        case ServiceId::GENERIC_NOTIFICATION:
          return "GENERIC_NOTIFICATION";
        case ServiceId::WIFI_PROJECTION:
          return "WIFI_PROJECTION";
        case ServiceId::NONE:
          return "NONE";
        default:
          return "(null)";
      }
    }

  }
}
