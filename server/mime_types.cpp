//
// mime_types.cpp
// ~~~~~~~~~~~~~~
//
// Copyright (c) 2003-2019 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include "mime_types.hpp"
#include <algorithm>
#include <iostream>

namespace http {
namespace server {
namespace mime_types {

struct mapping
{
  std::string extension;
  std::string mime_type;
} mappings[] =
{
  { "gif", "image/gif" },
  { "htm", "text/html" },
  { "html", "text/html" },
  { "jpg", "image/jpeg" },
  { "jpeg", "image/jpeg" },
  { "png", "image/png" },
  { "txt", "text/plain" },
  { "pdf", "application/pdf"}
};

std::string extension_to_type(std::string extension)
{
  std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
  std::cout << extension << std::endl;
  for (mapping m: mappings)
  {
    if (extension.size() >= m.extension.size() && extension.compare(extension.size() - m.extension.size(), m.extension.size(), m.extension) == 0)
    {
      return m.mime_type;
    }
  }

  return "text/plain";
}

} // namespace mime_types
} // namespace server
} // namespace http
