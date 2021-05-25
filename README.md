# Crystal Lang CoAP Protocol

[![CI](https://github.com/spider-gazelle/coap/actions/workflows/ci.yml/badge.svg)](https://github.com/spider-gazelle/coap/actions/workflows/ci.yml)

Communicate with IoT devices supporting CoAP

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     coap:
       github: spider-gazelle/coap
   ```

2. Run `shards install`


## Usage

```crystal

require "coap"

# client has similar semantics to HTTP::Client
client = CoAP::Client.new(URI.parse("coap://coap.me"))

# requests inherit from HTTP::Request so work the same way
request = CoAP::Request.new("get", "/test")

# use client.exec! to send a request, it returns a channel for obtaining responses
# this is because you can multi-cast requests and each device will send a response
response_channel = client.exec!(request)

# you might only be expecting a single response
response = response_channel.receive

response.status_code # => 205
response.headers["Content-Format"] # => "text/plain"
response.body # => "welcome to the ETSI plugtest!"

```
