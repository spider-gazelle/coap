require "bindata"
require "log"
require "uri"

URI.set_default_port "coap", 5683
URI.set_default_port "coaps", 5684

module CoAP
  Log = ::Log.for("coap")

  enum CodeClass
    # Method == request such as Get post etc defined below
    Method      = 0
    Success     = 2
    ClientError = 4
    ServerError = 5
    Signaling   = 7
  end

  enum MethodCode
    GET    = 1
    POST
    PUT
    DELETE
    FETCH
    PATCH
    IPATCH
  end

  # https://tools.ietf.org/html/rfc7252#section-5.10
  enum Options
    If_Match       =  1
    Uri_Host       =  3
    ETag           =  4
    If_None_Match  =  5
    # https://tools.ietf.org/html/rfc7641
    Observe        =  6
    Uri_Port       =  7
    Location_Path  =  8
    Uri_Path       = 11
    Content_Format = 12
    Max_Age        = 14
    Uri_Query      = 15
    Accept         = 17
    Location_Query = 20
    # https://tools.ietf.org/html/rfc7959#section-1
    Block2         = 23
    Block1         = 27
    Proxy_Uri      = 35
    Proxy_Scheme   = 39
    Size1          = 60
  end

  CONTENT_FORMAT = {} of String => UInt16
  LOOKUP_FORMAT  = {} of UInt16 => String

  def self.register_format(name : String, number : UInt16)
    name = name.split(';')[0]

    CONTENT_FORMAT[name] = number
    LOOKUP_FORMAT[number] = name
  end

  {
     0_u16 => "text/plain",
    40_u16 => "application/link-format",
    41_u16 => "application/xml",
    42_u16 => "application/octet-stream",
    47_u16 => "application/exi",
    50_u16 => "application/json",
    60_u16 => "application/cbor",
  }.each { |number, name| register_format(name, number) }
end

require "./message"
require "./client"
