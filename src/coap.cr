require "bindata"
require "log"

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
    Observe        =  6
    Uri_Port       =  7
    Location_Path  =  8
    Uri_Path       = 11
    Content_Format = 12
    Max_Age        = 14
    Uri_Query      = 15
    Accept         = 17
    Location_Query = 20
    Block2         = 23
    Block1         = 27
    Proxy_Uri      = 35
    Proxy_Scheme   = 39
    Size1          = 60
  end

  DEFAULT_PORTS = {
    "coap"  => 5683,
    "coaps" => 5684,
  }
  CONTENT_FORMAT = {} of String => Bytes
  LOOKUP_FORMAT  = {} of Bytes => String

  def self.register_format(name : String, number : UInt8 | UInt16)
    buffer = IO::Memory.new(2)
    buffer.write_bytes(number, IO::ByteFormat::BigEndian)
    bytes = buffer.to_slice
    name = name.split(';')[0]

    CONTENT_FORMAT[name] = bytes
    LOOKUP_FORMAT[bytes] = name
  end

  {
     0_u8 => "text/plain",
    40_u8 => "application/link-format",
    41_u8 => "application/xml",
    42_u8 => "application/octet-stream",
    47_u8 => "application/exi",
    50_u8 => "application/json",
    60_u8 => "application/cbor",
  }.each { |number, name| register_format(name, number) }
end

require "./message"
require "./client"
