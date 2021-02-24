require "bindata"

module CoAP
  enum CodeClass
    # Method == request such as Get post etc defined below
    Method      = 0
    Success     = 2
    ClientError = 4
    ServerError = 5
    Signaling   = 7
  end

  enum MethodCode
    Get    = 1
    Post
    Put
    Delete
    Fetch
    Patch
    IPatch
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
end

require "./message"
