require "bindata"

module CoAP
  enum CodeClass
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
end

require "./message"
