require "./spec_helper"

module CoAP
  describe CoAP do
    it "should parse an observation rejection message" do
      io = IO::Memory.new("7000aa0f".hexbytes)
      msg = io.read_bytes(Message)
      msg.version.should eq(1)
      msg.type.should eq(Message::Type::Reset)
      msg.code_class.should eq(CodeClass::Method)
      msg.code_detail.should eq(0)
      msg.message_id.should eq(43535)
      msg.token.empty?.should eq(true)
      msg.options.empty?.should eq(true)
    end

    it "should parse a minimal message" do
      io = IO::Memory.new(Bytes[64, 0, 0, 0])
      msg = io.read_bytes(Message)
      msg.version.should eq(1)
      msg.type.should eq(Message::Type::Confirmable)
      msg.code_class.should eq(CodeClass::Method)
      msg.code_detail.should eq(0)
      msg.message_id.should eq(0)
      msg.token.empty?.should eq(true)
      msg.options.empty?.should eq(true)
    end

    it "should parse integer options" do
      io = IO::Memory.new(Bytes[1, 32])
      msg = io.read_bytes(Option)
      msg.max_age.should eq(32)
      msg.observation.should eq(32)

      msg.max_age 32
      msg.observation 32

      msg.to_slice.should eq(io.to_slice)
    end

    it "should parse content-type options" do
      io = IO::Memory.new(Bytes[1, 42])
      msg = io.read_bytes(Option)
      msg.content_type.should eq("application/octet-stream")
      msg.content_type "application/octet-stream"

      msg.to_slice.should eq(io.to_slice)
    end

    it "should parse a message with content" do
      io = IO::Memory.new
      io.write(Bytes[97, 69, 188, 144, 113, 68])
      io << "abcd"
      io.write_byte(0xFF_u8)
      io << "temp = 22.5 C"
      io.rewind

      msg = io.read_bytes(Message)
      msg.version.should eq(1)
      msg.type.should eq(Message::Type::Acknowledgement)

      # Codes, ref: https://github.com/chrysn/aiocoap/blob/02e18b80e7ffb765cf3f31acb66f77afc5c76cea/aiocoap/numbers/codes.py
      msg.code_class.should eq(CodeClass::Success)
      msg.code_detail.should eq(5) # CONTENT
      msg.status_code.should eq(205)
      msg.status_code = 205
      msg.status = HTTP::Status::RESET_CONTENT

      msg.message_id.should eq(0xBC90)
      String.new(msg.token).should eq("q")
      msg.options.size.should eq(1)
      # etag, ref: https://github.com/chrysn/aiocoap/blob/7441d0e4a3a2c281090970fb55c1f7797fa463db/aiocoap/numbers/optionnumbers.py
      option = msg.options[0]
      option.type.should eq(Options::ETag)
      String.new(option.data).should eq("abcd")
      String.new(msg.payload_data).should eq("temp = 22.5 C")

      # Re-apply the options to ensure our application code works
      msg.options = msg.options

      msg.to_slice.should eq(io.to_slice)
    end
  end
end
