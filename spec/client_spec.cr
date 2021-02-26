require "./spec_helper"

module CoAP
  describe CoAP do
    it "should generate a basic coap request" do
      request = CoAP::Request.new("get", "/testing", HTTP::Headers{
        "Origin" => "coap://test.server.com",
      })
      message = request.to_coap

      message.type.should eq(Message::Type::Confirmable)
      message.code_class.should eq(CodeClass::Method)
      message.code_detail.should eq(MethodCode::GET.to_i)
      message.message_id.should eq(0_u16)
      message.token.size.should eq(0)
      message.payload_data.size.should eq(0)

      message.options.select { |opt| opt.type == Options::Uri_Host }.first.string.should eq("test.server.com")
      message.options.select { |opt| opt.type == Options::Uri_Port }.first.uri_port.should eq(5683)
      message.options.select { |opt| opt.type == Options::Uri_Path }.first.string.should eq("/testing")
      message.options.select { |opt| opt.type == Options::Uri_Query }.empty?.should eq(true)
    end

    it "should generate a complex coap request" do
      request = CoAP::Request.new("post", "/testing?arg=1", HTTP::Headers{
        "Origin"         => "coaps://test.server.com",
        "Content-Format" => "application/json",
      }, %({"temp": "22.5 C"}))
      request.message_id = 2_u16
      message = request.to_coap

      message.type.should eq(Message::Type::Confirmable)
      message.code_class.should eq(CodeClass::Method)
      message.code_detail.should eq(MethodCode::POST.to_i)
      message.message_id.should eq(2_u16)
      message.token.size.should eq(0)
      String.new(message.payload_data).should eq %({"temp": "22.5 C"})

      message.options.select { |opt| opt.type == Options::Uri_Host }.first.string.should eq("test.server.com")
      message.options.select { |opt| opt.type == Options::Uri_Port }.first.uri_port.should eq(5684)
      message.options.select { |opt| opt.type == Options::Uri_Path }.first.string.should eq("/testing")
      message.options.select { |opt| opt.type == Options::Uri_Query }.first.string.should eq("arg=1")
      message.options.select { |opt| opt.type == Options::Content_Format }.first.content_type.should eq("application/json")
    end

    it "should generate a response object based on a CoAP message" do
      io = IO::Memory.new
      io.write(Bytes[97, 69, 188, 144, 113, 68])
      io << "abcd"
      io.write_byte(0xFF_u8)
      io << "temp = 22.5 C"
      io.rewind
      msg = io.read_bytes(Message)

      response = CoAP::Response.from_coap(msg)
      response.status_code.should eq(205)
      response.message_id.should eq(0xBC90)
      String.new(response.token).should eq("q")
      response.headers["ETag"].should eq("abcd")
      response.body.should eq("temp = 22.5 C")
    end
  end
end
