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

      message.options.find { |opt| opt.type == Options::Uri_Host }.try &.string.should eq("test.server.com")
      message.options.find { |opt| opt.type == Options::Uri_Path }.try &.string.should eq("testing")
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

      message.options.find { |opt| opt.type == Options::Uri_Host }.try &.string.should eq("test.server.com")
      message.options.find { |opt| opt.type == Options::Uri_Path }.try &.string.should eq("testing")
      message.options.find { |opt| opt.type == Options::Uri_Query }.try &.string.should eq("arg=1")
      message.options.find { |opt| opt.type == Options::Content_Format }.try &.content_type.should eq("application/json")
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
      response.headers["ETag"].should eq("61626364")
      response.body.should eq("temp = 22.5 C")
    end

    it "should parse a COAP response" do
      io = IO::Memory.new
      io.write "60453e1c485fba79aceb7cf5ef80ff77656c636f6d6520746f20746865204554534920706c75677465737421206c617374206368616e67653a20323032312d30322d32382031333a33313a323820555443".hexbytes
      io.rewind

      msg = io.read_bytes(Message)
      response = CoAP::Response.from_coap(msg)
      response.status_code.should eq(205)
      response.message_id.should eq(15900_u16)
      response.headers["ETag"].should eq("5fba79aceb7cf5ef")
      response.headers["Content-Format"].should eq("text/plain")
      response.body.should eq("welcome to the ETSI plugtest! last change: 2021-02-28 13:31:28 UTC")
    end

    it "should make a coap request" do
      client = CoAP::Client.new(URI.parse("coap://coap.me"))
      response = client.exec(CoAP::Request.new("get", "/test"))

      response.status_code.should eq(205)
      response.headers["Content-Format"].should eq("text/plain")
      response.body.should start_with("welcome to the ETSI plugtest!")
    end
  end
end
