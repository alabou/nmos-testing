#!/usr/bin/env python3
"""
sdp_decode_test.py

This test suite verifies the decoding functionality of the sdp.py module.
It is a translation (with enhancements) of the original Go tests.
"""

import io
import unittest

from MatroxSdp import MatroxSdp, InvalidData, InvalidObject

class TestSdpDecode(unittest.TestCase):
    def test_nmos0(self):
        # List of test cases: (name, SDP text)
        test_cases = [
            ("r1", 
             "v=0\r\n"
             "o=- 1496222842 1496222842 IN IP4 172.29.226.25\r\n"
             "s=IP Studio Stream\r\n"
             "t=0 0\r\n"
             "m=video 5010 RTP/AVP 103\r\n"
             "c=IN IP4 232.250.98.80/32\r\n"
             "a=source-filter: incl IN IP4 232.250.98.80 172.29.226.25\r\n"
             "a=rtpmap:103 raw/90000\r\n"
             "a=fmtp:103 sampling=YCbCr-4:2:2; width=1920; height=1080; depth=10; interlace; exactframerate=25; colorimetry=BT709; PM=2110GPM; SSN=ST2110-20:2017; TP=2110TPW; \r\n"
             "a=mediaclk:direct=1876655126 rate=90000\r\n"
             "a=extmap:1 urn:x-nmos:rtp-hdrext:origin-timestamp\r\n"
             "a=extmap:2 urn:ietf:params:rtp-hdrext:smpte-tc 3600@90000/25\r\n"
             "a=extmap:3 urn:x-nmos:rtp-hdrext:flow-id\r\n"
             "a=extmap:4 urn:x-nmos:rtp-hdrext:source-id\r\n"
             "a=extmap:5 urn:x-nmos:rtp-hdrext:grain-flags\r\n"
             "a=extmap:7 urn:x-nmos:rtp-hdrext:sync-timestamp\r\n"
             "a=extmap:9 urn:x-nmos:rtp-hdrext:grain-duration\r\n"
             "a=ts-refclk:ptp=IEEE1588-2008:08-00-11-FF-FE-21-E1-B0:0\r\n"
            ),
            ("r2",
             "v=0\r\n"
             "o=- 1496222842 1496222842 IN IP4 172.29.226.25\r\n"
             "s=IP Studio Stream\r\n"
             "t=0 0\r\n"
             "m=video 5010 RTP/AVP 103\r\n"
             "c=IN IP4 232.250.98.80/32\r\n"
             "a=source-filter: incl IN IP4 232.250.98.80 172.29.226.25\r\n"
             "a=rtpmap:103 raw/90000\r\n"
             "a=fmtp:103 sampling=YCbCr-4:2:2; width=1920; height=1080; depth=10; interlace; exactframerate=25; colorimetry=BT709; PM=2110GPM; SSN=ST2110-20:2017; TP=2110TPW; \r\n"
             "a=mediaclk:direct=1876655126 rate=90000\r\n"
             "a=extmap:1 urn:x-nmos:rtp-hdrext:origin-timestamp\r\n"
             "a=extmap:2 urn:ietf:params:rtp-hdrext:smpte-tc 3600@90000/25\r\n"
             "a=extmap:3 urn:x-nmos:rtp-hdrext:flow-id\r\n"
             "a=extmap:4 urn:x-nmos:rtp-hdrext:source-id\r\n"
             "a=extmap:5 urn:x-nmos:rtp-hdrext:grain-flags\r\n"
             "a=extmap:7 urn:x-nmos:rtp-hdrext:sync-timestamp\r\n"
             "a=extmap:9 urn:x-nmos:rtp-hdrext:grain-duration\r\n"
             "a=ts-refclk:ptp=IEEE1588-2008:08-00-11-FF-FE-21-E1-B0:0\r\n"
            ),
            ("r3",
             "v=0\n"
             "o=- 2890844526 2890842807 IN IP4 10.47.16.5\n"
             "s=SDP Example\n"
             "c=IN IP4 10.46.16.34/127\n"
             "t=2873397496 2873404696\n"
             "a=recvonly\n"
             "m=video 51372 RTP/AVP 99\n"
             "a=rtpmap:99 h263-1998/90000\n"
            ),
            ("r4",
             "v=0\n"
             "o=- 1497010742 1497010742 IN IP4 172.29.26.24\n"
             "s=SDP Example\n"
             "t=2873397496 2873404696\n"
             "m=video 5000 RTP/AVP 103\n"
             "c=IN IP4 232.21.21.133/32\n"
             "a=source-filter: incl IN IP4 172.29.26.24 172.29.26.24\n"
            ),
            ("r5",
             "v=0\n"
             "o=- 1497010742 1497010742 IN IP4 172.29.26.24\n"
             "s=SDP Example\n"
             "t=2873397496 2873404696\n"
             "m=video 5000 RTP/AVP 103\n"
             "c=IN IP4 239.21.21.133/32\n"
             "a=rtpmap:103 raw/90000\n"
            ),
            ("r7",  # DUP grouping test
             "v=0\n"
             "o=ali 1122334455 1122334466 IN IP4 dup.example.com\n"
             "s=DUP Grouping Semantics\n"
             "t=0 0\n"
             "a=group:DUP S1a S1b\n"
             "m=video 30000 RTP/AVP 100\n"
             "c=IN IP4 233.252.0.1/127\n"
             "a=source-filter: incl IN IP4 233.252.0.1 198.51.100.1\n"
             "a=rtpmap:100 MP2T/90000\n"
             "a=mid:S1a\n"
             "m=video 30000 RTP/AVP 101\n"
             "c=IN IP4 233.252.0.2/127\n"
             "a=source-filter: incl IN IP4 233.252.0.2 198.51.100.1\n"
             "a=rtpmap:101 MP2T/90000\n"
             "a=mid:S1b\n"
            ),
            ("r8",
             "v=0\n"
             "o=- 1497010742 1497010742 IN IP4 172.29.26.24\n"
             "s=SDP Example\n"
             "t=2873397496 2873404696\n"
             "m=video 5000 RTP/AVP 103\n"
             "c=IN IP4 232.21.21.133/32\n"
             "a=source-filter: incl IN IP4 232.21.21.133 172.29.226.24\n"
             "a=rtpmap:103 raw/90000\n"
             "a=rtcp:5001 IN IP4 232.21.21.133\n"
            ),
            ("r9",
             "v=0\n"
             "o=- 3826217993 3826217993 IN IP4 10.xx.xxx.198\n"
             "s=AWS Elemental SMPTE 2110 Output: [LiveEvent: 13] [OutputGroup: smpte_2110] [EssenceType_ID: 2110-20_video_198]\n"
             "t=0 0\n"
             "m=video 50000 RTP/AVP 96\n"
             "c=IN IP4 239.x.x.x/64\n"
             "b=AS:2568807\n"
             "a=source-filter: incl IN IP4 239.x.x.x 10.xx.xxx.2\n"
             "a=rtpmap:96 raw/90000\n"
             "a=fmtp:96 sampling=YCbCr-4:2:2; width=1920; height=1080; exactframerate=60; depth=10; TCS=SDR; colorimetry=BT709; interlace; PM=2110GPM; SSN=ST2110-20:2017; TP=2110TPN; PAR=1:1;\n"
             "a=mediaclk:direct=0\n"
             "a=ts-refclk:localmac=1c-34-da-5a-be-34\n"
            ),
            ("r10",
             "v=0\n"
             "o=- 1443716955 1443716955 IN IP4 10.xx.xxx.236\n"
             "s=st2110 0-1-0\n"
             "t=0 0\n"
             "m=audio 20000 RTP/AVP 97\n"
             "c=IN IP4 239.x.x.x/64\n"
             "a=source-filter: incl IN IP4 239.x.x.x 10.xx.xxx.236\n"
             "a=rtpmap:97 L24/48000/2\n"
             "a=mediaclk:direct=0 rate=48000\n"
             "a=framecount:48\n"
             "a=ptime:1\n"
             "a=ts-refclk:ptp=IEEE1588-2008:04-5c-6c-ff-fe-0a-53-70:127\n"
            ),
            ("r11",
             "v=0\n"
             "o=- 1443716955 1443716955 IN IP4 10.xx.xxx.236\n"
             "s=st2110 0-9-0\n"
             "t=0 0\n"
             "m=video 20000 RTP/AVP 100\n"
             "c=IN IP4 239.x.x.xx/64\n"
             "a=source-filter: incl IN IP4 239.x.x.xx 10.xx.xxx.236\n"
             "a=rtpmap:100 smpte291/90000\n"
             "a=fmtp:100 VPID_Code=133;\n"
             "a=mediaclk:direct=0 rate=90000\n"
             "a=ts-refclk:ptp=IEEE1588-2008:04-5c-6c-ff-fe-0a-53-70:127\n"
            ),
            ("r12",
             "v=0\n"
             "o=- 456221445 456221445 IN IP4 203.x.xxx.252\n"
             "s=AJA Lily10G2-SDI 2110\n"
             "t=0 0\n"
             "a=group:DUP 1 2\n"
             "m=video 20000 RTP/AVP 96\n"
             "c=IN IP4 10.24.34.0/24\n"
             "a=source-filter:incl IN IP4 192.x.x.1 198.xx.xxx.252\n"
             "a=rtpmap:96 raw/90000\n"
             "a=fmtp:96 sampling=YCbCr-4:2:2; width=1920; height=1080; exactframerate=30000/1001; depth=10; TCS=SDR; colorimetry=BT709; PM=2110GPM; SSN=ST2110-20:2017; TP=2110TPN; interlace=1; a=ts-refclk:ptp=IEEE1588-2008:00-90-56-FF-FE-08-0F-45\n"
             "a=mediaclk:direct=0\n"
             "a=mid:1\n"
             "m=video 20000 RTP/AVP 96\n"
             "c=IN IP4 10.24.34.0/24\n"
             "a=source-filter:incl IN IP4 192.x.x.3 1198.xx.xxx.253\n"
             "a=rtpmap:96 raw/90000\n"
             "a=fmtp:96 sampling=YCbCr-4:2:2; width=1920; height=1080; exactframerate=30000/1001; depth=10; TCS=SDR; colorimetry=BT709; PM=2110GPM; SSN=ST2110-20:2017; TP=2110TPN; interlace=1;\n"
             "a=ts-refclk:ptp=IEEE1588-2008:00-90-56-FF-FE-08-0F-45\n"
             "a=mediaclk:direct=0\n"
             "a=mid:2\n"
            ),
            ("r13",
             "v=0\n"
             "o=- 1543226715 1543226715 IN IP4 10.162.0.3\n"
             "s=Demo Video Stream\n"
             "t=0 0\n"
             "m=video 5306 RTP/AVP 97\n"
             "c=IN IP4 232.40.50.35/32\n"
             "a=source-filter: incl IN IP4 232.40.50.35 10.162.0.3\n"
             "a=ts-refclk:ptp=IEEE1588-2008:EC-46-70-FF-FE-00-CE-DE:0\n"
             "a=rtpmap:97 raw/90000\n"
             "a=fmtp:97 sampling=YCbCr-4:2:2; width=1920; height=1080; depth=10; interlace; SSN=ST2110-20:2017; colorimetry=BT709; PM=2110GPM; TP=2110TPW; TCS=SDR; exactframerate=25\n"
             "a=mediaclk:direct=0 rate=90000\n"
            )
        ]
        
        for name, sdp_text in test_cases:
            with self.subTest(name=name):
                sdp_instance = MatroxSdp()
                reader = io.StringIO(sdp_text)
                try:
                    sdp_instance.Decode(reader)
                except Exception as e:
                    self.fail(f"Decoding {name} raised an exception: {e}")
                
                # Additional enhancements: for the DUP group test, check that the two media entries are set properly.
                if name == "r7":
                    self.assertEqual(sdp_instance.PrimaryMediaName, "S1a", "Primary media name mismatch")
                    self.assertEqual(sdp_instance.SecondaryMediaName, "S1b", "Secondary media name mismatch")
                    self.assertEqual(sdp_instance.PrimaryMedia.MediaName, "S1a", "Primary media MID mismatch")
                    self.assertEqual(sdp_instance.SecondaryMedia.MediaName, "S1b", "Secondary media MID mismatch")

if __name__ == '__main__':
    unittest.main()
