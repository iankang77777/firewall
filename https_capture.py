from scapy.all import load_layer, sniff
from scapy.layers.tls.handshake import TLSClientHello

#TLS 관련 레이어를 로드하여 Scapu에서 TLS패킷을 인식할 수 있도록 설정
load_layer('tls')

#패킷에서 SNI정보를 추출하는 함수 정의
def extract_sni(packet):
    #해당 패킷이 TLSClientHello 메시지를 포함하고 있는지 확인
    if packet.haslayer(TLSClientHello):
        client_hello = packet[TLSClientHello]
        #ClientHello의 extensions필드에서 SNI정보를 검색
        for ext in getattr(client_hello, 'ext', []):
            #extension 중에 servernames 속성이 있는 경우 (SNI extension)
            if hasattr(ext, 'servernames'):
                #여러 서버 이름이 있을 수 있으므로 반복
                for servername in ext.servernames:
                    #서버 이름 (servername)은 bytes 형이므로 문자열로 디코딩 후 출력
                    print('SNI도메인:', servername.servername.decode())
#TCP포트 443(HTTPS)로 들어오는 패킷을 실시간으로 캡처하고,
#각 패킷마다 extract_snl 함수를 호출하여 SNI 도메인을 추출
sniff(filter="tcp port 443", prn=extract_sni)

