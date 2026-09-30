"""Generate public, synthetic evidence only. No external logs or credentials."""
from pathlib import Path
import datetime, struct, zlib, json
ROOT = Path(__file__).resolve().parents[1] / 'tests' / 'fixtures'
ROOT.mkdir(parents=True, exist_ok=True)
T = int(datetime.datetime(2026, 9, 30, 2, tzinfo=datetime.timezone.utc).timestamp())
(ROOT/'auth.log').write_text(''.join(f'2026-09-30T02:00:0{i}Z demo sshd[123]: Failed password for demo from 192.0.2.10 port 50000 ssh2\n' for i in range(6)) + '2026-09-30T02:00:08Z demo sshd[123]: Accepted password for demo from 192.0.2.10 port 50000 ssh2\n', encoding='utf-8')
(ROOT/'access.log').write_text('192.0.2.10 - demo [30/Sep/2026:10:00:00 +0800] "GET /index HTTP/1.1" 200 10 "-" "DemoBrowser"\n192.0.2.20 - - [30/Sep/2026:10:00:01 +0800] "GET /%2e%2e/etc/passwd HTTP/1.1" 404 0 "-" "DemoBrowser"\nbroken record <script>\n', encoding='utf-8')
(ROOT/'custom-format.conf').write_text('log_format custom \'$remote_addr|$time_iso8601|$request_method|$request_uri|$status\';\n')
(ROOT/'custom.log').write_text('192.0.2.10|2026-09-30T10:00:00+08:00|GET|/.env|403\n')
processes=[{'pid':1,'parent_pid':None,'name':'init','path':'/sbin/init','command':[]}, {'pid':100,'parent_pid':1,'name':'demo','path':'/tmp/demo','command':['demo']}, {'pid':101,'parent_pid':100,'name':'powershell.exe','path':'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe','command':['powershell.exe','-EncodedCommand','ZGVtbw==']}]
(ROOT/'processes.json').write_text(json.dumps(processes, indent=2)+'\n')
for name,typ,count in [('sample.wtmp',7,1),('sample.btmp',7,6),('sample.utmp',7,1)]:
    data=bytearray()
    for i in range(count):
        r=bytearray(384);struct.pack_into('<h',r,0,typ);struct.pack_into('<i',r,4,123);r[8:13]=b'pts/0';r[44:48]=b'demo';host=b'192.0.2.10';r[76:76+len(host)]=host;struct.pack_into('<ii',r,340,T+i,0);r[348:352]=bytes([192,0,2,10]);data.extend(r)
    (ROOT/name).write_bytes(data)
# Ethernet + IPv4 + TCP + plaintext synthetic HTTP request.
payload=b'GET /.env HTTP/1.1\r\nHost: demo.invalid\r\n\r\ndemo-body'
ip=bytearray(20);ip[0]=0x45;struct.pack_into('>H',ip,2,20+20+len(payload));ip[8]=64;ip[9]=6;ip[12:16]=bytes([192,0,2,10]);ip[16:20]=bytes([192,0,2,20])
tcp=bytearray(20);struct.pack_into('>HH',tcp,0,50000,80);tcp[12]=0x50;tcp[13]=0x18
packet=bytes(12)+b'\x08\x00'+ip+tcp+payload
pcap=struct.pack('<IHHIIII',0xa1b2c3d4,2,4,0,0,65535,1)+struct.pack('<IIII',T,123456,len(packet),len(packet))+packet
(ROOT/'sample.pcap').write_bytes(pcap)
def block(kind,body,endian='<'):
    body+=bytes((-len(body))%4);size=12+len(body);return struct.pack(endian+'II',kind,size)+body+struct.pack(endian+'I',size)
def section(endian):
    return block(0x0a0d0d0a,struct.pack(endian+'IHHq',0x1a2b3c4d,1,0,-1),endian)
def ngpacket(endian='<'):
    ticks=T*1000000+123456
    return block(6,struct.pack(endian+'IIIII',0,ticks>>32,ticks&0xffffffff,len(packet),len(packet))+packet,endian)
ng=section('<')+block(1,struct.pack('<HHI',1,0,65535))+ngpacket('<')
ng+=section('>')+block(1,struct.pack('>HHI',1,0,65535),'>')+ngpacket('>')
(ROOT/'sample.pcapng').write_bytes(ng)
# Direct BinXML elements with inline EVTX name-table entries.
chunk=bytearray(65536);chunk[:8]=b'ElfChnk\0';pos=512;last=pos
for idx in range(1,8):
    start=pos;blob=bytearray(b'\x0f\x01\x01\x00')
    def node(name,children):
        namebytes=name.encode('utf-16le');nameoffset=start+24+len(blob)+9
        blob.extend(b'\x01'+struct.pack('<II',0,nameoffset)+struct.pack('<IHH',0,0,len(name))+namebytes+b'\0\0'+b'\x02')
        if isinstance(children,str):
            value=children.encode('utf-16le');blob.extend(b'\x05\x01'+struct.pack('<H',len(children))+value)
        else:
            for key,value in children:node(key,value)
        blob.extend(b'\x04')
    node('Event',[('System',[('EventID','4625' if idx<7 else '4624'),('Computer','demo.invalid')]),('EventData',[('TargetUserName','demo'),('IpAddress','192.0.2.10')])])
    blob.extend(b'\0');size=24+len(blob)+4;pad=(-size)%8;size+=pad
    record=struct.pack('<IIQQ',0x2a2a,size,idx,(T+idx+11644473600)*10000000)+blob+bytes(pad)+struct.pack('<I',size)
    chunk[pos:pos+size]=record;last=pos;pos+=size
struct.pack_into('<QQQQIIII',chunk,8,1,7,1,7,128,last,pos,zlib.crc32(chunk[512:pos]))
struct.pack_into('<I',chunk,124,zlib.crc32(chunk[:120]+chunk[128:512]))
header=bytearray(4096);header[:8]=b'ElfFile\0';struct.pack_into('<QQQIHHHH',header,8,0,0,8,128,1,3,4096,1);struct.pack_into('<I',header,124,zlib.crc32(header[:120]))
(ROOT/'synthetic.evtx').write_bytes(header+chunk)
empty=header.copy();struct.pack_into('<H',empty,42,0);struct.pack_into('<I',empty,124,zlib.crc32(empty[:120]));(ROOT/'empty.evtx').write_bytes(empty)
(ROOT/'empty.log').write_bytes(b'')
(ROOT/'malformed.evtx').write_bytes(b'ElfFile\0broken')
(ROOT/'truncated.pcap').write_bytes(pcap[:-10])
