# -*- coding: utf-8 -*-
import sys
import os
import socket
import ssl
import select
import httplib
import urlparse
import threading
import gzip
import zlib
import time
import json
import re
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from cStringIO import StringIO
from subprocess import Popen, PIPE
from HTMLParser import HTMLParser


def with_color(c, s):
    return "\x1b[%dm%s\x1b[0m" % (c, s)

def join_with_script_dir(path):
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), path)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def handle_error(self, request, client_address):
        # surpress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):
    cakey = join_with_script_dir('ca.key')
    cacert = join_with_script_dir('ca.crt')
    certkey = join_with_script_dir('cert.key')
    certdir = join_with_script_dir('certs/')
    timeout = 5
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):
        # surpress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def do_CONNECT(self):
        if os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(self.certkey) and os.path.isdir(self.certdir):
            self.connect_intercept()
        else:
            self.connect_relay()

    def connect_intercept(self):
        hostname = self.path.split(':')[0]
        certpath = "%s/%s.crt" % (self.certdir.rstrip('/'), hostname)

        with self.lock:
            if not os.path.isfile(certpath):
                epoch = "%d" % (time.time() * 1000)
                p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN=%s" % hostname], stdout=PIPE)
                p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey, "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
                p2.communicate()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'Connection Established'))
        self.end_headers()

        self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, server_side=True)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

        conntype = self.headers.get('Proxy-Connection', '')
        if self.protocol_version == "HTTP/1.1" and conntype.lower() != 'close':
            self.close_connection = 0
        else:
            self.close_connection = 1

    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception as e:
            self.send_error(502)
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = 0
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = 1
                    break
                other.sendall(data)

    def do_GET(self):
        if self.path == 'http://proxy2.test/':
            self.send_cacert()
            return

        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if req.path[0] == '/':
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)

        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = urlparse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc
        setattr(req, 'headers', self.filter_headers(req.headers))

        try:
            origin = (scheme, netloc)
            if not origin in self.tls.conns:
                if scheme == 'https':
                    self.tls.conns[origin] = httplib.HTTPSConnection(netloc, timeout=self.timeout)
                else:
                    self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, dict(req.headers))
            res = conn.getresponse()

            version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
            setattr(res, 'headers', res.msg)
            setattr(res, 'response_version', version_table[res.version])

            # support streaming
            if not 'Content-Length' in res.headers and 'no-store' in res.headers.get('Cache-Control', ''):
                self.response_handler(req, req_body, res, '')
                setattr(res, 'headers', self.filter_headers(res.headers))
                self.relay_streaming(res)
                with self.lock:
                    self.save_handler(req, req_body, res, '')
                return

            res_body = res.read()
        except Exception as e:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            return

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
        if res_body_modified is False:
            self.send_error(403)
            return
        elif res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))

        setattr(res, 'headers', self.filter_headers(res.headers))

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.save_handler(req, req_body, res, res_body_plain)

    def relay_streaming(self, res):
        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        try:
            while True:
                chunk = res.read(8192)
                if not chunk:
                    break
                self.wfile.write(chunk)
            self.wfile.flush()
        except socket.error:
            # connection closed by client
            pass

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            del headers[k]

        # accept only supported encodings
        if 'Accept-Encoding' in headers:
            ae = headers['Accept-Encoding']
            filtered_encodings = [x for x in re.split(r',\s*', ae) if x in ('identity', 'gzip', 'x-gzip', 'deflate')]
            headers['Accept-Encoding'] = ', '.join(filtered_encodings)

        return headers

    def encode_content_body(self, text, encoding):
        if encoding == 'identity':
            data = text
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO()
            with gzip.GzipFile(fileobj=io, mode='wb') as f:
                f.write(text)
            data = io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO(data)
            with gzip.GzipFile(fileobj=io) as f:
                text = f.read()
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'OK'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def print_info(self, req, req_body, res, res_body):
        def parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in urlparse.parse_qsl(s, keep_blank_values=True))

        req_header_text = "%s %s %s\n%s" % (req.command, req.path, req.request_version, req.headers)
        res_header_text = "%s %d %s\n%s" % (res.response_version, res.status, res.reason, res.headers)

        print with_color(33, req_header_text)

        u = urlparse.urlsplit(req.path)
        if u.query:
            query_text = parse_qsl(u.query)
            print with_color(32, "==== QUERY PARAMETERS ====\n%s\n" % query_text)

        cookie = req.headers.get('Cookie', '')
        if cookie:
            cookie = parse_qsl(re.sub(r';\s*', '&', cookie))
            print with_color(32, "==== COOKIE ====\n%s\n" % cookie)

        auth = req.headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            token = auth.split()[1].decode('base64')
            print with_color(31, "==== BASIC AUTH ====\n%s\n" % token)

        if req_body is not None:
            req_body_text = None
            content_type = req.headers.get('Content-Type', '')

            if content_type.startswith('application/x-www-form-urlencoded'):
                req_body_text = parse_qsl(req_body)
            elif content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(req_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        req_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        req_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    req_body_text = req_body
            elif len(req_body) < 1024:
                req_body_text = req_body

            if req_body_text:
                print with_color(32, "==== REQUEST BODY ====\n%s\n" % req_body_text)

        print with_color(36, res_header_text)

        cookies = res.headers.getheaders('Set-Cookie')
        if cookies:
            cookies = '\n'.join(cookies)
            print with_color(31, "==== SET-COOKIE ====\n%s\n" % cookies)

        if res_body is not None:
            res_body_text = None
            content_type = res.headers.get('Content-Type', '')

            if content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(res_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        res_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        res_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    res_body_text = res_body
            elif content_type.startswith('text/html'):
                m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', res_body, re.I)
                if m:
                    h = HTMLParser()
                    print with_color(32, "==== HTML TITLE ====\n%s\n" % h.unescape(m.group(1).decode('utf-8')))
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = res_body

            if res_body_text:
                print with_color(32, "==== RESPONSE BODY ====\n%s\n" % res_body_text)

    def request_handler(self, req, req_body):
        if req.path.contains('/aweme/v1/user/') and req.path.contains('api2-19-h2.musical.ly'):
            return '{ 	"status_code": 0, 	"user": { 		"with_stick_entry": false, 		"weibo_schema": "", 		"enterprise_verify_reason": "", 		"region": "US", 		"apple_account": 0, 		"video_icon_virtual_URI": "", 		"follower_count": 11387524, 		"is_gov_media_vip": false, 		"follower_status": 0, 		"latest_order_time": 0, 		"is_pro_account": false, 		"avatar_medium": { 			"uri": "musically-maliva-obj/1639714752984069", 			"url_list": ["http://p16.muscdn.com/img/musically-maliva-obj/1639714752984069~c5_720x720.jpeg"] 		}, 		"is_verified": true, 		"unique_id": "cash.baker", 		"mplatform_followers_count": 0, 		"has_activity_medal": false, 		"constellation": 0, 		"school_poi_id": "", 		"dongtai_count": 1706, 		"avatar_uri": "musically-maliva-obj/1639714752984069", 		"nickname": "Cash is here„, 		"weibo_url": "", 		"verification_type": 0, 		"user_mode": 1, 		"youtube_refresh_token": "", 		"sync_to_toutiao": 0, 		"with_commerce_enterprise_tab_entry": false, 		"signature_language": "en", 		"wx_tag": 0, 		"avatar_thumb": { 			"uri": "musically-maliva-obj/1639714752984069", 			"url_list": ["http://p16.muscdn.com/img/musically-maliva-obj/1639714752984069~c5_100x100.jpeg"] 		}, 		"favoriting_count": 0, 		"commerce_user_level": 0, 		"prevent_download": false, 		"cover_url": [{ 			"uri": "musically-maliva-obj/1612555907887110", 			"url_list": ["https://m-p16.akamaized.net/obj/musically-maliva-obj/1612555907887110"] 		}], 		"hide_location": false, 		"original_musician": { 			"digg_count": 0, 			"music_count": 0, 			"music_used_count": 0 		}, 		"star_use_new_download": true, 		"secret": 0, 		"city": "", 		"birthday_hide_level": 0, 		"total_favorited": 520341200, 		"location": "", 		"special_lock": 1, 		"video_icon": { 			"uri": "", 			"url_list": [] 		}, 		"province": "", 		"bio_secure_url": "https://link-va.byteoversea.com/?aid=1233&lang=en&scene=bio&target=http://Shopcashandmav.com", 		"room_id": 0, 		"react_setting": 0, 		"profile_tab_type": 0, 		"is_star": false, 		"ad_cover_url": null, 		"custom_verify": "Popular creator", 		"download_setting": 0, 		"iso_country_code": "", 		"youtube_last_refresh_time": 0, 		"share_info": { 			"share_qrcode_url": { 				"uri": "", 				"url_list": [] 			}, 			"share_image_url": { 				"uri": "tos-maliva-p-0068/78b03f89f636409c95263fd85094ea21", 				"url_list": ["https://m-p16.akamaized.net/obj/tos-maliva-p-0068/78b03f89f636409c95263fd85094ea21"] 			}, 			"share_weibo_desc": "TikTok: Make Every Second Count", 			"share_desc": "Check out Cash! #TikTok", 			"bool_persist": 1, 			"share_title_myself": "This TikTok app is soooooo fun! Follow me @cash.baker on TikTok and check out my videos!", 			"share_title_other": "This TikTok user is really cool. Follow @cash.baker on TikTok and check out those amazing videos!", 			"share_url": "https://m.tiktok.com/h5/share/usr/6558879147065475077.html?language=en&sec_uid=MS4wLjABAAAArg_559ejF51bHxP1pmrtxxw9NKdXBhoiTU_33DBotjZHDl8E0TQ7-OGD6rVHnAs9&u_code=bde96gjfc9bch", 			"share_title": "Join TikTok and see what I've been up to!" 		}, 		"twitter_name": "", 		"comment_setting": 0, 		"has_insights": false, 		"type_label": null, 		"account_region": "US", 		"duet_setting": 0, 		"hide_following_follower_list": 0, 		"item_list": null, 		"platform_sync_info": null, 		"share_qrcode_uri": "", 		"signature": "Single🔓god💗\nTap the link for the Dallas TX show and the new merch drop!⬇️⬇️", 		"weibo_verify": "", 		"bind_phone": "", 		"avatar_300x300": { 			"uri": "musically-maliva-obj/1639714752984069", 			"url_list": ["http://p16.muscdn.com/img/musically-maliva-obj/1639714752984069~c5_300x300.webp"] 		}, 		"sec_uid": "MS4wLjABAAAArg_559ejF51bHxP1pmrtxxw9NKdXBhoiTU_33DBotjZHDl8E0TQ7-OGD6rVHnAs9", 		"with_commerce_entry": false, 		"ins_id": "cash.baker", 		"download_prompt_ts": 1554608228, 		"watch_status": false, 		"avatar_168x168": { 			"uri": "musically-maliva-obj/1639714752984069", 			"url_list": ["http://p16.muscdn.com/img/musically-maliva-obj/1639714752984069~c5_168x168.webp"] 		}, 		"district": "", 		"user_period": 0, 		"verify_info": "", 		"content_language_already_popup": 0, 		"is_block": false, 		"youtube_channel_id": "UCgV3ODiWCzMvovfLXCU7kNQ", 		"bio_url": "http://Shopcashandmav.com", 		"short_id": "0", 		"following_count": 37, 		"activity": { 			"use_music_count": 0, 			"digg_count": 0 		}, 		"is_effect_artist": false, 		"cha_list": null, 		"relative_users": null, 		"uid": "6558879147065475077", 		"aweme_count": 1706, 		"with_shop_entry": false, 		"geofencing": [], 		"is_blocked": false, 		"user_canceled": false, 		"live_commerce": false, 		"story_open": false, 		"new_story_cover": null, 		"avatar_larger": { 			"uri": "musically-maliva-obj/1639714752984069", 			"url_list": ["http://p16.muscdn.com/img/musically-maliva-obj/1639714752984069~c5_1080x1080.jpeg"] 		}, 		"follow_status": 1, 		"reflow_page_uid": 0, 		"birthday": "1900-01-01", 		"show_image_bubble": false, 		"gender": 2, 		"unique_id_modify_time": 1565443984, 		"twitter_id": "", 		"youtube_channel_title": "Cash Baker", 		"with_fusion_shop_entry": false, 		"recommend_reason_relation": "", 		"followers_detail": [{ 			"name": "抖音", 			"icon": "http://p3.pstatp.com/origin/50ec00079b64de2050dc", 			"fans_count": 0, 			"open_url": "snssdk1128://user/profile/0?", 			"apple_id": "1142110895", 			"download_url": "https://d.douyin.com/Y4Fy/", 			"package_name": "com.ss.android.ugc.aweme", 			"app_name": "aweme" 		}, { 			"app_name": "news_article", 			"name": "头条", 			"icon": "http://p3.pstatp.com/origin/50ed00079a1b6b8d1fb1", 			"fans_count": 0, 			"open_url": "snssdk141://profile?uid=0?", 			"apple_id": "529092160", 			"download_url": "https://d.toutiao.com/fUN5/", 			"package_name": "com.ss.android.article.news" 		}, { 			"package_name": "com.ss.android.ugc.live", 			"app_name": "live_stream", 			"name": "火山", 			"icon": "http://p3.pstatp.com/origin/551900041a7e00ec86ca", 			"fans_count": 0, 			"open_url": "snssdk1112://profile?id=0", 			"apple_id": "1086047750", 			"download_url": "http://d.huoshanzhibo.com/e7fw/" 		}], 		"reflow_page_gid": 0, 		"with_new_goods": false, 		"country": "", 		"with_luban_entry": false 	}, 	"extra": { 		"now": 1565443984000 	}, 	"log_pb": { 		"impr_id": "20190810133304010110068176339128" 	} }'

    def response_handler(self, req, req_body, res, res_body):
        pass

    def save_handler(self, req, req_body, res, res_body):
        self.print_info(req, req_body, res, res_body)


def test(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
    if sys.argv[1:]:
        port = int(sys.argv[1])
    else:
        port = 8080
    server_address = ('::1', port)

    HandlerClass.protocol_version = protocol
    httpd = ServerClass(server_address, HandlerClass)

    sa = httpd.socket.getsockname()
    print "Serving HTTP Proxy on", sa[0], "port", sa[1], "..."
    httpd.serve_forever()


if __name__ == '__main__':
    test()
