import re
import json
import binascii
from urllib.parse import urlparse, urljoin

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidGuardExtractor(BaseExtractor):
    """
    VidGuard extractor for MediaFlow Proxy
    Compatible domains:
        vidguard.to, vid-guard.com, vgfplay.com, vgfplay.xyz,
        vembed.net, embedv.net, v6embed.xyz, go-streamer.net,
        fslinks.org, bembed.net, listeamed.net, kinoger.pw, *.sbs
    """

    VALID_DOMAINS = [
        "vidguard.to", "vid-guard.com", "vgfplay.com", "vgfplay.xyz",
        "vgembed.com", "vembed.net", "embedv.net", "v6embed.xyz",
        "fslinks.org", "go-streamer.net", "bembed.net", "listeamed.net",
        "kinoger.pw"
    ]

    mediaflow_endpoint = "hls_manifest_proxy"

    # -----------------------------------------------------
    #                   MAIN EXTRACTOR
    # -----------------------------------------------------
    async def extract(self, url: str):
        parsed_url = urlparse(url)

        if not parsed_url.hostname:
            raise ExtractorError("VIDGUARD: URL missing hostname")

        if not any(parsed_url.hostname.endswith(d) for d in self.VALID_DOMAINS):
            raise ExtractorError("VIDGUARD: Invalid VidGuard domain")

        # Step 1: fetch the embed HTML
        # Step 1: fetch the embed HTML
        response = await self._make_request(
            url,
            headers={
             "User-Agent": (
                 "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                 "AppleWebKit/537.36 (KHTML, like Gecko) "
                 "Chrome/120.0.0.0 Safari/537.36"
             ),
             "Referer": url,
             "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            }
        )
        html = response.text

        # Step 2: VidGuard stores stream in AA-encoded JS inside:
        # eval("window.ADBLOCKER=false;\n .... ;");
        js_match = re.search(
            r'eval\("window\.ADBLOCKER\s*=\s*false;\\n(.+?);"\);</script',
            html
        )

        if not js_match:
            raise ExtractorError("VIDGUARD: Cannot locate encoded stream block")

        encoded_js = self._cleanup_js(js_match.group(1))

        # Step 3: decode AA encoded JavaScript
        decoded = self._aadecode(encoded_js)

        # VidGuard JSON begins at offset 11
        try:
            json_data = json.loads(decoded[11:])
        except Exception:
            raise ExtractorError("VIDGUARD: Failed parsing decoded JSON")

        streams = json_data.get("stream")
        if not streams:
            raise ExtractorError("VIDGUARD: No stream source found")

        # Step 4: Pick best quality if list
        if isinstance(streams, list):
            # Each entry = {"Label": "1080p", "URL": "https...."}
            streams_sorted = sorted(
                streams,
                key=lambda x: int(x.get("Label", "0p").replace("p", "")),
                reverse=True,
            )
            stream_url = streams_sorted[0]["URL"]
        else:
            stream_url = streams

        # Fix malformed protocol `:////` etc
        if not stream_url.startswith("http"):
            stream_url = re.sub(r":/*", "://", stream_url)

        # Step 5: Decode VidGuard signature (?sig=xxxx)
        try:
            stream_url = self._decode_signature(stream_url)
        except Exception:
            raise ExtractorError("VIDGUARD: Failed to decode signature")

        # -----------------------------------------------------
        #         RETURN MFP STRUCTURE (required format)
        # -----------------------------------------------------
        headers = self.base_headers.copy()
        headers["referer"] = url

        return {
            "destination_url": stream_url,
            "request_headers": headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    # -----------------------------------------------------
    #                SIGNATURE DECODING
    # -----------------------------------------------------
    def _decode_signature(self, url: str) -> str:
        if "sig=" not in url:
            return url

        sig = url.split("sig=")[1].split("&")[0]

        decoded = ""
        for v in binascii.unhexlify(sig):
            # XOR by 2 — same as original resolver
            decoded += chr((v if isinstance(v, int) else ord(v)) ^ 2)

        # Remove padding / reverse bytes
        decoded_bytes = decoded + "=="
        decoded_final = self._b64decode(decoded_bytes)[:-5][::-1]

        # swap every 2 bytes
        t = list(decoded_final)
        for i in range(0, len(t) - 1, 2):
            t[i], t[i + 1] = t[i + 1], t[i]

        return url.replace(sig, "".join(t)[:-5])

    # -----------------------------------------------------
    #                AA-DECODE (Python rewrite)
    # -----------------------------------------------------
    def _aadecode(self, text):
    # Strip whitespace and JS comments
    text = re.sub(r"\s+|/\*.*?\*/", "", text)

    # ALT patterns used by VidGuard
    try:
        data = text.split("+(ﾟɆﾟ)[ﾟoﾟ]")[1]
        chars = data.split("+(ﾟɆﾟ)[ﾟεﾟ]+")[1:]
        char1 = "ღ"
        char2 = "(ﾟɆﾟ)[ﾟΘﾟ]"
    except:
        # Standard AAencode fallback
        data = text.split("+(ﾟДﾟ)[ﾟoﾟ]")[1]
        chars = data.split("+(ﾟДﾟ)[ﾟεﾟ]+")[1:]
        char1 = "c"
        char2 = "(ﾟДﾟ)['0']"

    txt = ""
    for char in chars:
        char = (
            char.replace("(oﾟｰﾟo)", "u")
            .replace(char1, "0")
            .replace(char2, "c")
            .replace("ﾟΘﾟ", "1")
            .replace("!+[]", "1")
            .replace("-~", "1+")
            .replace("o", "3")
            .replace("_", "3")
            .replace("ﾟｰﾟ", "4")
            .replace("(+", "(")
        )
        char = re.sub(r"\((\d)\)", r"\1", char)

        c = ""
        sub = ""
        for v in char:
            c += v
            try:
                sub += str(eval(c))
                c = ""
            except:
                pass

        if sub:
            txt += sub + "|"

    txt = txt[:-1].replace("+", "")

    try:
        txt_result = "".join([chr(int(n, 8)) for n in txt.split("|")])
    except:
        raise ExtractorError("VIDGUARD: Failed to decode AAencoded stream block")

    return self._to_string_cases(txt_result)


def _to_string_cases(self, txt):
    sum_base = ""
    m3 = False

    if ".toString(" in txt:
        if "+(" in txt:
            m3 = True
            try:
                sum_base = "+" + re.search(
                    r".toString...(\d+).", txt, re.DOTALL
                ).groups(1)
            except:
                sum_base = ""
            txt_pre_temp = re.findall(r"..(\d),(\d+).", txt, re.DOTALL)
            txt_temp = [(n, b) for b, n in txt_pre_temp]
        else:
            txt_temp = re.findall(
                r"(\d+)\.0.\w+.([^\)]+).", txt, re.DOTALL
            )

        for numero, base in txt_temp:
            code = self._to_string(int(numero), eval(base + sum_base))
            if m3:
                txt = re.sub(
                    r'"|\+', '', txt.replace("(" + base + "," + numero + ")", code)
                )
            else:
                txt = re.sub(
                    r"'|\+", '', txt.replace(numero + ".0.toString(" + base + ")", code)
                )

    return txt


def _to_string(self, number, base):
    chars = "0123456789abcdefghijklmnopqrstuvwxyz"
    if number < base:
        return chars[number]
    return self._to_string(number // base, base) + chars[number % base]