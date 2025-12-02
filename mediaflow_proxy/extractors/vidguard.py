import re
import json
import binascii
import base64
from urllib.parse import urlparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidGuardExtractor(BaseExtractor):
    """
    VidGuard extractor for MediaFlow Proxy.
    Stremio already normalizes URLs to /e/{id}.
    Our job is ONLY to decode VidGuard's JS and signature.
    """

    VALID_DOMAINS = [
        "vidguard.to", "vid-guard.com", "vgfplay.com", "vgfplay.xyz",
        "vgembed.com", "vembed.net", "embedv.net", "v6embed.xyz",
        "go-streamer.net", "fslinks.org", "bembed.net", "listeamed.net",
        "kinoger.pw", "moflix-stream.day",
        "6tnutl8knw.sbs", "dhmu4p2hkp.sbs", "gsfjzmqu.sbs",
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

        # Incoming referer from Stremio (DO NOT override!)
        incoming_referer = self.headers.get("referer", url)

        # Step 1: Fetch embed page EXACTLY like browser
        response = await self._make_request(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) "
                    "Gecko/20100101 Firefox/140.0"
                ),
                "Referer": incoming_referer,
            },
        )
        html = response.text

        # Step 2: VidGuard stores stream info in eval("window.ADBLOCKER=false;\n ... ;");
        js_match = re.search(
            r'eval\("window\.ADBLOCKER\s*=\s*false;\\n(.+?);"\);</script',
            html,
        )
        if not js_match:
            raise ExtractorError("VIDGUARD: Cannot locate encoded stream block")

        encoded_js = self._cleanup_js(js_match.group(1))

        # Step 3: AAdecode
        decoded = self._aadecode(encoded_js)

        # Step 4: Parse JSON (starts after offset 11)
        try:
            json_data = json.loads(decoded[11:])
        except Exception:
            raise ExtractorError("VIDGUARD: Failed parsing decoded JSON")

        streams = json_data.get("stream")
        if not streams:
            raise ExtractorError("VIDGUARD: No stream source found")

        # Step 5: Choose highest quality
        if isinstance(streams, list):
            def _label_to_int(label: str) -> int:
                try:
                    return int(label.replace("p", ""))
                except Exception:
                    return 0

            streams_sorted = sorted(
                streams, key=lambda x: _label_to_int(x.get("Label", "0p")), reverse=True
            )
            stream_url = streams_sorted[0].get("URL")
        else:
            stream_url = streams

        if not stream_url:
            raise ExtractorError("VIDGUARD: Empty stream URL")

        # Fix protocol issues
        if not stream_url.startswith("http"):
            stream_url = re.sub(r":/*", "://", stream_url)

        # Step 6: Decode ?sig=
        stream_url = self._decode_signature(stream_url)

        # -----------------------------------------------------
        # RETURN STRUCTURE
        # -----------------------------------------------------
        headers = self.base_headers.copy()

        # DO NOT modify referer or origin — use exactly what Stremio provided
        if incoming_referer:
            headers["referer"] = incoming_referer

        headers.setdefault(
            "user-agent",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"
        )

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

        # hex signature
        if re.fullmatch(r"[0-9a-fA-F]+", sig):
            raw = binascii.unhexlify(sig)
        else:
            # base64url signature
            padded = sig + "=" * (-len(sig) % 4)
            raw = base64.urlsafe_b64decode(padded)

        # XOR by 2
        t = "".join(chr(b ^ 2) for b in raw)

        # inner base64 decode
        decoded = self._b64decode(t + "==")

        decoded = decoded[:-5][::-1]  # remove tail + reverse

        # swap bytes
        b = list(decoded)
        for i in range(0, len(b) - 1, 2):
            b[i], b[i + 1] = b[i + 1], b[i]

        final = "".join(chr(x) for x in b[:-5])
        return url.replace(sig, final)

    # -----------------------------------------------------
    #                AA-DECODE
    # -----------------------------------------------------
    def _aadecode(self, text: str) -> str:
        text = re.sub(r"\s+|/\*.*?\*/", "", text)

        # VidGuard ALT pattern
        try:
            data = text.split("+(ﾟɆﾟ)[ﾟoﾟ]")[1]
            chars = data.split("+(ﾟɆﾟ)[ﾟεﾟ]+")[1:]
            char1 = "ღ"
            char2 = "(ﾟɆﾟ)[ﾟΘﾟ]"
        except Exception:
            # fallback AAencode
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
                except Exception:
                    pass

            if sub:
                txt += sub + "|"

        if not txt:
            raise ExtractorError("VIDGUARD: Failed AAdecode")

        txt = txt[:-1].replace("+", "")

        try:
            txt_result = "".join(chr(int(n, 8)) for n in txt.split("|"))
        except Exception:
            raise ExtractorError("VIDGUARD: Failed octal decode")

        return self._to_string_cases(txt_result)

    def _to_string_cases(self, txt: str) -> str:
        if ".toString(" not in txt:
            return txt

        sum_base = ""
        m3 = False

        if "+(" in txt:
            m3 = True
            try:
                sum_base = "+" + re.search(r".toString...(\d+).", txt, re.DOTALL).groups(1)
            except Exception:
                pass
            pairs = re.findall(r"..(\d),(\d+).", txt, re.DOTALL)
            cases = [(n, b) for b, n in pairs]
        else:
            cases = re.findall(r"(\d+)\.0.\w+.([^\)]+).", txt, re.DOTALL)

        for numero, base in cases:
            code = self._to_string(int(numero), eval(base + sum_base))
            if m3:
                txt = txt.replace("(" + base + "," + numero + ")", code)
            else:
                txt = txt.replace(f"{numero}.0.toString({base})", code)

        return re.sub(r"'|\+", "", txt)

    def _to_string(self, number: int, base: int) -> str:
        chars = "0123456789abcdefghijklmnopqrstuvwxyz"
        return chars[number] if number < base else self._to_string(number // base, base) + chars[number % base]

    # -----------------------------------------------------
    #                HELPERS
    # -----------------------------------------------------
    def _cleanup_js(self, text: str) -> str:
        return (
            text.replace("\\u002b", "+")
            .replace("\\u0027", "'")
            .replace("\\u0022", '"')
            .replace("\\/", "/")
            .replace("\\\\", "\\")
            .replace('\\"', '"')
        )

    def _b64decode(self, data: str) -> bytes:
        return base64.b64decode(data)
