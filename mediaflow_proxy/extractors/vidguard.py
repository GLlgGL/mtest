import re
import json
import binascii
import base64
from urllib.parse import urlparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidGuardExtractor(BaseExtractor):
    """
    VidGuard extractor for MediaFlow Proxy
    """

    VALID_DOMAINS = [
        "vidguard.to", "vid-guard.com", "vgfplay.com", "vgfplay.xyz",
        "vgembed.com", "vembed.net", "embedv.net", "v6embed.xyz",
        "fslinks.org", "go-streamer.net", "bembed.net", "listeamed.net",
        "kinoger.pw", "moflix-stream.day",
        "6tnutl8knw.sbs", "dhmu4p2hkp.sbs", "gsfjzmqu.sbs",
    ]

    mediaflow_endpoint = "hls_manifest_proxy"

    # -----------------------------------------------------
    #                 NORMALIZATION
    # -----------------------------------------------------
    def normalize(self, url: str) -> str:
        """
        Convert any VidGuard-style link to clean /e/<ID> form:

        Examples normalized:

        /e/ID
        /e/ID/filename.mp4
        /v/ID
        /d/ID/anything
        /embed/ID
        /ID

        → https://domain/e/ID
        """
        parsed = urlparse(url)
        parts = parsed.path.split("/")
        segments = [p for p in parts if p]

        if not segments:
            return url

        first = segments[0]

        if first in ("e", "v", "d", "embed") and len(segments) >= 2:
            media_id = segments[1]
        else:
            media_id = segments[-1]

        return f"{parsed.scheme}://{parsed.netloc}/e/{media_id}"

    # -----------------------------------------------------
    #                 MAIN EXTRACTOR
    # -----------------------------------------------------
    async def extract(self, url: str):
        normalized = self.normalize(url)
        parsed_url = urlparse(normalized)

        if not parsed_url.hostname:
            raise ExtractorError("VIDGUARD: URL missing hostname")

        if not any(parsed_url.hostname.endswith(d) for d in self.VALID_DOMAINS):
            raise ExtractorError("VIDGUARD: Invalid VidGuard domain")

        # Step 1 — fetch embed page
        response = await self._make_request(
            normalized,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) "
                    "Gecko/20100101 Firefox/140.0"
                ),
                "Referer": f"{parsed_url.scheme}://{parsed_url.netloc}/",
            },
        )
        html = response.text

        # Step 2 — find AAencoded eval block
        js_match = re.search(
            r'eval\("window\.ADBLOCKER\s*=\s*false;\\n(.+?);"\);</script',
            html,
        )
        if not js_match:
            raise ExtractorError("VIDGUARD: Cannot locate encoded stream block")

        encoded_js = self._cleanup_js(js_match.group(1))

        # Step 3 — decode AAencoded JS → JSON
        decoded_js = self._aadecode(encoded_js)

        try:
            json_data = json.loads(decoded_js[11:])
        except Exception:
            raise ExtractorError("VIDGUARD: Failed parsing decoded JSON")

        streams = json_data.get("stream")
        if not streams:
            raise ExtractorError("VIDGUARD: No stream source found")

        # Step 4 — pick best source
        if isinstance(streams, list):
            def _p(label): 
                try: return int(label.replace("p", ""))
                except: return 0

            streams_sorted = sorted(streams, key=lambda x: _p(x.get("Label","0p")), reverse=True)
            stream_url = streams_sorted[0].get("URL")
        else:
            stream_url = streams

        if not stream_url:
            raise ExtractorError("VIDGUARD: Empty stream URL")

        # Fix malformed scheme
        if not stream_url.startswith("http"):
            stream_url = re.sub(r":/*", "://", stream_url)

        # Step 5 — decode sig parameter
        stream_url = self._decode_signature(stream_url)

        # Final result
        headers = self.base_headers.copy()
        headers["referer"] = normalized

        return {
            "destination_url": stream_url,
            "request_headers": headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    # -----------------------------------------------------
    #          SIGNATURE DECODING (hex + base64url)
    # -----------------------------------------------------
    def _decode_signature(self, url: str) -> str:
        if "sig=" not in url:
            return url

        sig = url.split("sig=")[1].split("&")[0]

        # Hex signature
        if re.fullmatch(r"[0-9a-fA-F]+", sig):
            try:
                raw = binascii.unhexlify(sig)
            except Exception:
                raise ExtractorError("VIDGUARD: Invalid hex sig")
        else:
            # base64url signature
            try:
                padded = sig + "=" * (-len(sig) % 4)
                raw = base64.urlsafe_b64decode(padded)
            except Exception:
                raise ExtractorError("VIDGUARD: Invalid base64url sig")

        # XOR with 2
        t = "".join(chr(b ^ 2) for b in raw)

        # Inner base64 decode like ResolveURL
        try:
            inner = self._b64decode(t + "==")
        except Exception:
            raise ExtractorError("VIDGUARD: Inner base64 decode failed")

        # Reverse & drop 5
        inner = inner[:-5][::-1]

        data = list(inner)
        for i in range(0, len(data) - 1, 2):
            data[i], data[i + 1] = data[i + 1], data[i]

        final = "".join(chr(b) for b in data[:-5])
        return url.replace(sig, final)

    # -----------------------------------------------------
    #                    AA DECODE
    # -----------------------------------------------------
    def _aadecode(self, text: str) -> str:
        text = re.sub(r"\s+|/\*.*?\*/", "", text)

        # VidGuard ALT charset
        try:
            data = text.split("+(ﾟɆﾟ)[ﾟoﾟ]")[1]
            chars = data.split("+(ﾟɆﾟ)[ﾟεﾟ]+")[1:]
            char1 = "ღ"
            char2 = "(ﾟɆﾟ)[ﾟΘﾟ]"
        except:
            # Standard AAencode
            try:
                data = text.split("+(ﾟДﾟ)[ﾟoﾟ]")[1]
                chars = data.split("+(ﾟДﾟ)[ﾟεﾟ]+")[1:]
                char1 = "c"
                char2 = "(ﾟДﾟ)['0']"
            except:
                raise ExtractorError("VIDGUARD: AAencode patterns not found")

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

        if not txt:
            raise ExtractorError("VIDGUARD: Failed numeric decode")

        txt = txt[:-1].replace("+", "")

        try:
            txt_result = "".join(chr(int(n, 8)) for n in txt.split("|"))
        except:
            raise ExtractorError("VIDGUARD: Failed octal decode")

        return self._to_string_cases(txt_result)

    def _to_string_cases(self, txt: str) -> str:
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
                tmp = re.findall(r"..(\d),(\d+).", txt, re.DOTALL)
                items = [(n, b) for b, n in tmp]
            else:
                items = re.findall(r"(\d+)\.0.\w+.([^\)]+).", txt, re.DOTALL)

            for number, base in items:
                code = self._to_string(int(number), eval(base + sum_base))
                if m3:
                    txt = re.sub(r'"|\+', "", txt.replace(f"({base},{number})", code))
                else:
                    txt = re.sub(
                        r"'|\+",
                        "",
                        txt.replace(f"{number}.0.toString({base})", code),
                    )

        return txt

    def _to_string(self, number: int, base: int) -> str:
        chars = "0123456789abcdefghijklmnopqrstuvwxyz"
        if number < base:
            return chars[number]
        return self._to_string(number // base, base) + chars[number % base]

    # -----------------------------------------------------
    #                    HELPERS
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