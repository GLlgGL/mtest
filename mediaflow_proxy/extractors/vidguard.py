import re
import json
import binascii
import base64
from urllib.parse import urlparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidGuardExtractor(BaseExtractor):
    VALID_DOMAINS = [
        "vidguard.to", "vid-guard.com", "vgfplay.com", "vgfplay.xyz",
        "vgembed.com", "vembed.net", "embedv.net", "v6embed.xyz",
        "go-streamer.net", "fslinks.org", "bembed.net", "listeamed.net",
        "kinoger.pw", "moflix-stream.day",
        "6tnutl8knw.sbs", "dhmu4p2hkp.sbs", "gsfjzmqu.sbs",
    ]

    mediaflow_endpoint = "hls_manifest_proxy"

    # -----------------------------------------------------
    # NORMALIZE URLs
    # -----------------------------------------------------
    def normalize(self, url: str) -> str:
        parsed = urlparse(url)
        segments = [s for s in parsed.path.split("/") if s]

        if not segments:
            return url

        first = segments[0]

        # Cases: /e/ID , /v/ID , /d/ID , /embed/ID
        if first in ("e", "v", "d", "embed") and len(segments) >= 2:
            media_id = segments[1]
        else:
            # fallback: last segment is ID
            media_id = segments[-1]

        return f"{parsed.scheme}://{parsed.netloc}/e/{media_id}"

    # -----------------------------------------------------
    # MAIN EXTRACTOR
    # -----------------------------------------------------
    async def extract(self, url: str, **extra):
        #
        # IMPORTANT: MediaFlow passes headers as kwargs:
        #   extract(url, referer="...", origin="...")
        #
        incoming_referer = (
            extra.get("referer")
            or extra.get("h_referer")
            or extra.get("h-referer")
            or url
        )

        normalized_url = self.normalize(url)
        parsed_url = urlparse(normalized_url)

        if not parsed_url.hostname:
            raise ExtractorError("VIDGUARD: URL missing hostname")

        if not any(parsed_url.hostname.endswith(d) for d in self.VALID_DOMAINS):
            raise ExtractorError("VIDGUARD: Invalid VidGuard domain")

        # Step 1 — fetch embed HTML exactly like browser
        response = await self._make_request(
            normalized_url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/142.0.0.0 Safari/537.36"
                ),
                "Referer": f"{parsed_url.scheme}://{parsed_url.netloc}/",
            },
        )

        html = response.text

        # Step 2 — Find AAencoded block
        js_match = re.search(
            r'eval\("window\.ADBLOCKER\s*=\s*false;\\n(.+?);"\);</script',
            html,
        )

        if not js_match:
            raise ExtractorError("VIDGUARD: Cannot locate encoded stream block")

        encoded_js = self._cleanup_js(js_match.group(1))

        # Step 3 — AAdecode
        decoded = self._aadecode(encoded_js)

        # Step 4 — JSON starts at offset 11
        try:
            json_data = json.loads(decoded[11:])
        except Exception:
            raise ExtractorError("VIDGUARD: Failed parsing decoded JSON")

        streams = json_data.get("stream")
        if not streams:
            raise ExtractorError("VIDGUARD: No stream source found")

        # Step 5 — pick best quality
        if isinstance(streams, list):
            def lbl(x):
                try:
                    return int(x.get("Label", "0p").replace("p", ""))
                except:
                    return 0

            streams_sorted = sorted(streams, key=lbl, reverse=True)
            stream_url = streams_sorted[0].get("URL")
        else:
            stream_url = streams

        if not stream_url:
            raise ExtractorError("VIDGUARD: Empty stream URL")

        if not stream_url.startswith("http"):
            stream_url = re.sub(r":/*", "://", stream_url)

        # Step 6 — Signature decode
        stream_url = self._decode_signature(stream_url)

        # -----------------------------------------------------
        # RETURN TO MEDIAFLOW
        # -----------------------------------------------------
        headers = self.base_headers.copy()

        # These headers MUST be present for GuardStorage
        headers["referer"] = f"{parsed_url.scheme}://{parsed_url.netloc}/"
        headers["origin"] = f"{parsed_url.scheme}://{parsed_url.netloc}"
        headers["user-agent"] = (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/142.0.0.0 Safari/537.36"
        )

        return {
            "destination_url": stream_url,
            "request_headers": headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    # -----------------------------------------------------
    # SIGNATURE DECODING
    # -----------------------------------------------------
    def _decode_signature(self, url: str) -> str:
        if "sig=" not in url:
            return url

        sig = url.split("sig=")[1].split("&")[0]

        # Hex signature
        if re.fullmatch(r"[0-9a-fA-F]+", sig):
            raw = binascii.unhexlify(sig)

        else:
            # Base64url signature
            padded = sig + "=" * (-len(sig) % 4)
            raw = base64.urlsafe_b64decode(padded)

        # XOR 2 (VidGuard standard)
        t = "".join(chr(b ^ 2) for b in raw)

        # Inner b64 decode
        decoded = self._b64decode(t + "==")

        decoded = decoded[:-5][::-1]

        # Swap bytes
        byte_list = list(decoded)
        for i in range(0, len(byte_list) - 1, 2):
            byte_list[i], byte_list[i + 1] = byte_list[i + 1], byte_list[i]

        final = "".join(chr(b) for b in byte_list[:-5])
        return url.replace(sig, final)

    # -----------------------------------------------------
    # AA DECODE
    # -----------------------------------------------------
    def _aadecode(self, text: str) -> str:
        text = re.sub(r"\s+|/\*.*?\*/", "", text)

        try:
            data = text.split("+(ﾟɆﾟ)[ﾟoﾟ]")[1]
            chars = data.split("+(ﾟɆﾟ)[ﾟεﾟ]+")[1:]
            char1 = "ღ"
            char2 = "(ﾟɆﾟ)[ﾟΘﾟ]"
        except:
            try:
                data = text.split("+(ﾟДﾟ)[ﾟoﾟ]")[1]
                chars = data.split("+(ﾟДﾟ)[ﾟεﾟ]+")[1:]
                char1 = "c"
                char2 = "(ﾟДﾟ)['0']"
            except:
                raise ExtractorError("VIDGUARD: AA patterns missing")

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
            raise ExtractorError("VIDGUARD: Bad AAdecode")

        txt = txt[:-1].replace("+", "")

        try:
            txt_result = "".join(chr(int(n, 8)) for n in txt.split("|"))
        except:
            raise ExtractorError("VIDGUARD: Octal decode failed")

        return self._to_string_cases(txt_result)

    # -----------------------------------------------------
    def _to_string_cases(self, txt: str) -> str:
        sum_base = ""
        m3 = False

        if ".toString(" in txt:
            if "+(" in txt:
                m3 = True
                try:
                    sum_base = "+" + re.search(
                        r".toString...(\d+).", txt
                    ).groups(1)
                except:
                    sum_base = ""
                txt_pre_temp = re.findall(r"..(\d),(\d+).", txt)
                txt_temp = [(n, b) for b, n in txt_pre_temp]
            else:
                txt_temp = re.findall(r"(\d+)\.0.\w+.([^\)]+).", txt)

            for numero, base in txt_temp:
                code = self._to_string(int(numero), eval(base + sum_base))
                if m3:
                    txt = txt.replace("(" + base + "," + numero + ")", code)
                else:
                    txt = txt.replace(f"{numero}.0.toString({base})", code)

        txt = txt.replace('"', "").replace("+", "")
        return txt

    def _to_string(self, number: int, base: int) -> str:
        chars = "0123456789abcdefghijklmnopqrstuvwxyz"
        if number < base:
            return chars[number]
        return self._to_string(number // base, base) + chars[number % base]

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
