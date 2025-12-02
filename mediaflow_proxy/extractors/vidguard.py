# mediaflow_proxy/extractors/vidguard.py

import re
import json
import binascii
import base64
from urllib.parse import urlparse

from mediaflow_proxy.extractors.base import BaseExtractor, ExtractorError


class VidGuardExtractor(BaseExtractor):
    """
    VidGuard extractor for MediaFlow Proxy

    Compatible domains:
        vidguard.to, vid-guard.com, vgfplay.com, vgfplay.xyz,
        vgembed.com, vembed.net, embedv.net, v6embed.xyz,
        go-streamer.net, fslinks.org, bembed.net, listeamed.net,
        kinoger.pw, moflix-stream.day,
        6tnutl8knw.sbs, dhmu4p2hkp.sbs, gsfjzmqu.sbs
    """

    VALID_DOMAINS = [
        "vidguard.to", "vid-guard.com", "vgfplay.com", "vgfplay.xyz",
        "vgembed.com", "vembed.net", "embedv.net", "v6embed.xyz",
        "fslinks.org", "go-streamer.net", "bembed.net", "listeamed.net",
        "kinoger.pw", "moflix-stream.day",
        "6tnutl8knw.sbs", "dhmu4p2hkp.sbs", "gsfjzmqu.sbs",
    ]

    # We want HLS to go through the HLS endpoint, not /stream
    mediaflow_endpoint = "hls_manifest_proxy"

    async def extract(self, url: str):
        parsed_url = urlparse(url)

        if not parsed_url.hostname:
            raise ExtractorError("VIDGUARD: URL missing hostname")

        if not any(parsed_url.hostname.endswith(d) for d in self.VALID_DOMAINS):
            raise ExtractorError("VIDGUARD: Invalid VidGuard domain")

        # -----------------------------
        # 1. Build base headers with REAL client IP preserved
        # -----------------------------
        # self.base_headers comes from ExtractorFactory.get_extractor("VidGuard", request_headers)
        # which already includes X-Forwarded-For / X-Real-IP coming from the Stremio addon.
        base = {k.lower(): v for k, v in self.base_headers.items()}

        client_ip = (
            base.get("x-real-ip")
            or (base.get("x-forwarded-for") or "").split(",")[0].strip()
            or None
        )

        headers = {
            # keep anything existing (cookies, etc)
            **self.base_headers,
            # enforce browser-like UA + referer, but DO NOT drop IP headers
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) "
                "Gecko/20100101 Firefox/140.0"
            ),
            "Referer": "https://listeamed.net/",
        }

        # ensure IP forwarding headers are preserved / normalized
        if client_ip:
            headers["X-Real-IP"] = client_ip
            headers["X-Forwarded-For"] = client_ip
            headers.setdefault("Forwarded", f"for={client_ip}")

        # -----------------------------
        # 2. Fetch embed HTML
        # -----------------------------
        response = await self._make_request(url, headers=headers)
        html = response.text

        # -----------------------------
        # 3. Locate AA-encoded JS: eval("window.ADBLOCKER=false;\n ... ;");
        # -----------------------------
        js_match = re.search(
            r'eval\("window\.ADBLOCKER\s*=\s*false;\\n(.+?);"\);</script',
            html,
        )

        if not js_match:
            raise ExtractorError("VIDGUARD: Cannot locate encoded stream block")

        encoded_js = self._cleanup_js(js_match.group(1))

        # -----------------------------
        # 4. AA decode → JSON
        # -----------------------------
        decoded = self._aadecode(encoded_js)

        try:
            json_data = json.loads(decoded[11:])
        except Exception:
            raise ExtractorError("VIDGUARD: Failed parsing decoded JSON")

        streams = json_data.get("stream")
        if not streams:
            raise ExtractorError("VIDGUARD: No stream source found")

        # -----------------------------
        # 5. Best quality selection
        # -----------------------------
        if isinstance(streams, list):

            def _label_to_int(label: str) -> int:
                try:
                    return int(label.replace("p", ""))
                except Exception:
                    return 0

            streams_sorted = sorted(
                streams,
                key=lambda x: _label_to_int(x.get("Label", "0p")),
                reverse=True,
            )
            stream_url = streams_sorted[0].get("URL")
        else:
            stream_url = streams

        if not stream_url:
            raise ExtractorError("VIDGUARD: Empty stream URL")

        # Fix malformed protocol `:////` etc
        if not stream_url.startswith("http"):
            stream_url = re.sub(r":/*", "://", stream_url)

        # -----------------------------
        # 6. Decode VidGuard signature (?sig=xxxx)
        # -----------------------------
        stream_url = self._decode_signature(stream_url)

        # -----------------------------
        # 7. Return MediaFlow response (HLS)
        # -----------------------------
        # These headers are used by routes to build h_* query params and for
        # outbound requests to GuardStorage / VidGuard HLS.
        mfp_headers = self.base_headers.copy()
        mfp_headers["referer"] = url

        # preserve IP headers explicitly
        if client_ip:
            mfp_headers["x-real-ip"] = client_ip
            mfp_headers["x-forwarded-for"] = client_ip
            mfp_headers.setdefault("forwarded", f"for={client_ip}")

        return {
            "destination_url": stream_url,
            "request_headers": mfp_headers,
            "mediaflow_endpoint": self.mediaflow_endpoint,
        }

    # -----------------------------------------------------
    #                SIGNATURE DECODING
    # -----------------------------------------------------
    def _decode_signature(self, url: str) -> str:
        if "sig=" not in url:
            return url

        sig = url.split("sig=")[1].split("&")[0]

        # hex signature (old format)
        if re.fullmatch(r"[0-9a-fA-F]+", sig):
            try:
                raw = binascii.unhexlify(sig)
            except binascii.Error:
                raise ExtractorError("VIDGUARD: Failed hex unhexlify")
        else:
            # base64url signature (new)
            try:
                padded = sig + "=" * (-len(sig) % 4)
                raw = base64.urlsafe_b64decode(padded)
            except Exception:
                raise ExtractorError("VIDGUARD: Signature is neither hex nor base64url")

        # XOR by 2
        t = "".join(chr(b ^ 2) for b in raw)

        # inner base64 decode
        try:
            decoded = self._b64decode(t + "==")
        except Exception:
            raise ExtractorError("VIDGUARD: Failed inner base64 decode in signature")

        decoded = decoded[:-5][::-1]

        byte_list = list(decoded)
        for i in range(0, len(byte_list) - 1, 2):
            byte_list[i], byte_list[i + 1] = byte_list[i + 1], byte_list[i]

        final = "".join(chr(b) for b in byte_list[:-5])

        return url.replace(sig, final)

    # -----------------------------------------------------
    #                AA-DECODE
    # -----------------------------------------------------
    def _aadecode(self, text: str) -> str:
        text = re.sub(r"\s+|/\*.*?\*/", "", text)

        # ALT pattern (ﾟɆﾟ)
        try:
            data = text.split("+(ﾟɆﾟ)[ﾟoﾟ]")[1]
            chars = data.split("+(ﾟɆﾟ)[ﾟεﾟ]+")[1:]
            char1 = "ღ"
            char2 = "(ﾟɆﾟ)[ﾟΘﾟ]"
        except Exception:
            # fallback to classic (ﾟДﾟ)
            try:
                data = text.split("+(ﾟДﾟ)[ﾟoﾟ]")[1]
                chars = data.split("+(ﾟДﾟ)[ﾟεﾟ]+")[1:]
                char1 = "c"
                char2 = "(ﾟДﾟ)['0']"
            except Exception:
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
                except Exception:
                    pass

            if sub:
                txt += sub + "|"

        if not txt:
            raise ExtractorError("VIDGUARD: Failed building AAdecode numeric string")

        txt = txt[:-1].replace("+", "")

        try:
            txt_result = "".join(chr(int(n, 8)) for n in txt.split("|"))
        except Exception:
            raise ExtractorError("VIDGUARD: Failed to decode AAencoded octal data")

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
                except Exception:
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
                        r'"|\+',
                        "",
                        txt.replace("(" + base + "," + numero + ")", code),
                    )
                else:
                    txt = re.sub(
                        r"'|\+",
                        "",
                        txt.replace(f"{numero}.0.toString({base})", code),
                    )

        return txt

    def _to_string(self, number: int, base: int) -> str:
        chars = "0123456789abcdefghijklmnopqrstuvwxyz"
        if number < base:
            return chars[number]
        return self._to_string(number // base, base) + chars[number % base]

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
