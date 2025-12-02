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
        kinoger.pw, *.sbs
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
    #                   MAIN EXTRACTOR
    # -----------------------------------------------------
    async def extract(self, url: str):
        parsed_url = urlparse(url)

        if not parsed_url.hostname:
            raise ExtractorError("VIDGUARD: URL missing hostname")

        # -----------------------------------------------------
        # STEP 0 — If NOT a VidGuard domain, extract iframe first
        # -----------------------------------------------------
        if not any(parsed_url.hostname.endswith(d) for d in self.VALID_DOMAINS):
            resp = await self._make_request(
                url,
                headers={"User-Agent": self.base_headers["user-agent"]}
            )
            html = resp.text

            domain_pattern = "(?:" + "|".join(
                d.replace(".", r"\.") for d in self.VALID_DOMAINS
            ) + ")"

            iframe = re.search(
                rf'<iframe[^>]+src=["\']([^"\']*{domain_pattern}[^"\']*)["\']',
                html,
                re.IGNORECASE
            )

            if not iframe:
                raise ExtractorError("VIDGUARD: No VidGuard iframe found in page")

            embed_url = iframe.group(1)

            # remove trailing MP4 filename
            if embed_url.endswith(".mp4"):
                embed_url = embed_url.rsplit("/", 1)[0]

            # retry extraction with real VidGuard link
            return await self.extract(embed_url)

        # -----------------------------------------------------
        # STEP 1 — Load VidGuard embed page
        # -----------------------------------------------------
        response = await self._make_request(
            url,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0"
                ),
                "Referer": "https://listeamed.net/",
            },
        )
        html = response.text

        # -----------------------------------------------------
        # STEP 2 — Find AA-encoded JS block
        # -----------------------------------------------------
        js_match = re.search(
            r'eval\("window\.ADBLOCKER\s*=\s*false;\\n(.+?);"\);</script',
            html,
            re.DOTALL
        )

        if not js_match:
            raise ExtractorError("VIDGUARD: Cannot locate encoded stream block")

        encoded_js = self._cleanup_js(js_match.group(1))

        # -----------------------------------------------------
        # STEP 3 — Decode AAencoded JS
        # -----------------------------------------------------
        decoded = self._aadecode(encoded_js)

        # VidGuard JSON begins at offset 11 in decoded string
        try:
            json_data = json.loads(decoded[11:])
        except Exception:
            raise ExtractorError("VIDGUARD: Failed parsing decoded JSON")

        streams = json_data.get("stream")
        if not streams:
            raise ExtractorError("VIDGUARD: No stream source found")

        # -----------------------------------------------------
        # STEP 4 — Choose best quality
        # -----------------------------------------------------
        if isinstance(streams, list):
            def _label_to_int(label: str) -> int:
                try:
                    return int(label.replace("p", ""))
                except:
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

        # fix malformed protocol (:// → :////)
        if not stream_url.startswith("http"):
            stream_url = re.sub(r":/*", "://", stream_url)

        # -----------------------------------------------------
        # STEP 5 — Decode ?sig= parameter
        # -----------------------------------------------------
        stream_url = self._decode_signature(stream_url)

        # -----------------------------------------------------
        # OUTPUT TO MEDIAFLOW
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

        if re.fullmatch(r"[0-9a-fA-F]+", sig):   # old hex format
            try:
                raw = binascii.unhexlify(sig)
            except:
                raise ExtractorError("VIDGUARD: Failed hex unhexlify")
        else:  # new base64url format
            try:
                padded = sig + "=" * (-len(sig) % 4)
                raw = base64.urlsafe_b64decode(padded)
            except:
                raise ExtractorError("VIDGUARD: Signature is neither hex nor base64url")

        t = "".join(chr(b ^ 2) for b in raw)

        try:
            decoded = self._b64decode(t + "==")
        except:
            raise ExtractorError("VIDGUARD: Failed inner base64 decode")

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
            raise ExtractorError("VIDGUARD: AAdecode number build failed")

        txt = txt[:-1].replace("+", "")

        try:
            txt_result = "".join(chr(int(n, 8)) for n in txt.split("|"))
        except:
            raise ExtractorError("VIDGUARD: Octal decode failed")

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
                txt_pre = re.findall(r"..(\d),(\d+).", txt, re.DOTALL)
                txt_temp = [(n, b) for b, n in txt_pre]
            else:
                txt_temp = re.findall(
                    r"(\d+)\.0.\w+.([^\)]+).", txt, re.DOTALL
                )

            for numero, base in txt_temp:
                code = self._to_string(int(numero), eval(base + sum_base))
                if m3:
                    txt = re.sub(r'"|\+', "", txt.replace("(" + base + "," + numero + ")", code))
                else:
                    txt = re.sub(r"'|\+", "", txt.replace(f"{numero}.0.toString({base})", code))

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
