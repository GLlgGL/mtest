import logging
import typing
from dataclasses import dataclass
from functools import partial
from urllib import parse
from urllib.parse import urlencode

import anyio
import h11
import httpx
import tenacity
from fastapi import Response
from starlette.background import BackgroundTask
from starlette.concurrency import iterate_in_threadpool
from starlette.requests import Request
from starlette.types import Receive, Send, Scope
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from tqdm.asyncio import tqdm as tqdm_asyncio

from mediaflow_proxy.configs import settings
from mediaflow_proxy.const import SUPPORTED_REQUEST_HEADERS
from mediaflow_proxy.utils.crypto_utils import EncryptionHandler

logger = logging.getLogger(__name__)


class DownloadError(Exception):
    def __init__(self, status_code, message):
        self.status_code = status_code
        self.message = message
        super().__init__(message)


def create_httpx_client(follow_redirects: bool = True, **kwargs) -> httpx.AsyncClient:
    mounts = settings.transport_config.get_mounts()
    kwargs.setdefault("timeout", settings.transport_config.timeout)
    return httpx.AsyncClient(mounts=mounts, follow_redirects=follow_redirects, **kwargs)


@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10),
    retry=retry_if_exception_type(DownloadError),
)
async def fetch_with_retry(client, method, url, headers, follow_redirects=True, **kwargs):
    try:
        response = await client.request(method, url, headers=headers, follow_redirects=follow_redirects, **kwargs)
        response.raise_for_status()
        return response
    except httpx.TimeoutException:
        raise DownloadError(409, f"Timeout while downloading {url}")
    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            raise e
        raise DownloadError(e.response.status_code, f"HTTP error {e.response.status_code} while downloading {url}")
    except Exception as e:
        raise


class Streamer:
    def __init__(self, client):
        self.client = client
        self.response = None
        self.progress_bar = None
        self.bytes_transferred = 0
        self.start_byte = 0
        self.end_byte = 0
        self.total_size = 0

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=10),
        retry=retry_if_exception_type(DownloadError),
    )
    async def create_streaming_response(self, url: str, headers: dict):
        try:
            request = self.client.build_request("GET", url, headers=headers)
            self.response = await self.client.send(request, stream=True, follow_redirects=True)
            self.response.raise_for_status()
        except httpx.TimeoutException:
            raise DownloadError(409, "Timeout while creating streaming response")
        except httpx.HTTPStatusError as e:
            raise DownloadError(e.response.status_code, f"HTTP error {e.response.status_code}")
        except Exception as e:
            raise RuntimeError(f"Error creating streaming response: {e}")

    async def stream_content(self) -> typing.AsyncGenerator[bytes, None]:
        if not self.response:
            raise RuntimeError("No response available for streaming")

        try:
            self.parse_content_range()

            # --- STREAMWISH FIX ---
            FAKE_PNG_HEADER = b"\x89PNG\r\n\x1a\n"
            first_chunk_processed = False

            if settings.enable_streaming_progress:
                with tqdm_asyncio(
                    total=self.total_size,
                    initial=self.start_byte,
                    unit="B",
                    unit_scale=True,
                    unit_divisor=1024,
                    desc="Streaming",
                    ncols=100,
                    mininterval=1,
                ) as self.progress_bar:
                    async for chunk in self.response.aiter_bytes():

                        # Remove StreamWish fake PNG header (only on first chunk)
                        if not first_chunk_processed:
                            first_chunk_processed = True
                            if chunk.startswith(FAKE_PNG_HEADER):
                                chunk = chunk[len(FAKE_PNG_HEADER):]

                        yield chunk
                        self.bytes_transferred += len(chunk)
                        self.progress_bar.update(len(chunk))

            else:
                async for chunk in self.response.aiter_bytes():

                    # *** STREAMWISH 8-BYTE HEADER CUT ***
                    if not first_chunk_processed:
                        first_chunk_processed = True
                        if chunk.startswith(FAKE_PNG_HEADER):
                            chunk = chunk[len(FAKE_PNG_HEADER):]

                    yield chunk
                    self.bytes_transferred += len(chunk)

        except Exception as e:
            raise

    @staticmethod
    def format_bytes(size) -> str:
        power = 2**10
        n = 0
        units = {0: "B", 1: "KB", 2: "MB", 3: "GB", 4: "TB"}
        while size > power:
            size /= power
            n += 1
        return f"{size:.2f} {units[n]}"

    def parse_content_range(self):
        content_range = self.response.headers.get("Content-Range", "")
        if content_range:
            range_info = content_range.split()[-1]
            self.start_byte, self.end_byte, self.total_size = map(int, range_info.replace("/", "-").split("-"))
        else:
            self.start_byte = 0
            self.total_size = int(self.response.headers.get("Content-Length", 0))
            self.end_byte = max(self.total_size - 1, 0)

    async def get_text(self, url: str, headers: dict):
        try:
            self.response = await fetch_with_retry(self.client, "GET", url, headers)
        except tenacity.RetryError as e:
            raise e.last_attempt.result()
        return self.response.text

    async def close(self):
        if self.response:
            await self.response.aclose()
        if self.progress_bar:
            self.progress_bar.close()
        await self.client.aclose()


async def download_file_with_retry(url: str, headers: dict):
    async with create_httpx_client() as client:
        response = await fetch_with_retry(client, "GET", url, headers)
        return response.content


async def request_with_retry(method: str, url: str, headers: dict, **kwargs) -> httpx.Response:
    async with create_httpx_client() as client:
        return await fetch_with_retry(client, method, url, headers, **kwargs)


@dataclass
class ProxyRequestHeaders:
    request: dict
    response: dict


def get_proxy_headers(request: Request) -> ProxyRequestHeaders:
    request_headers = {k: v for k, v in request.headers.items() if k in SUPPORTED_REQUEST_HEADERS}
    request_headers.update({k[2:].lower(): v for k, v in request.query_params.items() if k.startswith("h_")})

    if "referrer" in request_headers and "referer" not in request_headers:
        request_headers["referer"] = request_headers.pop("referrer")

    response_headers = {k[2:].lower(): v for k, v in request.query_params.items() if k.startswith("r_")}
    return ProxyRequestHeaders(request_headers, response_headers)
    
def encode_mediaflow_proxy_url(
    mediaflow_proxy_url: str,
    endpoint: typing.Optional[str] = None,
    destination_url: typing.Optional[str] = None,
    query_params: typing.Optional[dict] = None,
    request_headers: typing.Optional[dict] = None,
    response_headers: typing.Optional[dict] = None,
    encryption_handler: EncryptionHandler = None,
    expiration: int = None,
    ip: str = None,
    filename: typing.Optional[str] = None,
) -> str:
    """
    Encodes & Encrypt (Optional) a MediaFlow proxy URL with query parameters and headers.
    """
    query_params = query_params or {}

    if destination_url:
        query_params["d"] = destination_url

    if request_headers:
        query_params.update(
            {f"h_{k}" if not k.startswith("h_") else k: v for k, v in request_headers.items()}
        )

    if response_headers:
        query_params.update(
            {f"r_{k}" if not k.startswith("r_") else k: v for k, v in response_headers.items()}
        )

    if endpoint is None:
        base_url = mediaflow_proxy_url.rstrip("/")
    else:
        base_url = parse.urljoin(mediaflow_proxy_url.rstrip("/"), endpoint.lstrip("/"))

    # ---- ENCRYPTED URL MODE ----
    if encryption_handler:
        encrypted_token = encryption_handler.encrypt_data(query_params, expiration, ip)

        parsed = parse.urlparse(base_url)
        new_path = f"/_token_{encrypted_token}{parsed.path}"

        rebuilt = list(parsed)
        rebuilt[2] = new_path

        final_url = parse.urlunparse(rebuilt)

        if filename:
            final_url = f"{final_url}/{parse.quote(filename)}"

        return final_url

    # ---- PLAIN QUERY PARAM MODE ----
    url = base_url
    if filename:
        url = f"{url}/{parse.quote(filename)}"

    if query_params:
        return f"{url}?{urlencode(query_params)}"

    return url


class EnhancedStreamingResponse(Response):
    body_iterator: typing.AsyncIterable[typing.Any]

    def __init__(
        self,
        content: typing.Union[typing.AsyncIterable[typing.Any], typing.Iterable[typing.Any]],
        status_code: int = 200,
        headers: typing.Optional[typing.Mapping[str, str]] = None,
        media_type: typing.Optional[str] = None,
        background: typing.Optional[BackgroundTask] = None,
    ) -> None:
        if isinstance(content, typing.AsyncIterable):
            self.body_iterator = content
        else:
            self.body_iterator = iterate_in_threadpool(content)
        self.status_code = status_code
        self.media_type = self.media_type if media_type is None else media_type
        self.background = background
        self.init_headers(headers)
        self.actual_content_length = 0

    @staticmethod
    async def listen_for_disconnect(receive: Receive) -> None:
        try:
            while True:
                message = await receive()
                if message["type"] == "http.disconnect":
                    break
        except Exception:
            pass

    async def stream_response(self, send: Send) -> None:
        try:
            headers = list(self.raw_headers)

            # remove content-length for streaming
            headers = [(k, v) for k, v in headers if k.lower() != b"content-length"]

            await send(
                {
                    "type": "http.response.start",
                    "status": self.status_code,
                    "headers": headers,
                }
            )

            async for chunk in self.body_iterator:
                if not isinstance(chunk, (bytes, memoryview)):
                    chunk = chunk.encode(self.charset)

                await send({"type": "http.response.body", "body": chunk, "more_body": True})
                self.actual_content_length += len(chunk)

            await send({"type": "http.response.body", "body": b"", "more_body": False})

        except Exception:
            raise

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        async with anyio.create_task_group() as tg:
            tg.start_soon(self.stream_response, send)
            tg.start_soon(self.listen_for_disconnect, receive)
        if self.background is not None:
            await self.background()
