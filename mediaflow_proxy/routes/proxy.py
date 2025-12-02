# mediaflow_proxy/routes/proxy.py

from typing import Annotated
from urllib.parse import quote, unquote
import re
import logging
import httpx
import time
import asyncio

from fastapi import Request, Depends, APIRouter, Query, HTTPException
from fastapi.responses import Response

from mediaflow_proxy.handlers import (
    handle_hls_stream_proxy,
    handle_stream_request,
    proxy_stream,
    get_manifest,
    get_playlist,
    get_segment,
    get_public_ip,
)
from mediaflow_proxy.schemas import (
    MPDSegmentParams,
    MPDPlaylistParams,
    HLSManifestParams,
    MPDManifestParams,
)
from mediaflow_proxy.utils.http_utils import (
    get_proxy_headers,
    ProxyRequestHeaders,
    create_httpx_client,
)
from mediaflow_proxy.utils.base64_utils import process_potential_base64_url

proxy_router = APIRouter()

_dlhd_extraction_cache = {}
_dlhd_cache_duration = 600

_sportsonline_extraction_cache = {}
_sportsonline_cache_duration = 600


def _get_client_ip_from_request(request: Request) -> str:
    """
    Unified way to get REAL client IP. This is what we will forward
    to VidGuard / GuardStorage, regardless of where MediaFlow runs.
    """
    xff = request.headers.get("X-Forwarded-For")
    if xff:
        return xff.split(",")[0].strip()
    xri = request.headers.get("X-Real-IP")
    if xri:
        return xri
    return request.client.host if request.client else "127.0.0.1"


def _inject_ip_into_proxy_headers(proxy_headers: ProxyRequestHeaders, client_ip: str):
    """
    Make sure all outbound HTTPX requests from MediaFlow carry the real client IP
    (as far as HTTP headers allow).
    """
    if not client_ip:
        return

    # request headers used by handle_hls_stream_proxy, handle_stream_request, etc.
    proxy_headers.request["x-real-ip"] = client_ip
    proxy_headers.request["x-forwarded-for"] = client_ip
    proxy_headers.request.setdefault("forwarded", f"for={client_ip}")


def _inject_ip_into_query_params(request: Request, client_ip: str):
    """
    Add h_x-real-ip / h_x-forwarded-for query params so that when we rewrite
    manifests (M3U8Processor), segment/key URLs also receive the IP headers
    on subsequent requests.
    """
    if not client_ip:
        return

    from fastapi.datastructures import QueryParams

    query_dict = dict(request.query_params)
    query_dict.setdefault("h_x-real-ip", client_ip)
    query_dict.setdefault("h_x-forwarded-for", client_ip)

    request._query_params = QueryParams(query_dict)
    request.scope["query_string"] = QueryParams(query_dict).__str__().encode()


def sanitize_url(url: str) -> str:
    logger = logging.getLogger(__name__)
    original_url = url

    url = process_potential_base64_url(url)

    url = re.sub(r"https%22//", "https://", url)
    url = re.sub(r"http%22//", "http://", url)

    url = re.sub(r"https%3A%22//", "https://", url)
    url = re.sub(r"http%3A%22//", "http://", url)

    url = re.sub(r'https:"//', "https://", url)
    url = re.sub(r'http:"//', "http://", url)

    if "&key_id=" in url and "&key=" in url:
        base_url = url.split("&key_id=")[0]
        logger.info(
            f"Removed incorrectly appended key parameters from URL: '{url}' -> '{base_url}'"
        )
        url = base_url

    if url != original_url:
        logger.info(f"URL sanitized: '{original_url}' -> '{url}'")

    try:
        decoded_url = unquote(url)
        if decoded_url != url:
            logger.info(f"URL after decoding: '{decoded_url}'")
            if ':"/' in decoded_url:
                fixed_decoded = re.sub(r'([a-z]+):"//', r"\1://", decoded_url)
                logger.info(f"Fixed decoded URL: '{fixed_decoded}'")
                return fixed_decoded
    except Exception as e:
        logger.warning(f"Error decoding URL '{url}': {e}")

    return url


def extract_drm_params_from_url(url: str) -> tuple[str, str, str]:
    logger = logging.getLogger(__name__)
    key_id = None
    key = None
    clean_url = url

    if "&key_id=" in url and "&key=" in url:
        key_id_match = re.search(r"&key_id=([^&]+)", url)
        if key_id_match:
            key_id = key_id_match.group(1)

        key_match = re.search(r"&key=([^&]+)", url)
        if key_match:
            key = key_match.group(1)

        clean_url = re.sub(r"&key_id=[^&]*", "", url)
        clean_url = re.sub(r"&key=[^&]*", "", clean_url)

        logger.info(f"Extracted DRM parameters from URL: key_id={key_id}, key={key}")
        logger.info(f"Cleaned URL: '{url}' -> '{clean_url}'")

    return clean_url, key_id, key


def _invalidate_dlhd_cache(destination: str):
    if destination in _dlhd_extraction_cache:
        del _dlhd_extraction_cache[destination]
        logger = logging.getLogger(__name__)
        logger.info(f"DLHD cache invalidated for: {destination}")


async def _check_and_extract_dlhd_stream(
    request: Request,
    destination: str,
    proxy_headers: ProxyRequestHeaders,
    force_refresh: bool = False,
) -> dict | None:
    import re
    from urllib.parse import urlparse
    from mediaflow_proxy.extractors.factory import ExtractorFactory
    from mediaflow_proxy.extractors.base import ExtractorError
    from mediaflow_proxy.utils.http_utils import DownloadError

    is_dlhd_link = (
        re.search(r"stream-\d+", destination)
        or "dlhd.dad" in urlparse(destination).netloc
        or "daddylive.sx" in urlparse(destination).netloc
    )

    if not is_dlhd_link:
        return None

    logger = logging.getLogger(__name__)
    logger.info(f"DLHD link detected: {destination}")

    current_time = time.time()
    if not force_refresh and destination in _dlhd_extraction_cache:
        cached_entry = _dlhd_extraction_cache[destination]
        cache_age = current_time - cached_entry["timestamp"]

        if cache_age < _dlhd_cache_duration:
            logger.info(f"Using cached DLHD data (age: {cache_age:.1f}s)")
            return cached_entry["data"]
        else:
            logger.info(
                f"DLHD cache expired (age: {cache_age:.1f}s), re-extracting..."
            )
            del _dlhd_extraction_cache[destination]

    try:
        logger.info(f"Extracting DLHD stream data from: {destination}")
        extractor = ExtractorFactory.get_extractor("DLHD", proxy_headers.request)
        result = await extractor.extract(destination)

        logger.info(
            f"DLHD extraction successful. Stream URL: {result.get('destination_url')}"
        )

        _dlhd_extraction_cache[destination] = {
            "data": result,
            "timestamp": current_time,
        }
        logger.info(f"DLHD data cached for {_dlhd_cache_duration}s")

        return result

    except (ExtractorError, DownloadError) as e:
        logger.error(f"DLHD extraction failed: {str(e)}")
        raise HTTPException(
            status_code=400, detail=f"DLHD extraction failed: {str(e)}"
        )
    except Exception as e:
        logger.exception(f"Unexpected error during DLHD extraction: {str(e)}")
        raise HTTPException(
            status_code=500, detail=f"DLHD extraction failed: {str(e)}"
        )


async def _check_and_extract_sportsonline_stream(
    request: Request,
    destination: str,
    proxy_headers: ProxyRequestHeaders,
    force_refresh: bool = False,
) -> dict | None:
    import re
    from urllib.parse import urlparse
    from mediaflow_proxy.extractors.factory import ExtractorFactory
    from mediaflow_proxy.extractors.base import ExtractorError
    from mediaflow_proxy.utils.http_utils import DownloadError

    parsed_netloc = urlparse(destination).netloc
    is_sportsonline_link = "sportzonline." in parsed_netloc or "sportsonline." in parsed_netloc

    if not is_sportsonline_link:
        return None

    logger = logging.getLogger(__name__)
    logger.info(f"Sportsonline link detected: {destination}")

    current_time = time.time()
    if not force_refresh and destination in _sportsonline_extraction_cache:
        cached_entry = _sportsonline_extraction_cache[destination]
        if current_time - cached_entry["timestamp"] < _sportsonline_cache_duration:
            logger.info(
                f"Using cached Sportsonline data (age: {current_time - cached_entry['timestamp']:.1f}s)"
            )
            return cached_entry["data"]
        else:
            logger.info("Sportsonline cache expired, re-extracting...")
            del _sportsonline_extraction_cache[destination]

    try:
        logger.info(f"Extracting Sportsonline stream data from: {destination}")
        extractor = ExtractorFactory.get_extractor("Sportsonline", proxy_headers.request)
        result = await extractor.extract(destination)
        logger.info(
            f"Sportsonline extraction successful. Stream URL: {result.get('destination_url')}"
        )
        _sportsonline_extraction_cache[destination] = {
            "data": result,
            "timestamp": current_time,
        }
        logger.info(f"Sportsonline data cached for {_sportsonline_cache_duration}s")
        return result
    except (ExtractorError, DownloadError, Exception) as e:
        logger.error(f"Sportsonline extraction failed: {str(e)}")
        raise HTTPException(
            status_code=400, detail=f"Sportsonline extraction failed: {str(e)}"
        )


@proxy_router.head("/hls/manifest.m3u8")
@proxy_router.get("/hls/manifest.m3u8")
async def hls_manifest_proxy(
    request: Request,
    hls_params: Annotated[HLSManifestParams, Query()],
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    """
    Master HLS manifest proxy (VidGuard / DLHD / generic).
    """

    logger = logging.getLogger(__name__)

    # REAL client IP
    client_ip = _get_client_ip_from_request(request)
    _inject_ip_into_proxy_headers(proxy_headers, client_ip)
    _inject_ip_into_query_params(request, client_ip)

    original_destination = hls_params.destination
    hls_params.destination = sanitize_url(hls_params.destination)

    force_refresh = request.query_params.get("dlhd_retry") == "1"

    dlhd_result = await _check_and_extract_dlhd_stream(
        request, hls_params.destination, proxy_headers, force_refresh=force_refresh
    )
    dlhd_original_url = None
    if dlhd_result:
        dlhd_original_url = hls_params.destination
        hls_params.destination = dlhd_result["destination_url"]
        extracted_headers = dlhd_result.get("request_headers", {})

        # do NOT override IP derived from request
        for k, v in extracted_headers.items():
            lk = k.lower()
            if lk in ("x-real-ip", "x-forwarded-for", "forwarded"):
                continue
            proxy_headers.request[k] = v

        from fastapi.datastructures import QueryParams

        query_dict = dict(request.query_params)
        for header_name, header_value in extracted_headers.items():
            if header_name.lower() in ("x-real-ip", "x-forwarded-for", "forwarded"):
                continue
            query_dict[f"h_{header_name}"] = header_value

        if dlhd_original_url:
            query_dict["dlhd_original"] = dlhd_original_url

        query_dict.pop("dlhd_retry", None)

        request._query_params = QueryParams(query_dict)
        request.scope["query_string"] = QueryParams(query_dict).__str__().encode()

    sportsonline_result = await _check_and_extract_sportsonline_stream(
        request, hls_params.destination, proxy_headers
    )
    if sportsonline_result:
        hls_params.destination = sportsonline_result["destination_url"]
        extracted_headers = sportsonline_result.get("request_headers", {})

        # again, don't overwrite IP headers
        for k, v in extracted_headers.items():
            lk = k.lower()
            if lk in ("x-real-ip", "x-forwarded-for", "forwarded"):
                continue
            proxy_headers.request[k] = v

        from fastapi.datastructures import QueryParams

        query_dict = dict(request.query_params)
        for header_name, header_value in extracted_headers.items():
            if header_name.lower() in ("x-real-ip", "x-forwarded-for", "forwarded"):
                continue
            query_dict[f"h_{header_name}"] = header_value

        query_dict.pop("dlhd_retry", None)
        request._query_params = QueryParams(query_dict)
        request.scope["query_string"] = QueryParams(query_dict).__str__().encode()

    try:
        result = await _handle_hls_with_dlhd_retry(
            request, hls_params, proxy_headers, dlhd_original_url
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        logger.exception(f"Unexpected error in hls_manifest_proxy: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def _handle_hls_with_dlhd_retry(
    request: Request,
    hls_params: HLSManifestParams,
    proxy_headers: ProxyRequestHeaders,
    dlhd_original_url: str | None,
):
    logger = logging.getLogger(__name__)

    if hls_params.max_res:
        from mediaflow_proxy.utils.hls_utils import parse_hls_playlist
        from mediaflow_proxy.utils.m3u8_processor import M3U8Processor

        async with create_httpx_client(
            headers=proxy_headers.request,
            follow_redirects=True,
        ) as client:
            try:
                response = await client.get(hls_params.destination)
                response.raise_for_status()
                playlist_content = response.text
            except httpx.HTTPStatusError as e:
                raise HTTPException(
                    status_code=502,
                    detail=(
                        "Failed to fetch HLS manifest from origin: "
                        f"{e.response.status_code} {e.response.reason_phrase}"
                    ),
                ) from e
            except httpx.TimeoutException as e:
                raise HTTPException(
                    status_code=504,
                    detail=f"Timeout while fetching HLS manifest: {e}",
                ) from e
            except httpx.RequestError as e:
                raise HTTPException(
                    status_code=502,
                    detail=f"Network error fetching HLS manifest: {e}",
                ) from e

        streams = parse_hls_playlist(playlist_content, base_url=hls_params.destination)
        if not streams:
            raise HTTPException(
                status_code=404, detail="No streams found in the manifest."
            )

        highest_res_stream = max(
            streams,
            key=lambda s: s.get("resolution", (0, 0))[0]
            * s.get("resolution", (0, 0))[1],
        )

        if highest_res_stream.get("resolution", (0, 0)) == (0, 0):
            logging.warning(
                "Selected stream has resolution (0, 0); resolution parsing may have failed."
            )

        lines = playlist_content.splitlines()
        highest_variant_index = streams.index(highest_res_stream)

        variant_index = -1
        new_manifest_lines = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if line.startswith("#EXT-X-STREAM-INF"):
                variant_index += 1
                next_line = ""
                if i + 1 < len(lines) and not lines[i + 1].startswith("#"):
                    next_line = lines[i + 1]

                if variant_index == highest_variant_index:
                    new_manifest_lines.append(line)
                    if next_line:
                        new_manifest_lines.append(next_line)

                i += 2 if next_line else 1
                continue

            new_manifest_lines.append(line)
            i += 1

        new_manifest = "\n".join(new_manifest_lines)

        processor = M3U8Processor(
            request,
            hls_params.key_url,
            hls_params.force_playlist_proxy,
            hls_params.key_only_proxy,
            hls_params.no_proxy,
        )
        processed_manifest = await processor.process_m3u8(
            new_manifest, base_url=hls_params.destination
        )

        return Response(
            content=processed_manifest, media_type="application/vnd.apple.mpegurl"
        )

    return await handle_hls_stream_proxy(request, hls_params, proxy_headers)


@proxy_router.head("/hls/key_proxy/manifest.m3u8", name="hls_key_proxy")
@proxy_router.get("/hls/key_proxy/manifest.m3u8", name="hls_key_proxy")
async def hls_key_proxy(
    request: Request,
    hls_params: Annotated[HLSManifestParams, Query()],
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    client_ip = _get_client_ip_from_request(request)
    _inject_ip_into_proxy_headers(proxy_headers, client_ip)
    _inject_ip_into_query_params(request, client_ip)

    hls_params.destination = sanitize_url(hls_params.destination)
    hls_params.key_only_proxy = True

    return await handle_hls_stream_proxy(request, hls_params, proxy_headers)


@proxy_router.get("/hls/segment")
async def hls_segment_proxy(
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    segment_url: str = Query(..., description="URL of the HLS segment"),
):
    from mediaflow_proxy.utils.hls_prebuffer import hls_prebuffer
    from mediaflow_proxy.configs import settings

    client_ip = _get_client_ip_from_request(request)
    _inject_ip_into_proxy_headers(proxy_headers, client_ip)

    segment_url = sanitize_url(segment_url)

    headers = {}
    for key, value in request.query_params.items():
        if key.startswith("h_"):
            headers[key[2:]] = value

    if client_ip:
        headers.setdefault("x-real-ip", client_ip)
        headers.setdefault("x-forwarded-for", client_ip)

    if settings.enable_hls_prebuffer:
        cached_segment = await hls_prebuffer.get_segment(segment_url, headers)
        if cached_segment:
            asyncio.create_task(
                hls_prebuffer.prebuffer_from_segment(segment_url, headers)
            )
            return Response(
                content=cached_segment,
                media_type="video/mp2t",
                headers={
                    "Content-Type": "video/mp2t",
                    "Cache-Control": "public, max-age=3600",
                    "Access-Control-Allow-Origin": "*",
                },
            )

    if settings.enable_hls_prebuffer:
        asyncio.create_task(
            hls_prebuffer.prebuffer_from_segment(segment_url, headers)
        )

    return await handle_stream_request("GET", segment_url, proxy_headers)


@proxy_router.get("/dash/segment")
async def dash_segment_proxy(
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    segment_url: str = Query(..., description="URL of the DASH segment"),
):
    from mediaflow_proxy.utils.dash_prebuffer import dash_prebuffer
    from mediaflow_proxy.configs import settings

    client_ip = _get_client_ip_from_request(request)
    _inject_ip_into_proxy_headers(proxy_headers, client_ip)

    segment_url = sanitize_url(segment_url)

    headers = {}
    for key, value in request.query_params.items():
        if key.startswith("h_"):
            headers[key[2:]] = value

    if client_ip:
        headers.setdefault("x-real-ip", client_ip)
        headers.setdefault("x-forwarded-for", client_ip)

    if settings.enable_dash_prebuffer:
        cached_segment = await dash_prebuffer.get_segment(segment_url, headers)
        if cached_segment:
            return Response(
                content=cached_segment,
                media_type="video/mp4",
                headers={
                    "Content-Type": "video/mp4",
                    "Cache-Control": "public, max-age=3600",
                    "Access-Control-Allow-Origin": "*",
                },
            )

    return await handle_stream_request("GET", segment_url, proxy_headers)


@proxy_router.head("/stream")
@proxy_router.get("/stream")
@proxy_router.head("/stream/{filename:path}")
@proxy_router.get("/stream/{filename:path}")
async def proxy_stream_endpoint(
    request: Request,
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
    destination: str = Query(..., description="The URL of the stream.", alias="d"),
    filename: str | None = None,
):
    destination = sanitize_url(destination)

    client_ip = _get_client_ip_from_request(request)
    _inject_ip_into_proxy_headers(proxy_headers, client_ip)

    dlhd_result = await _check_and_extract_dlhd_stream(
        request, destination, proxy_headers
    )
    if dlhd_result:
        destination = dlhd_result["destination_url"]
        extracted_headers = dlhd_result.get("request_headers", {})
        for k, v in extracted_headers.items():
            lk = k.lower()
            if lk in ("x-real-ip", "x-forwarded-for", "forwarded"):
                continue
            proxy_headers.request[k] = v

    if proxy_headers.request.get("range", "").strip() == "":
        proxy_headers.request.pop("range", None)

    if proxy_headers.request.get("if-range", "").strip() == "":
        proxy_headers.request.pop("if-range", None)

    if "range" not in proxy_headers.request:
        proxy_headers.request["range"] = "bytes=0-"

    if filename:
        try:
            filename.encode("latin-1")
            content_disposition = f'attachment; filename="{filename}"'
        except UnicodeEncodeError:
            encoded_filename = quote(filename.encode("utf-8"))
            content_disposition = f"attachment; filename*=UTF-8''{encoded_filename}"

        proxy_headers.response.update({"content-disposition": content_disposition})

    return await proxy_stream(request.method, destination, proxy_headers)


@proxy_router.get("/mpd/manifest.m3u8")
async def mpd_manifest_proxy(
    request: Request,
    manifest_params: Annotated[MPDManifestParams, Query()],
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    client_ip = _get_client_ip_from_request(request)
    _inject_ip_into_proxy_headers(proxy_headers, client_ip)
    _inject_ip_into_query_params(request, client_ip)

    clean_url, extracted_key_id, extracted_key = extract_drm_params_from_url(
        manifest_params.destination
    )
    manifest_params.destination = sanitize_url(clean_url)

    if extracted_key_id and not manifest_params.key_id:
        manifest_params.key_id = extracted_key_id
    if extracted_key and not manifest_params.key:
        manifest_params.key = extracted_key

    return await get_manifest(request, manifest_params, proxy_headers)


@proxy_router.get("/mpd/playlist.m3u8")
async def playlist_endpoint(
    request: Request,
    playlist_params: Annotated[MPDPlaylistParams, Query()],
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    client_ip = _get_client_ip_from_request(request)
    _inject_ip_into_proxy_headers(proxy_headers, client_ip)
    _inject_ip_into_query_params(request, client_ip)

    clean_url, extracted_key_id, extracted_key = extract_drm_params_from_url(
        playlist_params.destination
    )

    playlist_params.destination = sanitize_url(clean_url)

    if extracted_key_id and not playlist_params.key_id:
        playlist_params.key_id = extracted_key_id
    if extracted_key and not playlist_params.key:
        playlist_params.key = extracted_key

    return await get_playlist(request, playlist_params, proxy_headers)


@proxy_router.get("/mpd/segment.mp4")
async def segment_endpoint(
    segment_params: Annotated[MPDSegmentParams, Query()],
    proxy_headers: Annotated[ProxyRequestHeaders, Depends(get_proxy_headers)],
):
    client_ip = _get_client_ip_from_request(request)
    _inject_ip_into_proxy_headers(proxy_headers, client_ip)

    return await get_segment(segment_params, proxy_headers)


@proxy_router.get("/ip")
async def get_mediaflow_proxy_public_ip():
    return await get_public_ip()
