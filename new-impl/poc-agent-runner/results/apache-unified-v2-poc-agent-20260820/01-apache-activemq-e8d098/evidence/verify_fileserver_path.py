#!/usr/bin/env python3
"""Local, non-network receipt for the exact ActiveMQ fileserver source decision.

This does not start ActiveMQ or issue HTTP requests.  It verifies the relevant
source/configuration tokens at the pinned checkout, then performs a benign copy
between two files below this evidence directory using the same URL-path-to-file
decision visible in RestFilter#doMove.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from urllib.parse import urlsplit


WORKSPACE = Path(__file__).resolve().parents[1]
REPO = WORKSPACE / "activemq"
EVIDENCE = WORKSPACE / "evidence"
SANDBOX = EVIDENCE / "local-path-receipt"


def require(text: str, token: str, source: Path) -> None:
    if token not in text:
        raise AssertionError(f"missing expected source token in {source}: {token!r}")


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    rest = REPO / "activemq-fileserver/src/main/java/org/apache/activemq/util/RestFilter.java"
    web_xml = REPO / "activemq-fileserver/src/main/webapp/WEB-INF/web.xml"
    jetty = REPO / "assembly/src/release/conf/jetty.xml"
    broker = REPO / "assembly/src/release/conf/activemq.xml"

    rest_text = rest.read_text()
    web_text = web_xml.read_text()
    jetty_text = jetty.read_text()
    broker_text = broker.read_text()

    for token in (
        'String destination = request.getHeader(HTTP_HEADER_DESTINATION);',
        'URL destinationUrl = new URL(destination);',
        'IOHelper.copyFile(file, new File(destinationUrl.getFile()));',
        'IOHelper.deleteFile(file);',
        'if (writePermissionRole != null && !request.isUserInRole(writePermissionRole))',
    ):
        require(rest_text, token, rest)
    for token in (
        '<filter-class>org.apache.activemq.util.RestFilter</filter-class>',
        '<url-pattern>/*</url-pattern>',
        'org.eclipse.jetty.servlet.DefaultServlet',
    ):
        require(web_text, token, web_xml)
    require(jetty_text, '<property name="contextPath" value="/fileserver" />', jetty)
    require(jetty_text, '<property name="host" value="0.0.0.0"/>', jetty)
    require(jetty_text, '<property name="pathSpec" value="/api/*,/admin/*,*.jsp" />', jetty)
    require(broker_text, '<import resource="jetty.xml"/>', broker)

    # The supplied descriptor has no role init-param.  The source gate above
    # therefore does not require a user role in the shipped configuration.
    if 'write-permission-role' in web_text:
        raise AssertionError('unexpected write-permission-role in supplied web.xml')

    storage = SANDBOX / "fileserver-storage"
    outside = SANDBOX / "outside-storage"
    storage.mkdir(parents=True, exist_ok=True)
    outside.mkdir(parents=True, exist_ok=True)
    source = storage / "benign-input.txt"
    destination = outside / "benign-output.txt"
    source.write_text('local receipt only\n', encoding='utf-8')

    # A file URL has a URL path equivalent to the Java URL#getFile value used
    # by the reviewed source for this simple no-query local receipt.
    safe_destination_url = destination.as_uri()
    destination_path = Path(urlsplit(safe_destination_url).path)
    if destination_path != destination:
        raise AssertionError('unexpected local URL path conversion')
    if storage in destination_path.parents:
        raise AssertionError('receipt destination must be outside storage root')

    shutil.copyfile(source, destination_path)
    source.unlink()

    result = {
        'mode': 'local-only source-derived receipt; no service started; no HTTP sent',
        'source_root': str(REPO),
        'source_file': str(rest.relative_to(REPO)),
        'sink_expression': 'new File(destinationUrl.getFile())',
        'configured_storage_root': str(storage),
        'destination_inside_storage_root': storage in destination_path.parents,
        'source_removed_after_copy': not source.exists(),
        'destination_created': destination.exists(),
        'source_sha256_before_copy': hashlib.sha256(b'local receipt only\n').hexdigest(),
        'destination_sha256': digest(destination),
        'asserted_tokens': {
            'rest_filter_sink': True,
            'fileserver_filter_mapping': True,
            'no_descriptor_write_role': True,
            'default_jetty_fileserver_context': True,
            'default_jetty_listen_host': '0.0.0.0',
            'default_security_path_spec': '/api/*,/admin/*,*.jsp',
            'broker_imports_jetty': True,
        },
    }
    output = EVIDENCE / "local-path-receipt.json"
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    print(output)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
